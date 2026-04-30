import json
import os

import evi

from pyenvector.utils.utils import _normalize_key_type


class VaultKeyStorageError(RuntimeError):
    def __init__(self, message, *, original_error=None):
        super().__init__(message)
        self.original_error = original_error


class VaultClient:
    DEFAULT_ADDR = "http://127.0.0.1:8200"
    DEFAULT_MOUNT = "secret"
    DEFAULT_PREFIX = "envector/keys"
    DEFAULT_TOKEN_ENV = "VAULT_TOKEN"

    def __init__(
        self,
        vault_addr: str = None,
        vault_mount: str = None,
        secret_prefix: str = None,
        token_env: str = None,
        namespace: str = None,
        verify_tls: bool = True,
    ):
        self.secret_prefix = (secret_prefix or self.DEFAULT_PREFIX).strip("/")

        cfg = evi.VaultConfig()
        cfg.address = (vault_addr or self.DEFAULT_ADDR).rstrip("/")
        cfg.kv_mount = (vault_mount or self.DEFAULT_MOUNT).strip("/")
        cfg.token_env = token_env or self.DEFAULT_TOKEN_ENV
        if hasattr(cfg, "name_space"):
            cfg.name_space = namespace or ""
        else:
            cfg.namespace = namespace or ""
        cfg.tls_skip_verify = not verify_tls
        self._client = evi.KeyManager(evi.KeyStorageConfig.make_vault(cfg))
        self._codec = evi.KeyManager()

    @staticmethod
    def _to_json_string(value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8")
        if isinstance(value, str):
            return value
        return json.dumps(value)

    @staticmethod
    def _to_bytes_payload(value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        raise TypeError(f"Unsupported payload type: {type(value)!r}")

    @staticmethod
    def _wrapped_bytes_to_json_obj(wrapped: bytes):
        return json.loads(wrapped.decode("utf-8"))

    @staticmethod
    def _parse_json_object(payload):
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, (bytes, bytearray)):
            try:
                payload = bytes(payload).decode("utf-8")
            except UnicodeDecodeError:
                return None
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _is_transport_envelope_json(payload):
        parsed = VaultClient._parse_json_object(payload)
        if not isinstance(parsed, dict):
            return False
        kid = parsed.get("kid")
        entries = parsed.get("entries")
        return isinstance(kid, str) and isinstance(entries, list) and len(entries) > 0

    @staticmethod
    def _raise_storage_error(action: str, error: Exception):
        message = f"Failed to {action}. Check Vault token, address/mount/prefix settings, and network connectivity."
        raise VaultKeyStorageError(message, original_error=error) from error

    def _storage_key(self, key_id: str, blob_type: str = "sec_blob", *, secret_prefix: str = None) -> str:
        prefix = self.secret_prefix if secret_prefix is None else (secret_prefix or "").strip("/")
        key = f"{key_id}/{blob_type}"
        if prefix:
            return f"{prefix}/{key}"
        return key

    def _read_sec_payload(self, storage_key: str) -> bytes:
        return self._client.get_sec_key(storage_key)

    def list_keys(self):
        try:
            return sorted(set(self._client.list_keys()))
        except Exception as e:
            self._raise_storage_error("list keys", e)

    def put_secret_string(self, name: str, secret_string: str, description=None):
        _ = description
        try:
            self._client.put_sec_key(name, secret_string.encode("utf-8"))
        except Exception as e:
            self._raise_storage_error(f"store secret '{name}'", e)

    def get_secret_string(self, name: str, *, allow_missing: bool = False):
        try:
            return self._read_sec_payload(name).decode("utf-8")
        except Exception as e:
            if allow_missing:
                return None
            self._raise_storage_error(f"load secret '{name}'", e)

    def check_key_id(self, key_id: str, *, secret_prefix: str = None) -> dict:
        sec_name = self._storage_key(key_id, "sec_blob", secret_prefix=secret_prefix)
        metadata_name = self._storage_key(key_id, "metadata_blob", secret_prefix=secret_prefix)
        sec_exists = self.get_secret_string(sec_name, allow_missing=True) is not None
        metadata_exists = self.get_secret_string(metadata_name, allow_missing=True) is not None
        return {
            "sec_blob": sec_exists,
            "metadata_blob": metadata_exists,
            "enc_blob": False,
            "eval_blob": False,
            "all_present": sec_exists,
        }

    def verify_key_id(self, key_id: str, *, secret_prefix: str = None) -> bool:
        return bool(self.check_key_id(key_id, secret_prefix=secret_prefix).get("all_present"))

    def store_key_dict(self, key_dict: dict, key_id: str, *, secret_prefix: str = None):
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            secret_prefix=secret_prefix,
            seal_info=None,
            seal_sec_and_metadata=False,
        )

    def load_key_dict(self, key_id: str, *, secret_prefix: str = None, key_type=None) -> dict:
        return self._load_key_dict_impl(
            key_id,
            secret_prefix=secret_prefix,
            seal_info=None,
            unseal_sec_and_metadata=False,
            key_type=key_type,
        )

    def _store_key_dict_impl(
        self,
        key_dict: dict,
        key_id: str,
        *,
        secret_prefix: str = None,
        seal_info=None,
        seal_sec_and_metadata: bool = False,
    ):
        if seal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when seal_sec_and_metadata is enabled.")

        sec_blob = key_dict.get("sec_blob")
        if sec_blob is None:
            raise ValueError("sec_blob is required for Vault storage")

        payload = dict(key_dict)
        payload["sec_blob"] = self._normalize_sec_blob_for_store(
            payload["sec_blob"],
            key_id=key_id,
            seal_info=seal_info,
            seal_sec=seal_sec_and_metadata,
        )

        metadata_blob = payload.get("metadata_blob")
        if seal_sec_and_metadata and metadata_blob is None:
            metadata_blob = os.urandom(32)
            payload["metadata_blob"] = metadata_blob
        if metadata_blob is not None:
            payload["metadata_blob"] = self._normalize_metadata_blob_for_store(
                metadata_blob,
                key_id=key_id,
                seal_info=seal_info,
                seal_metadata=seal_sec_and_metadata,
            )

        storage_key = self._storage_key(key_id, "sec_blob", secret_prefix=secret_prefix)
        self.put_secret_string(storage_key, self._to_json_string(payload["sec_blob"]))

        if metadata_blob is not None:
            metadata_key = self._storage_key(key_id, "metadata_blob", secret_prefix=secret_prefix)
            self.put_secret_string(metadata_key, self._to_json_string(payload["metadata_blob"]))

    def _load_key_dict_impl(
        self,
        key_id: str,
        *,
        secret_prefix: str = None,
        seal_info=None,
        unseal_sec_and_metadata: bool = False,
        key_type=None,
    ) -> dict:
        if unseal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when unseal_sec_and_metadata is enabled.")

        kt = _normalize_key_type(key_type)
        result = {}

        if kt is None or "sec" in kt:
            storage_key = self._storage_key(key_id, "sec_blob", secret_prefix=secret_prefix)
            sec_text = self.get_secret_string(storage_key)
            try:
                result["sec_blob"] = json.loads(sec_text)
            except json.JSONDecodeError:
                result["sec_blob"] = sec_text.encode("utf-8")

        if kt is None or "metadata" in kt:
            metadata_text = self.get_secret_string(
                self._storage_key(key_id, "metadata_blob", secret_prefix=secret_prefix),
                allow_missing=True,
            )
            if metadata_text is not None:
                try:
                    parsed_metadata = json.loads(metadata_text)
                except json.JSONDecodeError:
                    result["metadata_blob"] = metadata_text.encode("utf-8")
                else:
                    if not self._is_transport_envelope_json(parsed_metadata):
                        result["metadata_blob"] = parsed_metadata
                    else:
                        try:
                            unwrapped = self._codec.unwrap_eval_key_bytes(metadata_text.encode("utf-8"))
                            result["metadata_blob"] = json.loads(unwrapped.decode("utf-8"))
                        except Exception:
                            result["metadata_blob"] = parsed_metadata

        if unseal_sec_and_metadata:
            if "sec_blob" in result:
                result["sec_blob"] = self._unwrap_sec_blob_to_raw(result["sec_blob"], seal_info=seal_info)
            if result.get("metadata_blob") is not None:
                result["metadata_blob"] = self._unwrap_metadata_blob_to_raw(
                    result["metadata_blob"], seal_info=seal_info
                )
        return result

    def store_key_dict_with_sealing(
        self,
        key_dict: dict,
        key_id: str,
        *,
        seal_info,
        secret_prefix: str = None,
    ):
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            secret_prefix=secret_prefix,
            seal_info=seal_info,
            seal_sec_and_metadata=True,
        )

    def load_key_dict_with_unsealing(
        self,
        key_id: str,
        *,
        seal_info,
        secret_prefix: str = None,
        key_type=None,
    ) -> dict:
        return self._load_key_dict_impl(
            key_id,
            secret_prefix=secret_prefix,
            seal_info=seal_info,
            unseal_sec_and_metadata=True,
            key_type=key_type,
        )

    def _normalize_sec_blob_for_store(self, payload, *, key_id: str, seal_info=None, seal_sec: bool = False):
        raw = self._unwrap_sec_blob_to_raw(payload, seal_info=seal_info)
        if seal_sec:
            wrapped = self._codec.wrap_sec_key_bytes(key_id, raw, seal_info)
        else:
            wrapped = self._codec.wrap_sec_key_bytes(key_id, raw)
        return self._wrapped_bytes_to_json_obj(wrapped)

    def _normalize_metadata_blob_for_store(
        self,
        payload,
        *,
        key_id: str,
        seal_info=None,
        seal_metadata: bool = False,
    ):
        raw = self._unwrap_metadata_blob_to_raw(payload, seal_info=seal_info)
        if seal_metadata:
            wrapped = self._codec.wrap_metadata_key_bytes(key_id, raw, seal_info)
        else:
            wrapped = self._codec.wrap_metadata_key_bytes(key_id, raw)
        return self._wrapped_bytes_to_json_obj(wrapped)

    def _unwrap_sec_blob_to_raw(self, payload, *, seal_info=None):
        raw = self._to_bytes_payload(payload)
        unwrap_attempts = []
        if seal_info is not None:
            unwrap_attempts.append(lambda: self._codec.unwrap_sec_key_bytes(raw, seal_info))
        unwrap_attempts.append(lambda: self._codec.unwrap_sec_key_bytes(raw))
        for unwrap in unwrap_attempts:
            try:
                return unwrap()
            except Exception:
                continue
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        raise ValueError("Unsupported sec_blob payload; unable to unwrap.")

    def _unwrap_metadata_blob_to_raw(self, payload, *, seal_info=None):
        if isinstance(payload, (bytes, bytearray)) and len(payload) == 32:
            return bytes(payload)

        raw = self._to_bytes_payload(payload)
        unwrap_attempts = []
        if seal_info is not None:
            unwrap_attempts.append(lambda: self._codec.unwrap_metadata_key_bytes(raw, seal_info))
        unwrap_attempts.append(lambda: self._codec.unwrap_metadata_key_bytes(raw))

        for unwrap in unwrap_attempts:
            try:
                return unwrap()
            except Exception:
                continue

        if isinstance(payload, str):
            return payload.encode("utf-8")
        if isinstance(payload, (bytes, bytearray)):
            return bytes(payload)
        raise ValueError("Unsupported metadata_blob payload; unable to unwrap.")

    def delete_sec_key(self, key_id: str, *, secret_prefix: str = None):
        try:
            self._client.delete_sec_key(self._storage_key(key_id, "sec_blob", secret_prefix=secret_prefix))
        except Exception as e:
            self._raise_storage_error(f"delete secret for key_id '{key_id}'", e)

    def delete_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        try:
            self._client.delete_sec_key(self._storage_key(key_id, "metadata_blob", secret_prefix=secret_prefix))
        except Exception:
            # metadata is optional
            return

    def delete_all_keys(self, key_id: str, *, secret_prefix: str = None):
        self.delete_sec_key(key_id, secret_prefix=secret_prefix)
        self.delete_metadata_key(key_id, secret_prefix=secret_prefix)
