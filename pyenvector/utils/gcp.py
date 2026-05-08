import json
import os
import re

import evi

from pyenvector.utils.utils import _normalize_key_type


class GCPKeyStorageError(RuntimeError):
    def __init__(self, message, *, original_error=None):
        super().__init__(message)
        self.original_error = original_error


class GCPClient:
    DEFAULT_BUCKET = "envector-key-storage"
    DEFAULT_PREFIX = "envector/keys"

    def __init__(self, bucket_name: str = None, secret_prefix: str = None):
        self.bucket_name = bucket_name or self.DEFAULT_BUCKET
        self.secret_prefix = secret_prefix or self.DEFAULT_PREFIX

        gcp_cfg = evi.GcpConfig()
        gcp_cfg.bucket_name = self.bucket_name
        self._client = evi.KeyManager(evi.KeyStorageConfig.make_gcp(gcp_cfg))
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
        parsed = GCPClient._parse_json_object(payload)
        if not isinstance(parsed, dict):
            return False
        kid = parsed.get("kid")
        entries = parsed.get("entries")
        return isinstance(kid, str) and isinstance(entries, list) and len(entries) > 0

    @staticmethod
    def _raise_storage_error(action: str, error: Exception):
        message = (
            f"Failed to {action}. Check GCP credentials, project settings, bucket configuration, "
            "and network connectivity."
        )
        raise GCPKeyStorageError(message, original_error=error) from error

    def list_keys(self):
        try:
            return sorted(set(self._client.list_keys()))
        except Exception as e:
            self._raise_storage_error("list keys", e)

    def _secret_id(self, key_id: str, blob_type: str, *, secret_prefix: str = None) -> str:
        prefix = (secret_prefix or self.secret_prefix or "").strip("/")
        parts = [part for part in (prefix, key_id, blob_type) if part]
        raw = "-".join(parts)
        sanitized = re.sub(r"[^A-Za-z0-9_-]", "-", raw)
        if not sanitized:
            sanitized = f"envector-{blob_type}"
        if not sanitized[0].isalpha():
            sanitized = f"envector-{sanitized}"
        return sanitized[:255]

    def _secret_path(self, secret_id: str) -> str:
        return secret_id

    def _secret_version_path(self, secret_id: str, version: str = "latest") -> str:
        _ = version
        return secret_id

    def _storage_key(self, key_id: str, blob_type: str, *, secret_prefix: str = None) -> str:
        prefix = (self.secret_prefix if secret_prefix is None else secret_prefix or "").strip("/")
        key = f"{key_id}/{blob_type}.json"
        if prefix:
            return f"{prefix}/{key}"
        return key

    def _bucket(self, bucket_name: str = None):
        return bucket_name or self.bucket_name

    def _create_secret(self, secret_id: str):
        return {"name": secret_id}

    def _read_remote_blob(self, storage_key: str, *, is_secret: bool) -> bytes:
        if is_secret:
            return self._client.get_sec_key(storage_key)
        return self._client.get_pub_key(storage_key)

    def put_secret_string(self, secret_id: str, secret_string: str):
        try:
            self._client.put_sec_key(secret_id, secret_string.encode("utf-8"))
        except Exception as e:
            self._raise_storage_error(f"store secret '{secret_id}'", e)

    def get_secret_string(self, secret_id: str, *, allow_missing: bool = False):
        try:
            return self._read_remote_blob(secret_id, is_secret=True).decode("utf-8")
        except Exception as e:
            if allow_missing:
                return None
            self._raise_storage_error(f"load secret '{secret_id}'", e)

    def _secret_exists(self, secret_id: str) -> bool:
        return self.get_secret_string(secret_id, allow_missing=True) is not None

    def _blob_exists(self, storage_key: str, *, bucket_name: str = None) -> bool:
        _ = bucket_name
        try:
            self._read_remote_blob(storage_key, is_secret=False)
            return True
        except Exception:
            return False

    def _delete_secret(self, secret_id: str, *, allow_missing: bool = True):
        try:
            self._client.delete_sec_key(secret_id)
        except Exception as e:
            if allow_missing:
                return
            self._raise_storage_error(f"delete secret '{secret_id}'", e)

    def _delete_blob(self, storage_key: str, *, bucket_name: str = None, allow_missing: bool = True):
        _ = bucket_name
        try:
            self._client.delete_pub_key(storage_key)
        except Exception as e:
            if allow_missing:
                return
            self._raise_storage_error(f"delete object '{storage_key}'", e)

    def check_key_id(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None) -> dict:
        bucket_name = bucket_name or self.bucket_name
        secret_prefix = secret_prefix or self.secret_prefix

        sec_name = self._secret_id(key_id, "sec_blob", secret_prefix=secret_prefix)
        metadata_name = self._secret_id(key_id, "metadata_blob", secret_prefix=secret_prefix)
        enc_storage_key = self._storage_key(key_id, "enc_blob", secret_prefix=secret_prefix)
        eval_storage_key = self._storage_key(key_id, "eval_blob", secret_prefix=secret_prefix)

        result = {
            "sec_blob": self._secret_exists(sec_name),
            "metadata_blob": self._secret_exists(metadata_name),
            "enc_blob": self._blob_exists(enc_storage_key, bucket_name=bucket_name),
            "eval_blob": self._blob_exists(eval_storage_key, bucket_name=bucket_name),
        }
        result["all_present"] = result["sec_blob"] and result["enc_blob"] and result["eval_blob"]
        return result

    def verify_key_id(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None) -> bool:
        status = self.check_key_id(key_id, bucket_name=bucket_name, secret_prefix=secret_prefix)
        return bool(status.get("all_present"))

    def store_key_dict(self, key_dict: dict, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            bucket_name=bucket_name,
            secret_prefix=secret_prefix,
            seal_info=None,
            seal_sec_and_metadata=False,
        )

    def load_key_dict(
        self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None, key_type=None
    ) -> dict:
        return self._load_key_dict_impl(
            key_id,
            bucket_name=bucket_name,
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
        bucket_name: str = None,
        secret_prefix: str = None,
        seal_info=None,
        seal_sec_and_metadata: bool = False,
    ):
        if seal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when seal_sec_and_metadata is enabled.")

        bucket_name = bucket_name or self.bucket_name
        secret_prefix = secret_prefix or self.secret_prefix

        payload = dict(key_dict)
        payload["sec_blob"] = self._normalize_sec_blob_for_store(
            payload["sec_blob"],
            key_id=key_id,
            seal_info=seal_info,
            seal_sec=seal_sec_and_metadata,
        )
        payload["enc_blob"] = self._normalize_pub_blob_for_store(payload["enc_blob"], key_id=key_id, blob_kind="enc")
        payload["eval_blob"] = self._normalize_pub_blob_for_store(payload["eval_blob"], key_id=key_id, blob_kind="eval")

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

        self.store_sec_key(payload["sec_blob"], key_id, secret_prefix=secret_prefix)
        if metadata_blob is not None:
            self.store_metadata_key(payload["metadata_blob"], key_id, secret_prefix=secret_prefix)
        self.store_enc_key(payload["enc_blob"], key_id, bucket_name=bucket_name, secret_prefix=secret_prefix)
        self.store_eval_key(payload["eval_blob"], key_id, bucket_name=bucket_name, secret_prefix=secret_prefix)

    def _load_key_dict_impl(
        self,
        key_id: str,
        *,
        bucket_name: str = None,
        secret_prefix: str = None,
        seal_info=None,
        unseal_sec_and_metadata: bool = False,
        key_type=None,
    ) -> dict:
        if unseal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when unseal_sec_and_metadata is enabled.")

        bucket_name = bucket_name or self.bucket_name
        secret_prefix = secret_prefix or self.secret_prefix
        kt = _normalize_key_type(key_type)

        result = {}

        if kt is None or "sec" in kt:
            result["sec_blob"] = self.load_sec_key(key_id, secret_prefix=secret_prefix)

        if kt is None or "metadata" in kt:
            metadata_blob = self.load_metadata_key(key_id, secret_prefix=secret_prefix)
            if metadata_blob is not None:
                result["metadata_blob"] = metadata_blob

        if kt is None or "enc" in kt:
            result["enc_blob"] = self.load_enc_key(key_id, bucket_name=bucket_name, secret_prefix=secret_prefix)

        if kt is None or "eval" in kt:
            result["eval_blob"] = self.load_eval_key(key_id, bucket_name=bucket_name, secret_prefix=secret_prefix)

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
        bucket_name: str = None,
        secret_prefix: str = None,
    ):
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            bucket_name=bucket_name,
            secret_prefix=secret_prefix,
            seal_info=seal_info,
            seal_sec_and_metadata=True,
        )

    def load_key_dict_with_unsealing(
        self,
        key_id: str,
        *,
        seal_info,
        bucket_name: str = None,
        secret_prefix: str = None,
        key_type=None,
    ) -> dict:
        return self._load_key_dict_impl(
            key_id,
            bucket_name=bucket_name,
            secret_prefix=secret_prefix,
            seal_info=seal_info,
            unseal_sec_and_metadata=True,
            key_type=key_type,
        )

    def _normalize_pub_blob_for_store(self, payload, *, key_id: str, blob_kind: str):
        if self._is_transport_envelope_json(payload):
            parsed = self._parse_json_object(payload)
            return parsed if parsed is not None else payload

        raw = self._to_bytes_payload(payload)
        if blob_kind == "enc":
            wrapped = self._codec.wrap_enc_key_bytes(key_id, raw)
        elif blob_kind == "eval":
            wrapped = self._codec.wrap_eval_key_bytes(key_id, raw)
        else:
            raise ValueError(f"Unsupported blob_kind: {blob_kind!r}")
        return self._wrapped_bytes_to_json_obj(wrapped)

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

    def store_sec_key(self, sec_blob, key_id: str, *, secret_prefix: str = None):
        sec_name = self._secret_id(key_id, "sec_blob", secret_prefix=secret_prefix)
        self.put_secret_string(sec_name, self._to_json_string(sec_blob))

    def store_metadata_key(self, metadata_blob, key_id: str, *, secret_prefix: str = None):
        meta_name = self._secret_id(key_id, "metadata_blob", secret_prefix=secret_prefix)
        metadata_payload = self._to_json_string(metadata_blob)
        if not self._is_transport_envelope_json(metadata_payload):
            wrapped = self._codec.wrap_eval_key_bytes(key_id, metadata_payload.encode("utf-8"))
            metadata_payload = wrapped.decode("utf-8")
        self.put_secret_string(meta_name, metadata_payload)

    def store_enc_key(self, enc_blob, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        _ = bucket_name
        payload = self._to_json_string(enc_blob).encode("utf-8")
        self._client.put_pub_key(self._storage_key(key_id, "enc_blob", secret_prefix=secret_prefix), payload)

    def store_eval_key(self, eval_blob, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        _ = bucket_name
        payload = self._to_json_string(eval_blob).encode("utf-8")
        self._client.put_pub_key(self._storage_key(key_id, "eval_blob", secret_prefix=secret_prefix), payload)

    def load_sec_key(self, key_id: str, *, secret_prefix: str = None):
        sec_name = self._secret_id(key_id, "sec_blob", secret_prefix=secret_prefix)
        sec_payload = self.get_secret_string(sec_name)
        return json.loads(sec_payload)

    def load_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        meta_name = self._secret_id(key_id, "metadata_blob", secret_prefix=secret_prefix)
        metadata_payload = self.get_secret_string(meta_name, allow_missing=True)
        if metadata_payload is None:
            return None
        try:
            parsed_payload = json.loads(metadata_payload)
        except json.JSONDecodeError:
            return metadata_payload
        if not self._is_transport_envelope_json(parsed_payload):
            return parsed_payload
        try:
            unwrapped = self._codec.unwrap_eval_key_bytes(metadata_payload.encode("utf-8"))
            return json.loads(unwrapped.decode("utf-8"))
        except Exception:
            # Backward compatibility: preserve previously stored JSON if unwrap fails.
            return parsed_payload

    def load_enc_key(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        _ = bucket_name
        payload = self._read_remote_blob(
            self._storage_key(key_id, "enc_blob", secret_prefix=secret_prefix), is_secret=False
        )
        return json.loads(payload.decode("utf-8"))

    def load_eval_key(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        _ = bucket_name
        payload = self._read_remote_blob(
            self._storage_key(key_id, "eval_blob", secret_prefix=secret_prefix), is_secret=False
        )
        return json.loads(payload.decode("utf-8"))

    def delete_sec_key(self, key_id: str, *, secret_prefix: str = None):
        sec_name = self._secret_id(key_id, "sec_blob", secret_prefix=secret_prefix)
        self._delete_secret(sec_name)

    def delete_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        meta_name = self._secret_id(key_id, "metadata_blob", secret_prefix=secret_prefix)
        self._delete_secret(meta_name)

    def delete_enc_key(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        storage_key = self._storage_key(key_id, "enc_blob", secret_prefix=secret_prefix)
        self._delete_blob(storage_key, bucket_name=bucket_name)

    def delete_eval_key(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        storage_key = self._storage_key(key_id, "eval_blob", secret_prefix=secret_prefix)
        self._delete_blob(storage_key, bucket_name=bucket_name)

    def delete_all_keys(self, key_id: str, *, bucket_name: str = None, secret_prefix: str = None):
        use_prefix = secret_prefix or self.secret_prefix
        self.delete_sec_key(key_id, secret_prefix=use_prefix)
        self.delete_metadata_key(key_id, secret_prefix=use_prefix)
        self.delete_enc_key(key_id, bucket_name=bucket_name, secret_prefix=use_prefix)
        self.delete_eval_key(key_id, bucket_name=bucket_name, secret_prefix=use_prefix)
