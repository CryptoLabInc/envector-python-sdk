import json
import os

import evi

from pyenvector.utils.utils import _normalize_key_type


class AWSKeyStorageError(RuntimeError):
    def __init__(self, message, *, original_error=None):
        super().__init__(message)
        self.original_error = original_error


class AWSClient:
    DEFAULT_BUCKET = "envector-key-storage"
    DEFAULT_PREFIX = "envector/keys"

    def __init__(self, region_name=None, s3_bucket: str = None, secret_prefix: str = None):
        self.region_name = region_name
        self.s3_bucket = s3_bucket or self.DEFAULT_BUCKET
        self.secret_prefix = secret_prefix or self.DEFAULT_PREFIX

        aws_cfg = evi.AwsConfig()
        aws_cfg.region = self.region_name or ""
        aws_cfg.bucket_name = self.s3_bucket
        self._client = evi.KeyManager(evi.KeyStorageConfig.make_aws(aws_cfg))
        self._codec = evi.KeyManager()

    def _secret_name(self, prefix: str, key_id: str, blob_type: str) -> str:
        base = prefix.rstrip("/") if prefix else ""
        if base:
            return f"{base}/{key_id}/{blob_type}"
        return f"{key_id}/{blob_type}"

    def _storage_key(self, key_id: str, blob_type: str, prefix: str = None) -> str:
        use_prefix = self.secret_prefix if prefix is None else prefix
        base = use_prefix.rstrip("/") if use_prefix else ""
        key = f"{key_id}/{blob_type}.json"
        if base:
            return f"{base}/{key}"
        return key

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
        parsed = AWSClient._parse_json_object(payload)
        if not isinstance(parsed, dict):
            return False
        kid = parsed.get("kid")
        entries = parsed.get("entries")
        return isinstance(kid, str) and isinstance(entries, list) and len(entries) > 0

    @staticmethod
    def _raise_storage_error(action: str, error: Exception):
        message = (
            f"Failed to {action}. Check AWS credentials, region settings, bucket configuration, "
            "and network connectivity."
        )
        raise AWSKeyStorageError(message, original_error=error) from error

    def list_keys(self):
        try:
            return sorted(set(self._client.list_keys()))
        except Exception as e:
            self._raise_storage_error("list keys", e)

    def upload_to_storage(self, file_path, bucket, key):
        """Upload a file from file_path to the specified storage bucket/key."""
        try:
            if bucket != self.s3_bucket:
                raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
            with open(file_path, "rb") as f:
                payload = f.read()
            self._client.put_pub_key(key, payload)
        except Exception as e:
            self._raise_storage_error(f"upload file to s3 bucket '{bucket}' with key '{key}'", e)

    def download_from_storage(self, bucket, key):
        """Return the bytes stored in bucket/key via get_object."""
        try:
            if bucket != self.s3_bucket:
                raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
            return self._client.get_pub_key(key)
        except Exception as e:
            self._raise_storage_error(f"download object from s3 bucket '{bucket}' with key '{key}'", e)

    def put_secret_string(self, name, secret_string, description=None):
        """Store a secret string, creating as needed."""
        _ = description
        try:
            self._client.put_sec_key(name, secret_string.encode("utf-8"))
        except Exception as e:
            self._raise_storage_error(f"store secret '{name}'", e)

    def get_secret_string(self, name, *, allow_missing=False):
        """Return a secret string value."""
        response = self._get_secret_value(name, allow_missing=allow_missing)
        if response is None:
            return None
        return response.get("SecretString")

    def put_secret_binary(self, name, secret_bytes, description=None):
        """Store a secret binary blob, creating as needed."""
        _ = description
        try:
            self._client.put_sec_key(name, bytes(secret_bytes))
        except Exception as e:
            self._raise_storage_error(f"store secret binary '{name}'", e)

    def get_secret_binary(self, name, *, allow_missing=False):
        """Return a secret binary value."""
        response = self._get_secret_value(name, allow_missing=allow_missing)
        if response is None:
            return None
        return response.get("SecretBinary")

    def _get_secret_value(self, name, *, allow_missing=False):
        try:
            payload = self._client.get_sec_key(name)
            return {"SecretString": payload.decode("utf-8"), "SecretBinary": payload}
        except Exception as e:
            if allow_missing:
                return None
            self._raise_storage_error(f"load secret '{name}'", e)

    def _delete_secret(self, name, *, allow_missing=True):
        try:
            self._client.delete_sec_key(name)
        except Exception as e:
            if allow_missing:
                return
            self._raise_storage_error(f"delete secret '{name}'", e)

    def _delete_s3_object(self, bucket, key, *, allow_missing=True):
        try:
            if bucket != self.s3_bucket:
                raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
            self._client.delete_pub_key(key)
        except Exception as e:
            if allow_missing:
                return
            self._raise_storage_error(f"delete s3 object '{key}' from bucket '{bucket}'", e)

    def _secret_exists(self, name: str) -> bool:
        return self.get_secret_string(name, allow_missing=True) is not None

    def _s3_object_exists(self, bucket: str, key: str) -> bool:
        if bucket != self.s3_bucket:
            raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
        try:
            return key in set(self._client.list_keys())
        except Exception:
            return False

    def check_key_id(self, key_id: str, *, bucket: str = None, secret_prefix: str = None) -> dict:
        """
        Verify whether all stored blobs for ``key_id`` exist in AWS Secrets Manager and S3.

        Returns a dictionary with the existence of each blob and an ``all_present`` flag
        that only considers mandatory blobs (sec, enc, eval).
        """

        bucket = bucket or self.s3_bucket
        secret_prefix = secret_prefix or self.secret_prefix

        sec_name = self._secret_name(secret_prefix, key_id, "sec_blob")
        metadata_name = self._secret_name(secret_prefix, key_id, "metadata_blob")
        enc_storage_key = self._storage_key(key_id, "enc_blob", secret_prefix)
        eval_storage_key = self._storage_key(key_id, "eval_blob", secret_prefix)

        result = {
            "sec_blob": self._secret_exists(sec_name),
            "metadata_blob": self._secret_exists(metadata_name),
            "enc_blob": self._s3_object_exists(bucket, enc_storage_key),
            "eval_blob": self._s3_object_exists(bucket, eval_storage_key),
        }
        result["all_present"] = result["sec_blob"] and result["enc_blob"] and result["eval_blob"]
        return result

    def verify_key_id(self, key_id: str, *, bucket: str = None, secret_prefix: str = None) -> bool:
        """
        Return True when all required blobs for ``key_id`` exist, False otherwise.

        This is primarily used by higher-level components to decide whether keys need to be generated.
        """

        status = self.check_key_id(key_id, bucket=bucket, secret_prefix=secret_prefix)
        return bool(status.get("all_present"))

    def store_key_dict(self, key_dict: dict, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        """
        Persist wrapped key blobs to AWS services.

        ``sec_blob`` and ``metadata_blob`` (if present) go to Secrets Manager,
        while ``enc_blob`` and ``eval_blob`` are stored in S3.
        """
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            bucket=bucket,
            secret_prefix=secret_prefix,
            seal_info=None,
            seal_sec_and_metadata=False,
        )

    def _store_key_dict_impl(
        self,
        key_dict: dict,
        key_id: str,
        *,
        bucket: str = None,
        secret_prefix: str = None,
        seal_info=None,
        seal_sec_and_metadata: bool = False,
    ):
        """
        Internal implementation for key persistence.

        When ``seal_sec_and_metadata`` is True:
        - sec_blob is unwrapped to raw bytes and re-wrapped with ``seal_info``
        - metadata_blob is generated if missing and wrapped with ``seal_info``
        - enc/eval remain provider-wrapped and are uploaded to S3
        """
        if seal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when seal_sec_and_metadata is enabled.")

        bucket = bucket or self.s3_bucket
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

        self.store_enc_key(payload["enc_blob"], key_id, bucket=bucket, secret_prefix=secret_prefix)
        self.store_eval_key(payload["eval_blob"], key_id, bucket=bucket, secret_prefix=secret_prefix)

    def store_key_dict_with_sealing(
        self,
        key_dict: dict,
        key_id: str,
        *,
        seal_info,
        bucket: str = None,
        secret_prefix: str = None,
    ):
        """
        Store keys while sealing sec/metadata with AES KEK (via ``seal_info``).
        """
        return self._store_key_dict_impl(
            key_dict,
            key_id,
            bucket=bucket,
            secret_prefix=secret_prefix,
            seal_info=seal_info,
            seal_sec_and_metadata=True,
        )

    def load_key_dict(
        self, key_id: str, *, bucket: str = None, secret_prefix: str = None, key_type=None
    ) -> dict:
        """
        Load key blobs for ``key_id`` and return a dictionary compatible with
        ``generate_keys_stream``.

        When ``key_type`` is ``None``, all supported blobs are loaded and returned:
        ``sec``, ``metadata``, ``enc``, and ``eval``. Otherwise, ``key_type`` acts
        as a filter and only the requested blob type(s) are fetched and included in
        the returned dictionary. Allowed values are ``sec``, ``metadata``, ``enc``,
        and ``eval``.
        """
        return self._load_key_dict_impl(
            key_id,
            bucket=bucket,
            secret_prefix=secret_prefix,
            seal_info=None,
            unseal_sec_and_metadata=False,
            key_type=key_type,
        )

    def _load_key_dict_impl(
        self,
        key_id: str,
        *,
        bucket: str = None,
        secret_prefix: str = None,
        seal_info=None,
        unseal_sec_and_metadata: bool = False,
        key_type=None,
    ) -> dict:
        if unseal_sec_and_metadata and seal_info is None:
            raise ValueError("seal_info is required when unseal_sec_and_metadata is enabled.")

        bucket = bucket or self.s3_bucket
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
            result["enc_blob"] = self.load_enc_key(key_id, bucket=bucket, secret_prefix=secret_prefix)

        if kt is None or "eval" in kt:
            result["eval_blob"] = self.load_eval_key(key_id, bucket=bucket, secret_prefix=secret_prefix)

        if unseal_sec_and_metadata:
            if "sec_blob" in result:
                result["sec_blob"] = self._unwrap_sec_blob_to_raw(result["sec_blob"], seal_info=seal_info)
            if result.get("metadata_blob") is not None:
                result["metadata_blob"] = self._unwrap_metadata_blob_to_raw(
                    result["metadata_blob"], seal_info=seal_info
                )

        return result

    def load_key_dict_with_unsealing(
        self,
        key_id: str,
        *,
        seal_info,
        bucket: str = None,
        secret_prefix: str = None,
        key_type=None,
    ) -> dict:
        """
        Load keys and unseal sec/metadata with AES KEK (via ``seal_info``).
        """
        return self._load_key_dict_impl(
            key_id,
            bucket=bucket,
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

        # If already raw key bytes, pass through.
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
        secret_prefix = secret_prefix or self.secret_prefix
        sec_name = self._secret_name(secret_prefix, key_id, "sec_blob")
        self.put_secret_string(sec_name, self._to_json_string(sec_blob))

    def store_metadata_key(self, metadata_blob, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        meta_name = self._secret_name(secret_prefix, key_id, "metadata_blob")
        metadata_payload = self._to_json_string(metadata_blob)
        if not self._is_transport_envelope_json(metadata_payload):
            wrapped = self._codec.wrap_eval_key_bytes(key_id, metadata_payload.encode("utf-8"))
            metadata_payload = wrapped.decode("utf-8")
        self.put_secret_string(meta_name, metadata_payload)

    def store_enc_key(self, enc_blob, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "enc_blob", secret_prefix)
        if bucket != self.s3_bucket:
            raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
        self._client.put_pub_key(storage_key, self._to_json_string(enc_blob).encode("utf-8"))

    def store_eval_key(self, eval_blob, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "eval_blob", secret_prefix)
        if bucket != self.s3_bucket:
            raise ValueError(f"bucket '{bucket}' does not match configured bucket '{self.s3_bucket}'")
        self._client.put_pub_key(storage_key, self._to_json_string(eval_blob).encode("utf-8"))

    def load_sec_key(self, key_id: str, *, secret_prefix: str = None):
        sec_name = self._secret_name(secret_prefix or self.secret_prefix, key_id, "sec_blob")
        sec_payload = self.get_secret_string(sec_name)
        return json.loads(sec_payload)

    def load_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        meta_name = self._secret_name(secret_prefix or self.secret_prefix, key_id, "metadata_blob")
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

    def load_enc_key(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        bucket = bucket or self.s3_bucket
        payload = self.download_from_storage(bucket, self._storage_key(key_id, "enc_blob", secret_prefix))
        return json.loads(payload.decode("utf-8"))

    def load_eval_key(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        bucket = bucket or self.s3_bucket
        payload = self.download_from_storage(bucket, self._storage_key(key_id, "eval_blob", secret_prefix))
        return json.loads(payload.decode("utf-8"))

    def delete_sec_key(self, key_id: str, *, secret_prefix: str = None):
        sec_name = self._secret_name(secret_prefix or self.secret_prefix, key_id, "sec_blob")
        self._delete_secret(sec_name)

    def delete_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        meta_name = self._secret_name(secret_prefix or self.secret_prefix, key_id, "metadata_blob")
        self._delete_secret(meta_name)

    def delete_enc_key(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        storage_key = self._storage_key(key_id, "enc_blob", secret_prefix)
        self._delete_s3_object(bucket or self.s3_bucket, storage_key)

    def delete_eval_key(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        storage_key = self._storage_key(key_id, "eval_blob", secret_prefix)
        self._delete_s3_object(bucket or self.s3_bucket, storage_key)

    def delete_all_keys(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        """Remove all stored blobs for the given key_id from secret store and bucket."""
        bucket = bucket or self.s3_bucket
        secret_prefix = secret_prefix or self.secret_prefix

        self.delete_sec_key(key_id, secret_prefix=secret_prefix)
        self.delete_metadata_key(key_id, secret_prefix=secret_prefix)
        self.delete_enc_key(key_id, bucket=bucket, secret_prefix=secret_prefix)
        self.delete_eval_key(key_id, bucket=bucket, secret_prefix=secret_prefix)
