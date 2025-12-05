import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError


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
        self.s3 = boto3.client("s3", region_name=region_name)
        self.secretsmanager = boto3.client("secretsmanager", region_name=region_name)

    def _secret_name(self, prefix: str, key_id: str, blob_type: str) -> str:
        base = prefix.rstrip("/") if prefix else ""
        if base:
            return f"{base}/{key_id}/{blob_type}"
        return f"{key_id}/{blob_type}"

    def _storage_key(self, key_id: str, blob_type: str) -> str:
        return f"{key_id}/{blob_type}.json"

    @staticmethod
    def _to_json_string(value):
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8")
        if isinstance(value, str):
            return value
        return json.dumps(value)

    @staticmethod
    def _raise_storage_error(action: str, error: Exception):
        message = (
            f"Failed to {action}. Check AWS credentials, region settings, bucket configuration, "
            "and network connectivity."
        )
        raise AWSKeyStorageError(message, original_error=error) from error

    def upload_to_storage(self, file_path, bucket, key):
        """Upload a file from file_path to the specified storage bucket/key."""
        try:
            self.s3.upload_file(file_path, bucket, key)
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"upload file to s3 bucket '{bucket}' with key '{key}'", e)

    def download_from_storage(self, bucket, key):
        """Return the bytes stored in bucket/key via get_object."""
        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
            return response["Body"].read()
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"download object from s3 bucket '{bucket}' with key '{key}'", e)

    def put_secret_string(self, name, secret_string, description=None):
        """Store a secret string, creating or updating as needed."""
        try:
            self.secretsmanager.create_secret(Name=name, Description=description or "", SecretString=secret_string)
        except ClientError as e:
            error_code = e.response["Error"].get("Code")
            error_message = e.response["Error"].get("Message", "")
            if error_code == "ResourceExistsException":
                message = (
                    f"A secret named '{name}' already exists. Use a new key_id or delete the existing secret "
                    "before storing again."
                )
                raise AWSKeyStorageError(message, original_error=e) from e
            if error_code == "InvalidRequestException" and "scheduled for deletion" in error_message.lower():
                message = (
                    f"Secret '{name}' is currently scheduled for deletion. Cancel the deletion in AWS Secrets "
                    "Manager or wait for it to complete before storing new data."
                )
                raise AWSKeyStorageError(message, original_error=e) from e
            self._raise_storage_error(f"store secret '{name}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"store secret '{name}'", e)

    def get_secret_string(self, name, *, allow_missing=False):
        """Return a secret string value."""
        response = self._get_secret_value(name, allow_missing=allow_missing)
        if response is None:
            return None
        return response.get("SecretString")

    def put_secret_binary(self, name, secret_bytes, description=None):
        """Store a secret binary blob, creating or updating as needed."""
        try:
            self.secretsmanager.create_secret(Name=name, Description=description or "", SecretBinary=secret_bytes)
        except ClientError as e:
            error_code = e.response["Error"].get("Code")
            error_message = e.response["Error"].get("Message", "")
            if error_code == "ResourceExistsException":
                message = (
                    f"A secret named '{name}' already exists. Use a new key_id or delete the existing secret "
                    "before storing again."
                )
                raise AWSKeyStorageError(message, original_error=e) from e
            if error_code == "InvalidRequestException" and "scheduled for deletion" in error_message.lower():
                message = (
                    f"Secret '{name}' is currently scheduled for deletion. Cancel the deletion in AWS Secrets "
                    "Manager or wait for it to complete before storing new data."
                )
                raise AWSKeyStorageError(message, original_error=e) from e
            self._raise_storage_error(f"store secret binary '{name}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"store secret binary '{name}'", e)

    def get_secret_binary(self, name, *, allow_missing=False):
        """Return a secret binary value."""
        response = self._get_secret_value(name, allow_missing=allow_missing)
        if response is None:
            return None
        return response.get("SecretBinary")

    def _get_secret_value(self, name, *, allow_missing=False):
        try:
            return self.secretsmanager.get_secret_value(SecretId=name)
        except ClientError as e:
            if allow_missing and e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            self._raise_storage_error(f"load secret '{name}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"load secret '{name}'", e)

    def _delete_secret(self, name, *, allow_missing=True):
        try:
            self.secretsmanager.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
        except ClientError as e:
            if allow_missing and e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            self._raise_storage_error(f"delete secret '{name}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"delete secret '{name}'", e)

    def _delete_s3_object(self, bucket, key, *, allow_missing=True):
        try:
            self.s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if allow_missing and e.response["Error"]["Code"] == "NoSuchKey":
                return
            self._raise_storage_error(f"delete s3 object '{key}' from bucket '{bucket}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"delete s3 object '{key}' from bucket '{bucket}'", e)

    def _secret_exists(self, name: str) -> bool:
        try:
            self.secretsmanager.describe_secret(SecretId=name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            self._raise_storage_error(f"check existence of secret '{name}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"check existence of secret '{name}'", e)

    def _s3_object_exists(self, bucket: str, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in {"NoSuchKey", "NotFound", "404"}:
                return False
            self._raise_storage_error(f"check existence of s3 object '{key}' in bucket '{bucket}'", e)
        except BotoCoreError as e:
            self._raise_storage_error(f"check existence of s3 object '{key}' in bucket '{bucket}'", e)

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
        enc_storage_key = self._storage_key(key_id, "enc_blob")
        eval_storage_key = self._storage_key(key_id, "eval_blob")

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

        bucket = bucket or self.s3_bucket
        secret_prefix = secret_prefix or self.secret_prefix

        self.store_sec_key(key_dict["sec_blob"], key_id, secret_prefix=secret_prefix)

        metadata_blob = key_dict.get("metadata_blob")
        if metadata_blob is not None:
            self.store_metadata_key(metadata_blob, key_id, secret_prefix=secret_prefix)

        self.store_enc_key(key_dict["enc_blob"], key_id, bucket=bucket)
        self.store_eval_key(key_dict["eval_blob"], key_id, bucket=bucket)

    def load_key_dict(self, key_id: str, *, bucket: str = None, secret_prefix: str = None) -> dict:
        """
        Load key blobs from AWS and return a dictionary compatible with ``generate_keys_stream``.
        """
        bucket = bucket or self.s3_bucket
        secret_prefix = secret_prefix or self.secret_prefix

        result = {}

        result["sec_blob"] = self.load_sec_key(key_id, secret_prefix=secret_prefix)

        metadata_blob = self.load_metadata_key(key_id, secret_prefix=secret_prefix)
        if metadata_blob is not None:
            result["metadata_blob"] = metadata_blob

        result["enc_blob"] = self.load_enc_key(key_id, bucket=bucket)
        result["eval_blob"] = self.load_eval_key(key_id, bucket=bucket)

        return result

    def store_sec_key(self, sec_blob, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        sec_name = self._secret_name(secret_prefix, key_id, "sec_blob")
        self.put_secret_string(sec_name, self._to_json_string(sec_blob))

    def store_metadata_key(self, metadata_blob, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        meta_name = self._secret_name(secret_prefix, key_id, "metadata_blob")
        self.put_secret_string(meta_name, self._to_json_string(metadata_blob))

    def store_enc_key(self, enc_blob, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        payload = self._to_json_string(enc_blob).encode("utf-8")
        storage_key = self._storage_key(key_id, "enc_blob")
        try:
            self.s3.put_object(Bucket=bucket, Key=storage_key, Body=payload)
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"store enc_blob in s3 bucket '{bucket}' with key '{storage_key}'", e)

    def store_eval_key(self, eval_blob, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        payload = self._to_json_string(eval_blob).encode("utf-8")
        storage_key = self._storage_key(key_id, "eval_blob")
        try:
            self.s3.put_object(Bucket=bucket, Key=storage_key, Body=payload)
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"store eval_blob in s3 bucket '{bucket}' with key '{storage_key}'", e)

    def load_sec_key(self, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        sec_name = self._secret_name(secret_prefix, key_id, "sec_blob")
        sec_payload = self.get_secret_string(sec_name)
        return json.loads(sec_payload)

    def load_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        meta_name = self._secret_name(secret_prefix, key_id, "metadata_blob")
        metadata_payload = self.get_secret_string(meta_name, allow_missing=True)
        if metadata_payload is None:
            return None
        return json.loads(metadata_payload)

    def load_enc_key(self, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "enc_blob")
        try:
            obj = self.s3.get_object(Bucket=bucket, Key=storage_key)
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"load enc_blob from s3 bucket '{bucket}' with key '{storage_key}'", e)
        payload = obj["Body"].read().decode("utf-8")
        return json.loads(payload)

    def load_eval_key(self, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "eval_blob")
        try:
            obj = self.s3.get_object(Bucket=bucket, Key=storage_key)
        except (ClientError, BotoCoreError) as e:
            self._raise_storage_error(f"load eval_blob from s3 bucket '{bucket}' with key '{storage_key}'", e)
        payload = obj["Body"].read().decode("utf-8")
        return json.loads(payload)

    def delete_sec_key(self, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        sec_name = self._secret_name(secret_prefix, key_id, "sec_blob")
        self._delete_secret(sec_name)

    def delete_metadata_key(self, key_id: str, *, secret_prefix: str = None):
        secret_prefix = secret_prefix or self.secret_prefix
        meta_name = self._secret_name(secret_prefix, key_id, "metadata_blob")
        self._delete_secret(meta_name)

    def delete_enc_key(self, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "enc_blob")
        self._delete_s3_object(bucket, storage_key)

    def delete_eval_key(self, key_id: str, *, bucket: str = None):
        bucket = bucket or self.s3_bucket
        storage_key = self._storage_key(key_id, "eval_blob")
        self._delete_s3_object(bucket, storage_key)

    def delete_all_keys(self, key_id: str, *, bucket: str = None, secret_prefix: str = None):
        """Remove all stored blobs for the given key_id from Secrets Manager and S3."""
        bucket = bucket or self.s3_bucket
        secret_prefix = secret_prefix or self.secret_prefix

        self.delete_sec_key(key_id, secret_prefix=secret_prefix)
        self.delete_metadata_key(key_id, secret_prefix=secret_prefix)
        self.delete_enc_key(key_id, bucket=bucket)
        self.delete_eval_key(key_id, bucket=bucket)
