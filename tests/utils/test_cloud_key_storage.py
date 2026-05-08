import json
import sys
import types
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _load_storage_module(name: str, relative_path: str):
    module_path = Path(__file__).resolve().parents[2] / relative_path
    fake_pyenvector = types.ModuleType("pyenvector")
    fake_utils_pkg = types.ModuleType("pyenvector.utils")
    fake_utils_mod = types.ModuleType("pyenvector.utils.utils")
    fake_utils_mod._normalize_key_type = lambda key_type: key_type
    fake_utils_pkg.utils = fake_utils_mod
    fake_pyenvector.utils = fake_utils_pkg
    previous = {
        "pyenvector": sys.modules.get("pyenvector"),
        "pyenvector.utils": sys.modules.get("pyenvector.utils"),
        "pyenvector.utils.utils": sys.modules.get("pyenvector.utils.utils"),
    }
    sys.modules["pyenvector"] = fake_pyenvector
    sys.modules["pyenvector.utils"] = fake_utils_pkg
    sys.modules["pyenvector.utils.utils"] = fake_utils_mod

    try:
        spec = spec_from_file_location(name, module_path)
        module = module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        for module_name, previous_module in previous.items():
            if previous_module is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous_module


aws_module = _load_storage_module("test_aws_module", "pyenvector/utils/aws.py")
gcp_module = _load_storage_module("test_gcp_module", "pyenvector/utils/gcp.py")

AWSClient = aws_module.AWSClient
AWSKeyStorageError = aws_module.AWSKeyStorageError
GCPClient = gcp_module.GCPClient
GCPKeyStorageError = gcp_module.GCPKeyStorageError


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeNotFound(Exception):
    pass


def make_aws_client():
    client = AWSClient.__new__(AWSClient)
    client.s3_bucket = "bucket-a"
    client.secret_prefix = "envector/keys"
    client._sm = MagicMock()
    client._s3 = MagicMock()
    client._client_error_cls = FakeClientError
    return client


def make_gcp_client():
    client = GCPClient.__new__(GCPClient)
    client.bucket_name = "bucket-a"
    client.secret_prefix = "envector/keys"
    client._project_id = "test-project"
    client._secretmanager = MagicMock()
    client._storage = MagicMock()
    client._exc_not_found = FakeNotFound
    return client


def test_aws_list_keys_returns_key_ids():
    client = make_aws_client()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Contents": [
                {"Key": "envector/keys/key-a/enc_blob.json"},
                {"Key": "envector/keys/key-a/eval_blob.json"},
                {"Key": "envector/keys/key-b/eval_blob.json"},
                {"Key": "envector/keys/invalid/path/extra.json"},
            ]
        }
    ]
    client._s3.get_paginator.return_value = paginator

    assert client.list_keys() == ["key-a", "key-b"]


def test_aws_download_closes_streaming_body():
    client = make_aws_client()
    body = MagicMock()
    body.read.return_value = b"payload"
    client._s3.get_object.return_value = {"Body": body}

    assert client.download_from_storage("bucket-a", "envector/keys/key-a/enc_blob.json") == b"payload"
    body.close.assert_called_once()


def test_aws_secret_exists_uses_describe_secret():
    client = make_aws_client()
    client._sm.describe_secret.return_value = {"Name": "secret-a"}

    assert client._secret_exists("secret-a") is True
    client._sm.describe_secret.assert_called_once_with(SecretId="secret-a")


def test_aws_get_secret_value_only_masks_not_found():
    client = make_aws_client()
    client._sm.get_secret_value.side_effect = FakeClientError("AccessDeniedException")

    with pytest.raises(AWSKeyStorageError):
        client.get_secret_string("secret-a", allow_missing=True)

    client._sm.get_secret_value.side_effect = FakeClientError("ResourceNotFoundException")
    assert client.get_secret_string("secret-a", allow_missing=True) is None


def test_aws_s3_exists_only_masks_not_found():
    client = make_aws_client()
    client._s3.head_object.side_effect = FakeClientError("403")

    with pytest.raises(AWSKeyStorageError):
        client._s3_object_exists("bucket-a", "envector/keys/key-a/enc_blob.json")

    client._s3.head_object.side_effect = FakeClientError("NoSuchKey")
    assert client._s3_object_exists("bucket-a", "envector/keys/key-a/enc_blob.json") is False


def test_aws_store_sets_content_type():
    client = make_aws_client()

    client.store_enc_key({"kid": "key-a"}, "key-a")
    kwargs = client._s3.put_object.call_args.kwargs

    assert kwargs["Bucket"] == "bucket-a"
    assert kwargs["ContentType"] == "application/json"


def test_gcp_list_keys_returns_key_ids():
    client = make_gcp_client()
    client._storage.list_blobs.return_value = [
        SimpleNamespace(name="envector/keys/key-a/enc_blob.json"),
        SimpleNamespace(name="envector/keys/key-a/eval_blob.json"),
        SimpleNamespace(name="envector/keys/key-b/eval_blob.json"),
        SimpleNamespace(name="envector/keys/invalid/path/extra.json"),
    ]

    assert client.list_keys() == ["key-a", "key-b"]


def test_gcp_secret_exists_uses_secret_metadata():
    client = make_gcp_client()

    assert client._secret_exists("secret-a") is True
    client._secretmanager.get_secret.assert_called_once_with(
        request={"name": "projects/test-project/secrets/secret-a"}
    )


def test_gcp_get_secret_string_only_masks_not_found():
    client = make_gcp_client()
    client._read_remote_blob = MagicMock(side_effect=RuntimeError("network"))

    with pytest.raises(GCPKeyStorageError):
        client.get_secret_string("secret-a", allow_missing=True)

    client._read_remote_blob = MagicMock(side_effect=FakeNotFound())
    assert client.get_secret_string("secret-a", allow_missing=True) is None


def test_gcp_blob_exists_propagates_errors():
    client = make_gcp_client()
    blob = MagicMock()
    blob.exists.side_effect = RuntimeError("network")
    bucket = MagicMock()
    bucket.blob.return_value = blob
    client._storage.bucket.return_value = bucket

    with pytest.raises(RuntimeError):
        client._blob_exists("envector/keys/key-a/enc_blob.json")


def test_gcp_load_enc_key_uses_requested_bucket():
    client = make_gcp_client()
    client._read_remote_blob = MagicMock(return_value=json.dumps({"kid": "key-a"}).encode("utf-8"))

    assert client.load_enc_key("key-a", bucket_name="bucket-b") == {"kid": "key-a"}
    client._read_remote_blob.assert_called_once_with(
        "envector/keys/key-a/enc_blob.json",
        is_secret=False,
        bucket_name="bucket-b",
    )
