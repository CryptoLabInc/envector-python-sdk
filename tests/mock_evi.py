from __future__ import annotations

import base64
import json
import secrets
import sys
import types
from enum import Enum
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


class ParameterPreset(Enum):
    IP1 = "IP1"
    IP2 = "IP2"
    QF0 = "QF0"


class EvalMode(Enum):
    RMP = "RMP"
    MM = "MM"
    MMS = "MMS"
    MM32 = "MM32"
    MMS32 = "MMS32"


class DeviceType(Enum):
    CPU = "CPU"
    GPU = "GPU"


class EncodeType(Enum):
    ITEM = "ITEM"
    QUERY = "QUERY"


class SealMode(Enum):
    NONE = "NONE"
    AES_KEK = "AES_KEK"


class SealInfo:
    def __init__(self, mode: SealMode, kek: list[int] | None = None):
        self.mode = mode
        self.kek = list(kek or [])


class Context:
    def __init__(self, preset: ParameterPreset, device_type: DeviceType, dim: int, eval_mode: EvalMode):
        self.preset = preset
        self.device_type = device_type
        self.dim = dim
        self.eval_mode = eval_mode


class Query:
    def __init__(self, payload: Any = None):
        self.payload = payload if payload is not None else []

    def getInnerItemCount(self) -> int:
        if isinstance(self.payload, (list, tuple)):
            return len(self.payload)
        return 0

    @staticmethod
    def serializeTo(query: "Query") -> bytes:
        payload = getattr(query, "payload", b"")
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        try:
            return json.dumps(payload).encode("utf-8")
        except TypeError:
            return b"mock-query"


class Ciphertext:
    def __init__(self, data: bytes = b""):
        self.data = data


class CiphertextLv0(Ciphertext):
    pass


class SearchResult:
    def __init__(self, payload: Any = None):
        self.payload = payload if payload is not None else []

    @classmethod
    def deserializeFrom(cls, data: bytes) -> "SearchResult":
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            payload = []
        return cls(payload)

    def get_item_count(self) -> int:
        if isinstance(self.payload, (list, tuple)):
            return len(self.payload)
        return 0


class KeyPack:
    def __init__(self, context: Context | None = None):
        self.context = context
        self.payload: bytes | None = None

    def load_enc_key_file(self, path: str) -> None:
        with open(path, "rb") as handle:
            self.payload = handle.read()

    def load_enc_key_stream(self, data: bytes) -> None:
        self.payload = bytes(data)


class SecretKey:
    def __init__(self, payload: Any, seal_info: SealInfo | None = None):
        self.payload = payload
        self.seal_info = seal_info


class Encryptor:
    def __init__(self, context: Context):
        self.context = context

    def encrypt(self, msg, enc_key, encoding_type, level=0):
        return Query(list(msg))

    def encrypt_row(self, msg, enc_key, encoding_type, level=0):
        return [Query.serializeTo(Query(list(row))) for row in msg]

    def encrypt_bulk(self, msg, enc_key, encoding_type, level=0):
        return [Query(list(row)) for row in msg]


class Decryptor:
    def __init__(self, context_or_key: Any):
        self.context_or_key = context_or_key

    def decrypt(self, enc_msg, sec_key, is_score: bool = False):
        payload = getattr(enc_msg, "payload", enc_msg)
        if isinstance(payload, list):
            return payload
        return []


class MultiKeyGenerator:
    def __init__(self, context_list, key_dir: str, seal_info: SealInfo):
        self.context_list = context_list
        self.key_dir = key_dir
        self.seal_info = seal_info

    def generate_keys(self):
        return None

    def generate_keys_per_stream(self):
        return (None, b"sec", b"enc", b"eval")


class AwsConfig:
    def __init__(self):
        self.region = ""
        self.bucket_name = ""
        self.secret_prefix = ""


class GcpConfig:
    def __init__(self):
        self.bucket_name = ""
        self.secret_prefix = ""


class VaultConfig:
    def __init__(self):
        self.addr = ""
        self.mount = ""
        self.secret_prefix = ""


class KeyStorageConfig:
    @staticmethod
    def make_aws(cfg: AwsConfig):
        return ("aws", cfg)

    @staticmethod
    def make_gcp(cfg: GcpConfig):
        return ("gcp", cfg)

    @staticmethod
    def make_vault(cfg: VaultConfig):
        return ("vault", cfg)


class KeyManager:
    def __init__(self, storage_config: Any = None):
        self.storage_config = storage_config

    def wrap_sec_key(self, key_id: str, bin_path: str, json_path: str, seal_info: SealInfo | None = None):
        return None

    def wrap_enc_key(self, key_id: str, bin_path: str, json_path: str):
        return None

    def wrap_eval_key(self, key_id: str, bin_path: str, json_path: str):
        return None

    def wrap_sec_key_bytes(self, key_id: str, sec_key_bytes: bytes, seal_info: SealInfo | None = None) -> bytes:
        return bytes(sec_key_bytes)

    def wrap_enc_key_bytes(self, key_id: str, enc_key_bytes: bytes) -> bytes:
        return bytes(enc_key_bytes)

    def wrap_eval_key_bytes(self, key_id: str, eval_key_bytes: bytes) -> bytes:
        return bytes(eval_key_bytes)

    def wrap_metadata_key_bytes(
        self, key_id: str, metadata_key_bytes: bytes, seal_info: SealInfo | None = None
    ) -> bytes:
        payload = {
            "format": "sealed-key-v2",
            "key_id": key_id,
            "entries": [
                {
                    "name": "metadata",
                    "usage": "metadata",
                    "alg": "MOCK",
                    "edk": _b64url_encode(bytes(metadata_key_bytes)),
                    "iv": "",
                    "tag": "",
                }
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def unwrap_enc_key_bytes(self, wrapped_enc_key: bytes) -> bytes:
        if wrapped_enc_key.startswith(b"{"):
            raise ValueError("mock provider envelope expected binary key blob")
        return bytes(wrapped_enc_key)

    def unwrap_eval_key_bytes(self, wrapped_eval_key: bytes) -> bytes:
        if wrapped_eval_key.startswith(b"{"):
            raise ValueError("mock provider envelope expected binary key blob")
        return bytes(wrapped_eval_key)

    def unwrap_sec_key_bytes(self, wrapped_sec_key: bytes, seal_info: SealInfo | None = None) -> bytes:
        if wrapped_sec_key.startswith(b"{"):
            raise ValueError("mock provider envelope expected binary key blob")
        return bytes(wrapped_sec_key)

    def unwrap_metadata_key_bytes(
        self, wrapped_metadata_key: bytes | dict | str, seal_info: SealInfo | None = None
    ) -> bytes:
        if isinstance(wrapped_metadata_key, dict):
            payload = wrapped_metadata_key
        else:
            raw = wrapped_metadata_key.encode("utf-8") if isinstance(wrapped_metadata_key, str) else wrapped_metadata_key
            payload = json.loads(raw.decode("utf-8"))

        if payload.get("format") != "sealed-key-v2":
            raise ValueError("mock provider envelope requires sealed-key-v2")

        entries = payload.get("entries")
        if not entries:
            raise ValueError("mock evi only unwraps provider envelopes")

        entry = entries[0]
        if entry.get("alg") != "MOCK":
            raise ValueError("mock evi only unwraps mock provider envelopes")
        edk = _b64url_decode(entry.get("edk", ""))
        iv = _b64url_decode(entry.get("iv", "")) if entry.get("iv") else b""
        tag = _b64url_decode(entry.get("tag", "")) if entry.get("tag") else b""
        return iv + tag + edk if iv or tag else edk


def install_mock_evi() -> types.ModuleType:
    module = types.ModuleType("evi")
    module.ParameterPreset = ParameterPreset
    module.EvalMode = EvalMode
    module.DeviceType = DeviceType
    module.EncodeType = EncodeType
    module.SealMode = SealMode
    module.SealInfo = SealInfo
    module.Context = Context
    module.Query = Query
    module.Ciphertext = Ciphertext
    module.CiphertextLv0 = CiphertextLv0
    module.SearchResult = SearchResult
    module.KeyPack = KeyPack
    module.SecretKey = SecretKey
    module.Encryptor = Encryptor
    module.Decryptor = Decryptor
    module.MultiKeyGenerator = MultiKeyGenerator
    module.KeyManager = KeyManager
    module.AwsConfig = AwsConfig
    module.GcpConfig = GcpConfig
    module.VaultConfig = VaultConfig
    module.KeyStorageConfig = KeyStorageConfig
    module.utils = types.SimpleNamespace(get_random_bytes=lambda size: secrets.token_bytes(size))
    module.__dict__["_IS_PYTEST_MOCK"] = True
    sys.modules["evi"] = module
    return module
