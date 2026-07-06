# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

import base64
import binascii
import hashlib
import heapq
import json
import os
from pathlib import Path
from typing import List, Optional, TypedDict, Union

import evi
from evi import SealInfo, SealMode

from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb


class Position(TypedDict):
    shard_idx: int
    row_idx: int


def is_empty_dir(path_str: str) -> bool:
    p = Path(path_str).expanduser().resolve()

    if p.exists() and p.is_file():
        return False

    if p.exists() and any(p.iterdir()):
        return False

    return True


def check_key_dir(key_path: str, key_id: str) -> bool:
    """
    Checks if the key directory structure is valid.

    Args:
        key_path (str): The base path where keys are stored.
        key_id (str): The ID of the key to check.

    Returns:
        bool: True if the directory structure and required files exist, False otherwise.
    """
    base_dir = Path(key_path).expanduser().resolve()

    # Check if key_path exists and is a directory
    if not base_dir.exists() or not base_dir.is_dir():
        return False

    # Check if key_id directory exists
    key_dir = base_dir / key_id
    if not key_dir.exists() or not key_dir.is_dir():
        return False

    # Check for required files in the key_id directory
    required_files = ["EncKey.json", "EvalKey.json"]
    for file_name in required_files:
        file_path = key_dir / file_name
        if not file_path.exists():
            return False
    optional_files = ["SecKey.json"]
    if not any((key_dir / file_name).exists() for file_name in optional_files):
        return False

    return True


def _encode_blob(value):
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            return json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return base64.b64encode(value).decode("ascii")
    return value


def _decode_blob(value):
    if isinstance(value, str):
        return base64.b64decode(value)
    elif isinstance(value, (dict, list)):
        return json.dumps(value).encode("utf-8")
    return value


def _metadata_bytes_to_serializable(metadata_key_bytes: bytes):
    try:
        decoded = metadata_key_bytes.decode("utf-8")
        return json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return base64.b64encode(metadata_key_bytes).decode("ascii")


def _metadata_serializable_to_bytes(metadata_serializable):
    if isinstance(metadata_serializable, (dict, list)):
        return json.dumps(metadata_serializable).encode("utf-8")
    if isinstance(metadata_serializable, str):
        try:
            return base64.b64decode(metadata_serializable)
        except binascii.Error:
            return metadata_serializable.encode("utf-8")
    return metadata_serializable


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (RFC 4648 S5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding as needed."""
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _extract_v2_sealed_bytes(payload: dict) -> bytes:
    """Extract and reassemble GCM sealed bytes (IV + tag + ciphertext) from a v2 envelope."""
    entries = payload.get("entries", [])
    if not entries:
        raise ValueError("sealed-key-v2 envelope has no entries")
    entry = entries[0]
    iv = _b64url_decode(entry["iv"])
    tag = _b64url_decode(entry["tag"])
    edk = _b64url_decode(entry["edk"])
    return iv + tag + edk


def check_key_metadata(key_id: str, key_path: str) -> bool:
    """
    Check if the key metadata file exists and contains the specified key_id.

    :param key_id: The ID of the key to check.
    :param key_path: The path where the keys are stored.
    :return: True if the metadata file exists and contains the key_id, False otherwise.
    """
    metadata_file = Path(key_path) / "metadata.json"
    if not metadata_file.exists():
        return False

    with open(metadata_file, "r") as f:
        data = json.load(f)

    return "registered_id" in data and key_id in data["registered_id"]


def topk(vector: List[List[float]], k: int):
    import numpy as np

    # Collect top-k candidates per shard using numpy argpartition, then merge.
    # Avoids iterating all N elements (~3M with nprobe=1024) via a pure-Python
    # generator+lambda, which dominated latency (~470ms for nprobe=1024).
    candidates: List[tuple] = []
    for i, row in enumerate(vector):
        arr = np.asarray(row, dtype=np.float32)
        n = len(arr)
        if n == 0:
            continue
        k2 = min(k, n)
        for j in np.argpartition(arr, -k2)[-k2:]:
            candidates.append((float(arr[j]), i, int(j)))

    candidates.sort(key=lambda x: x[0], reverse=True)
    top = candidates[:k]

    topk_result = [((shard, row), score) for score, shard, row in top]
    topk_indices = [Position(shard_idx=shard, row_idx=row) for _, shard, row in top]

    return topk_result, topk_indices


def convert_to_encode_type(encode_type: Union[str, evi.EncodeType]) -> evi.EncodeType:
    if encode_type.lower() == "db" or encode_type.lower() == "item":
        return evi.EncodeType.ITEM
    elif encode_type.lower() == "query":
        return evi.EncodeType.QUERY
    elif isinstance(encode_type, evi.EncodeType):
        return encode_type
    else:
        raise ValueError(f"Unknown encode type: {encode_type}. Supported types are: ITEM, QUERY.")


_EVI_PRESET_ATTR = {"ip1": "IP1", "ip2": "IP2", "ip3": "IP3"}


def convert_to_preset(preset):
    key = preset.lower()
    if key.startswith("ip"):  # Case: IP
        attr = _EVI_PRESET_ATTR.get(key)
        if attr is None:
            raise ValueError(f"Unsupported IP preset: {preset}. Use IP1, IP2, or IP3.")
        if not hasattr(evi.ParameterPreset, attr):
            raise ValueError(
                f"Preset {attr} is not available in the installed evi extension. "
                f"Rebuild pyenvector against an evi version that exposes ParameterPreset.{attr}."
            )
        return getattr(evi.ParameterPreset, attr)
    elif key.startswith("qf"):  # Case: QF
        # Consider only QF0 for now
        return evi.ParameterPreset.QF0
    else:
        raise ValueError(f"Unknown preset: {preset}. Supported presets are: IP, QF.")


# Compat matrix between preset and eval_mode. Mirrors
# services/internal/utils/preset.go::ValidatePresetEvalMode on the Go side.
#   mm   / mms          -> ip1, ip2       (64-bit Q/P u64 path)
#   mm32 / mms32        -> ip3            (32-bit Q/P u32 NTT path)
#   rmp / flat / others -> not enforced   (passthrough)
# IP2 was demoted from the u32 path to the u64 path (companion to evi PR
# #698): pairing IP2 with mm32/mms32 is semantically contradictory, so IP2
# is now valid only under the u64 modes mm/mms (alongside IP1). IP2 remains
# a valid preset — this is a demotion of its eval-mode pairing, not removal.
_PRESET_EVAL_MODE_ALLOWED = {
    "mm": {"ip1", "ip2"},
    "mms": {"ip1", "ip2"},
    "mm32": {"ip3"},
    "mms32": {"ip3"},
}

# Default preset chosen when an example/CLI caller omits --preset. For modes
# with a single valid preset (mm32/mms32 -> ip3) the choice is forced; for
# mm/mms we keep ip1 (the longest-deployed u64 option) for backward compat.
_DEFAULT_PRESET_FOR_EVAL_MODE = {
    "mm": "ip1",
    "mms": "ip1",
    "mm32": "ip3",
    "mms32": "ip3",
}


def _preset_evalmode_name(value):
    """Return the lowercase string form of a preset or eval_mode argument.

    Accepts str, evi enum (ParameterPreset / EvalMode — exposes ``.name``), or
    None/empty. Anything else (e.g. an enum without a name) yields "".
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip().lower()
    name = getattr(value, "name", None)
    return name.strip().lower() if isinstance(name, str) else ""


def validate_preset_evalmode(preset, eval_mode):
    """Raise ValueError if (preset, eval_mode) is an unsupported combination.

    Accepts str or evi enum (ParameterPreset / EvalMode) on either argument.
    Empty preset or empty eval_mode short-circuits to None so that callers can
    let default-resolution fill them in and re-validate later.
    """
    p = _preset_evalmode_name(preset)
    m = _preset_evalmode_name(eval_mode)
    if not p or not m:
        return
    allowed = _PRESET_EVAL_MODE_ALLOWED.get(m)
    if allowed is None:
        return  # passthrough for rmp / flat / unknown
    if p not in allowed:
        raise ValueError(
            f"preset {preset!r} is not compatible with eval_mode {eval_mode!r} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )


def resolve_preset(arg_preset, eval_mode):
    """Return a validated, lowercase preset string for the given eval_mode.

    If ``arg_preset`` is falsy, falls back to the per-eval_mode default. The
    resolved (preset, eval_mode) pair is then run through
    validate_preset_evalmode and any incompatibility raises ValueError.
    """
    m = _preset_evalmode_name(eval_mode)
    preset = (arg_preset or _DEFAULT_PRESET_FOR_EVAL_MODE.get(m, "")).lower()
    validate_preset_evalmode(preset, eval_mode)
    return preset


def convert_to_search_type(preset):
    if isinstance(preset, str):
        if preset.lower() == "iponly" or preset.lower() == "ip" or preset.lower() == "ip0":
            search_type = envector_type_pb.SearchType.IPOnly
        elif preset.lower() == "ipandqf" or preset.lower() == "qf" or preset.lower() == "qf0":
            search_type = envector_type_pb.SearchType.IPAndQF
        else:
            search_type = envector_type_pb.SearchType.IPOnly

    elif isinstance(preset, envector_type_pb.SearchType):
        if preset not in [envector_type_pb.SearchType.IPOnly, envector_type_pb.SearchType.IPAndQF]:
            search_type = envector_type_pb.SearchType.IPOnly
        else:
            search_type = search_type
    else:
        raise ValueError(f"Invalid type for search_type: {type(search_type)}.")

    return search_type


def _get_seal_info(seal_mode, seal_kek_path):
    if seal_mode is None or seal_mode.lower() == "none":
        return SealInfo(SealMode.NONE)
    if (seal_mode.lower() == "aes" or seal_mode.lower() == "aes_kek") and seal_kek_path is None:
        raise ValueError("Seal Mode needs kek path or kek bytes")
    if seal_mode.lower() == "aes" or seal_mode.lower() == "aes_kek":
        if isinstance(seal_kek_path, bytes):
            data = seal_kek_path
            if len(data) < 32:
                raise ValueError(f"KEK bytes are too small: expected at least 32 bytes, got {len(data)}")
            return SealInfo(SealMode.AES_KEK, list(data))
        elif isinstance(seal_kek_path, str):
            if not os.path.isfile(seal_kek_path):
                raise FileNotFoundError(f"KEK file not found: {seal_kek_path}")
            with open(seal_kek_path, "rb") as f:
                data = f.read(32)
            if len(data) < 32:
                raise ValueError(f"KEK file is too small: expected at least 32 bytes, got {len(data)}")
            return SealInfo(SealMode.AES_KEK, list(data))
        else:
            raise TypeError("seal_kek_path must be a file path (str) or bytes")
    raise ValueError(f"Unknown seal mode: {seal_mode}. Supported modes are: aes.")


def get_envector_enc_key() -> Union[str, None]:
    """
    Retrieves the Envector encryption key from the environment variable.

    Returns:
        str or None: The encryption key if set, otherwise None.
    """
    return os.environ.get("ENVECTOR_ENC_KEY", None)


def get_envector_sec_key() -> Union[str, None]:
    """
    Retrieves the Envector secret key from the environment variable.

    Returns:
        str or None: The secret key if set, otherwise None.
    """
    return os.environ.get("ENVECTOR_SEC_KEY", None)


def get_envector_eval_key() -> Union[str, None]:
    """
    Retrieves the Envector evaluation key from the environment variable.

    Returns:
        str or None: The evaluation key if set, otherwise None.
    """
    return os.environ.get("ENVECTOR_EVAL_KEY", None)


def get_metadata_key() -> Union[str, None]:
    """
    Retrieves the Envector metadata key from the environment variable.

    Returns:
        str or None: The metadata key if set, otherwise None.
    """
    return os.environ.get("ENVECTOR_METADATA_KEY", None)


def get_seal_kek() -> Union[bytes, None]:
    """
    Retrieves the Envector seal KEK from the environment variable.

    Returns:
        bytes or None: The seal KEK if set, otherwise None.
    """
    kek = os.environ.get("ENVECTOR_SEAL_KEK", None)
    return bytes(kek, "utf-8") if kek is not None else None


_EVI_KEY_MANAGER: Optional["evi.KeyManager"] = None


def _get_evi_key_manager():
    global _EVI_KEY_MANAGER
    if _EVI_KEY_MANAGER is None:
        _EVI_KEY_MANAGER = evi.KeyManager()
    return _EVI_KEY_MANAGER


def _load_wrapped_metadata_key(raw_bytes: bytes):
    # Backward compatibility: prefer provider-envelope unwrap (new evi format) before legacy pyenvector parsing.
    unwrapped = _try_unwrap_provider_envelope(raw_bytes)
    if unwrapped is not None:
        return unwrapped

    payload = json.loads(raw_bytes.decode("utf-8"))
    fmt = payload.get("format")
    if fmt == "sealed-key-v2":
        return _extract_v2_sealed_bytes(payload)
    if fmt is not None:
        # Provider envelope (EVI crypto): try generic unwrap before failing.
        unwrapped = _try_unwrap_provider_envelope(raw_bytes)
        if unwrapped is not None:
            return unwrapped
        metadata_entry = _extract_metadata_entry_key_data(payload)
        if metadata_entry is not None:
            return metadata_entry
        raise ValueError(f"Unknown sealed-key format: {fmt!r}")
    serialized = payload.get("metadata_blob", payload)
    return _metadata_serializable_to_bytes(serialized)


def _try_unwrap_provider_envelope(raw_bytes: bytes) -> Optional[bytes]:
    km = _get_evi_key_manager()
    unwrap_candidates = [km.unwrap_sec_key_bytes, km.unwrap_enc_key_bytes, km.unwrap_eval_key_bytes]
    unwrap_metadata = getattr(km, "unwrap_metadata_key_bytes", None)
    if callable(unwrap_metadata):
        unwrap_candidates.append(unwrap_metadata)

    for unwrap in unwrap_candidates:
        try:
            return unwrap(raw_bytes)
        except Exception:
            continue
    return None


def _extract_metadata_entry_key_data(payload: dict) -> Optional[bytes]:
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        return None
    entry = entries[0]
    if not isinstance(entry, dict):
        return None

    name = str(entry.get("name", "")).lower()
    usage = str(entry.get("usage", "")).lower()
    role = str(entry.get("role", "")).lower()
    is_metadata_entry = (
        name in {"metadatakey", "metadata_key", "meta_aes"} or usage == "metadata" or ("metadata" in role)
    )
    if not is_metadata_entry:
        return None

    key_data = entry.get("key_data")
    if isinstance(key_data, str):
        try:
            return base64.b64decode(key_data)
        except binascii.Error:
            return None
    return None


def _unwrap_key_dict_payload(payload: dict) -> bytes:
    metadata_blob = payload.get("metadata_blob")
    if metadata_blob is not None:
        return _metadata_serializable_to_bytes(metadata_blob)
    fmt = payload.get("format")
    if fmt == "sealed-key-v2":
        return _extract_v2_sealed_bytes(payload)

    raw_bytes = json.dumps(payload).encode("utf-8")
    unwrapped = _try_unwrap_provider_envelope(raw_bytes)
    if unwrapped is not None:
        return unwrapped

    metadata_entry = _extract_metadata_entry_key_data(payload)
    if metadata_entry is not None:
        return metadata_entry

    raise ValueError("Unsupported JSON key payload.")


def _load_wrapped_key_from_json(path: Path) -> bytes:
    raw_bytes = path.read_bytes()
    filename = path.name.lower()
    if filename.endswith("metadatakey.json"):
        return _load_wrapped_metadata_key(raw_bytes)
    km = _get_evi_key_manager()
    if filename.endswith("seckey.json"):
        return km.unwrap_sec_key_bytes(raw_bytes)
    if filename.endswith("enckey.json"):
        return km.unwrap_enc_key_bytes(raw_bytes)
    if filename.endswith("evalkey.json"):
        return km.unwrap_eval_key_bytes(raw_bytes)

    # Fallback for arbitrary JSON filenames (e.g., sec_blob.json in external stores).
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        return _unwrap_key_dict_payload(payload)

    unwrapped = _try_unwrap_provider_envelope(raw_bytes)
    if unwrapped is not None:
        return unwrapped

    raise ValueError(f"Unsupported key file: {path}")


def get_key_stream(key_path: Union[str, bytes, dict]) -> bytes:
    """
    Reads and returns the bytes of the key file or key stream.

    Args:
        key_path (Union[str, bytes]): The key source.
    Returns:
        bytes: The bytes of the key file or provided data.
    """
    if isinstance(key_path, dict):
        key_bytes = _unwrap_key_dict_payload(key_path)
    elif isinstance(key_path, (bytes, bytearray)):
        key_bytes = bytes(key_path)
    elif isinstance(key_path, str):
        potential_path = Path(key_path).expanduser()
        if potential_path.exists():
            if potential_path.suffix == ".bin":
                key_bytes = potential_path.read_bytes()
            elif potential_path.suffix == ".json":
                key_bytes = _load_wrapped_key_from_json(potential_path)
            else:
                with open(potential_path, "rb") as key_file:
                    key_bytes = key_file.read()
        else:
            stripped = key_path.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    data = json.loads(stripped)
                except json.JSONDecodeError:
                    raw_bytes = stripped.encode("utf-8")
                else:
                    return _unwrap_key_dict_payload(data)
                key_bytes = _try_unwrap_provider_envelope(raw_bytes)
                if key_bytes is None:
                    raise ValueError("Unsupported JSON key payload.")
            else:
                import ast

                key_bytes = ast.literal_eval(key_path)
    else:
        raise TypeError("key_path must be a file path (str) or bytes")
    return key_bytes


def _normalize_key_type(key_type) -> set:
    if key_type is None:
        return None
    return {key_type} if isinstance(key_type, str) else set(key_type)


def _calculate_file_sha256(file_path: str) -> str:
    """
    Calculate SHA256 checksum of a file without loading it entirely into memory.
    """
    hash_obj = hashlib.sha256()
    if isinstance(file_path, str):
        with open(file_path, "rb") as file:
            hash_obj.update(file.read())
    elif isinstance(file_path, bytes):
        hash_obj.update(file_path)
    return hash_obj.hexdigest()
