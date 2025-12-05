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

from pyenvector.proto_gen import type_pb2 as envector_type_pb


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
    topk_result = heapq.nlargest(
        k, (((i, j), v) for i, row in enumerate(vector) for j, v in enumerate(row)), key=lambda x: x[1]
    )

    topk_indices = [Position(shard_idx=pos[0], row_idx=pos[1]) for pos, _ in topk_result]

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


def convert_to_preset(preset):
    if preset.lower() == "ip" or preset.lower() == "ip0":
        return evi.ParameterPreset.IP0
    elif preset.lower() == "qf" or preset.lower() == "qf0":
        return evi.ParameterPreset.QF0
    else:
        raise ValueError(f"Unknown preset: {preset}. Supported presets are: IP, QF.")


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
    payload = json.loads(raw_bytes.decode("utf-8"))
    serialized = payload.get("metadata_blob", payload)
    return _metadata_serializable_to_bytes(serialized)


def _unwrap_key_dict_payload(payload: dict) -> bytes:
    metadata_blob = payload.get("metadata_blob")
    if metadata_blob is not None:
        return _metadata_serializable_to_bytes(metadata_blob)
    raw_bytes = json.dumps(payload).encode("utf-8")
    km = _get_evi_key_manager()
    for unwrap in (km.unwrap_sec_key_bytes, km.unwrap_enc_key_bytes, km.unwrap_eval_key_bytes):
        try:
            return unwrap(raw_bytes)
        except Exception:
            continue
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
                km = _get_evi_key_manager()
                for unwrap in (km.unwrap_sec_key_bytes, km.unwrap_enc_key_bytes, km.unwrap_eval_key_bytes):
                    try:
                        key_bytes = unwrap(raw_bytes)
                        break
                    except Exception:
                        continue
                else:
                    raise ValueError("Unsupported JSON key payload.")
            else:
                import ast

                key_bytes = ast.literal_eval(key_path)
    else:
        raise TypeError("key_path must be a file path (str) or bytes")
    return key_bytes


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
