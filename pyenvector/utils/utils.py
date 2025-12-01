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

import hashlib
import heapq
import json
import os
from pathlib import Path
from typing import List, TypedDict, Union

import evi
from evi import SealInfo, SealMode

from pyenvector.proto_gen import type_pb2 as envector_type_pb


class Position(TypedDict):
    shard_idx: int
    row_idx: int


def is_empty_dir(path_str: str) -> None:
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
    required_files = ["EncKey.bin", "EvalKey.bin"]
    for file_name in required_files:
        file_path = key_dir / file_name
        if not file_path.exists():
            return False
    optional_files = ["SecKey.bin", "SecKey_sealed.bin"]
    if not any((key_dir / file_name).exists() for file_name in optional_files):
        return False

    return True


def is_empty_key_metadata(key_path: str) -> bool:
    """
    Check if the key metadata file exists and is empty.

    :param key_path: The path where the keys are stored.
    :return: True if the metadata file does not exist or is empty, False otherwise.
    """
    metadata_file = Path(key_path) / "metadata.json"
    if not metadata_file.exists():
        return True
    return metadata_file.stat().st_size == 0


def is_registered_key(key_id: str, key_path: str) -> bool:
    """
    Check if the key with the given key_id is registered in the specified key_path.

    :param key_id: The ID of the key to check.
    :param key_path: The path where the keys are stored.
    :return: True if the key is registered, False otherwise.
    """
    return check_key_metadata(key_id, key_path)


def generate_metadata(
    key_id: str,
    key_path: str,
):
    metadata_file = Path(key_path) / "metadata.json"

    if metadata_file.exists():
        with open(metadata_file, "r") as f:
            data = json.load(f)
        if "registered_id" in data:
            data["registered_id"].append(key_id)
        else:
            data["registered_id"] = [key_id]
    else:
        data = {"registered_id": [key_id]}

    with open(metadata_file, "w") as f:
        json.dump(data, f, indent=2)


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


def check_sec_key(key_dir: str, is_ip: bool = True):
    """
    Checks if the secret key file exists in the specified directory.

    Args:
        key_dir (str): The directory where the secret key file is expected.
        is_ip (bool): If True, checks for 'SecKey.bin'; otherwise, checks for 'SecKeyD16.bin'.

    Returns:
        bool: True if the secret key file exists, False otherwise.
    """
    key_dir = Path(key_dir).expanduser().resolve()

    if not key_dir.exists() or not key_dir.is_dir():
        return False

    sec_key_file = "SecKey.bin" if is_ip else "SecKeyD16.bin"
    sec_key_path = key_dir / sec_key_file

    return sec_key_path.exists()


def check_enc_key(key_dir: str):
    """
    Checks if the encrypted key file exists in the specified directory.

    Args:
        key_dir (str): The directory where the encrypted key file is expected.

    Returns:
        bool: True if the encrypted key file exists, False otherwise.
    """
    key_dir = Path(key_dir).expanduser().resolve()

    if not key_dir.exists() or not key_dir.is_dir():
        return False

    enc_key_file = "EncKey.bin"
    enc_key_path = key_dir / enc_key_file

    return enc_key_path.exists()


def get_enc_key_path(key_dir: str):
    """
    Returns the path to the encrypted key file.

    Args:
        key_dir (str): The directory where the encrypted key file is expected.

    Returns:
        str: The full path to the encrypted key file.
    """
    key_dir = Path(key_dir).expanduser().resolve()

    if not key_dir.exists() or not key_dir.is_dir():
        raise FileNotFoundError(f"The directory {key_dir} does not exist or is not a directory.")

    enc_key_file = "EncKey.bin"
    return str(key_dir / enc_key_file)


def get_sec_key_path(key_dir: str, is_ip: bool = True):
    """
    Returns the path to the secret key file based on the specified directory and type.

    Args:
        key_dir (str): The directory where the secret key file is expected.
        is_ip (bool): If True, returns the path for 'SecKey.bin'; otherwise, returns the path for 'SecKeyD16.bin'.

    Returns:
        str: The full path to the secret key file.
    """
    key_dir = Path(key_dir).expanduser().resolve()

    if not key_dir.exists() or not key_dir.is_dir():
        raise FileNotFoundError(f"The directory {key_dir} does not exist or is not a directory.")

    sec_key_file = "SecKey.bin" if is_ip else "SecKeyD16.bin"
    return str(key_dir / sec_key_file)


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


def get_key_stream(key_path: str) -> bytes:
    """
    Reads and returns the bytes of the key file at the specified path.

    Args:
        key_path (str): The path to the key file.
    Returns:
        bytes: The bytes of the key file.
    """
    if isinstance(key_path, str):
        if not key_path.endswith(".bin"):
            import ast

            key_bytes = ast.literal_eval(key_path)
        else:
            with open(key_path, "rb") as key_file:
                key_bytes = key_file.read()
    elif isinstance(key_path, bytes):
        key_bytes = key_path
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
