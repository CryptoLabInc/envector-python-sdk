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

"""
AES encryption utilities for pyenvector/enVector.

This module provides AES-GCM encryption/decryption functionality for metadata
and key sealing operations.
"""

import base64
import json
import os
import secrets
from typing import Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from pyenvector.utils.utils import get_key_stream


class AESHelper:
    """Helper class for AES-CTR operations to reduce code duplication."""

    # Constants
    AES256_KEY_SIZE = 32
    AES256_IV_SIZE = 16  # For CTR, 16 bytes (128 bits) is standard
    MIN_SEALED_KEY_SIZE = AES256_IV_SIZE + AES256_KEY_SIZE  # 48 bytes

    @staticmethod
    def validate_key_length(key: bytes, expected_length: int = AES256_KEY_SIZE) -> None:
        """Validate key length."""
        if len(key) != expected_length:
            raise ValueError(f"Key must be {expected_length} bytes, got {len(key)}")

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random IV for AES-CTR."""
        return secrets.token_bytes(AESHelper.AES256_IV_SIZE)

    @staticmethod
    def encrypt_with_aes(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt plaintext using AES-256-CTR."""
        iv = AESHelper.generate_iv()
        cipher = CryptoCipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def decrypt_with_aes(key: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext using AES-256-CTR."""
        if len(ciphertext) < AESHelper.AES256_IV_SIZE:
            raise ValueError("Ciphertext too short")
        iv = ciphertext[: AESHelper.AES256_IV_SIZE]
        ct = ciphertext[AESHelper.AES256_IV_SIZE :]
        cipher = CryptoCipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    @staticmethod
    def save_key_to_file(key: bytes, path: str) -> None:
        """Save key to file with restrictive permissions."""
        with open(path, "wb") as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    @staticmethod
    def load_key_from_file(path: str, expected_length: int = AES256_KEY_SIZE) -> bytes:
        """Load key from file and validate length."""
        with open(path, "rb") as f:
            key = f.read()
        AESHelper.validate_key_length(key, expected_length)
        return key


def generate_aes256_key(path: str, save: bool) -> bytes:
    """
    Generates a 32-byte random key (AES-256) and saves it to a file.
    Returns: The generated key (bytes)
    """
    key = secrets.token_bytes(AESHelper.AES256_KEY_SIZE)
    if save:
        AESHelper.save_key_to_file(key, path)
    return key


def load_key(path: str) -> bytes:
    """Load key from file with flexible length validation."""
    with open(path, "rb") as f:
        key = f.read()
    if len(key) < 32:
        raise ValueError(f"Invalid AES key length: {len(key)}")
    return key[:32]


def _get_kek_bytes(kek: Union[bytes, str]) -> bytes:
    """
    Helper function to get KEK bytes from either bytes or file path.

    Args:
        kek: Either KEK bytes or path to KEK file

    Returns:
        bytes: KEK bytes

    Raises:
        ValueError: If kek is neither bytes nor str, or if file cannot be read
    """
    if isinstance(kek, bytes):
        AESHelper.validate_key_length(kek, AESHelper.AES256_KEY_SIZE)
        return kek
    elif isinstance(kek, str):
        # Treat as file path
        return load_key(kek)
    else:
        raise ValueError(f"KEK must be bytes or str (file path), got {type(kek)}")


def seal_metadata_enc_key(metadata_enc_key: bytes, kek: Union[bytes, str], output_path: str = None) -> None:
    """
    Seals a metadata encryption key using KEK (Key Encryption Key) with AES-256-GCM.

    Args:
        metadata_enc_key: The metadata encryption key to seal (32 bytes)
        kek: The Key Encryption Key (32 bytes or path to KEK file)
        output_path: Path where the sealed key will be saved

    Raises:
        ValueError: If key lengths are invalid
        IOError: If file operations fail
    """
    AESHelper.validate_key_length(metadata_enc_key, AESHelper.AES256_KEY_SIZE)

    # Get KEK bytes (from bytes or file path)
    kek_bytes = _get_kek_bytes(kek)

    # Encrypt the metadata key using AES-256-GCM
    sealed_key = AESHelper.encrypt_with_aes(kek_bytes, metadata_enc_key)
    if output_path is None:
        return sealed_key
    # Save to file
    AESHelper.save_key_to_file(sealed_key, output_path)


def unseal_metadata_enc_key(sealed_key_source: Union[str, bytes, bytearray], kek: Union[bytes, str]) -> bytes:
    """
    Unseals a metadata encryption key using KEK (Key Encryption Key) with AES-256-GCM.

    Args:
        sealed_key_source: Path to the sealed key file or raw sealed key bytes
        kek: The Key Encryption Key (32 bytes or path to KEK file)

    Returns:
        bytes: The unsealed metadata encryption key (32 bytes)

    Raises:
        ValueError: If key lengths are invalid or file format is incorrect
        IOError: If file operations fail
    """
    # Get KEK bytes (from bytes or file path)
    kek_bytes = _get_kek_bytes(kek)

    # Load sealed key bytes from path or raw bytes
    if isinstance(sealed_key_source, (bytes, bytearray)):
        sealed_data = bytes(sealed_key_source)
    elif isinstance(sealed_key_source, str):
        sealed_data = get_key_stream(sealed_key_source)
    else:
        raise TypeError("sealed_key_source must be a path or bytes-like object.")

    # Check minimum size
    if len(sealed_data) < AESHelper.MIN_SEALED_KEY_SIZE:
        raise ValueError(
            "Sealed key file too small: expected at least "
            f"{AESHelper.MIN_SEALED_KEY_SIZE} bytes, got {len(sealed_data)}"
        )

    # Decrypt using AES-256-GCM
    try:
        metadata_enc_key = AESHelper.decrypt_with_aes(kek_bytes, sealed_data)
    except Exception as e:
        raise ValueError(f"Failed to decrypt sealed key: {e}")

    # Validate decrypted key length
    AESHelper.validate_key_length(metadata_enc_key, AESHelper.AES256_KEY_SIZE)

    return metadata_enc_key


def _to_bytes(metadata: Union[dict, list, str, bytes]) -> bytes:
    """Convert metadata to bytes for encryption."""
    if isinstance(metadata, (dict, list)):
        return json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if isinstance(metadata, str):
        return metadata.encode("utf-8")
    if isinstance(metadata, (bytes, bytearray)):
        return bytes(metadata)
    raise TypeError(f"Unsupported metadata type: {type(metadata)}")


def _resolve_metadata_key(
    key_source: Union[str, bytes, bytearray, None],
    kek: Optional[Union[bytes, str]] = None,
) -> bytes:
    """Return usable metadata key bytes from a path/bytes."""
    if key_source is None:
        raise ValueError("Metadata key is not configured.")
    if isinstance(key_source, (bytes, bytearray)):
        key_bytes = bytes(key_source)
    else:
        key_bytes = get_key_stream(key_source)
    if kek is not None:
        return unseal_metadata_enc_key(key_bytes, kek)
    AESHelper.validate_key_length(key_bytes, AESHelper.AES256_KEY_SIZE)
    return key_bytes


def encrypt_metadata(
    metadata: Union[dict, list, str, bytes],
    key_path: Union[str, bytes, bytearray, None],
    *,
    aad: Optional[bytes] = None,
    kek: Optional[Union[bytes, str]] = None,
) -> str:
    """
    Encrypts metadata using AES-GCM and returns a Base64 string.

    Args:
        metadata: Metadata to encrypt. Can be dict, list, str, or bytes.
                 (Will be converted to JSON string if dict/list, or to string if str/bytes.)
        key_path: Path to the encryption key file (can be sealed or unsealed)
        aad: Additional authenticated data (optional)
        kek: Key Encryption Key for unsealing the metadata key (bytes or path to KEK file, optional)

    Returns:
        str: Base64-encoded encrypted metadata string

    Note:
        The Go backend expects metadata to be stored as string type in the database.
        This function ensures compatibility by converting all input types to string format.
        If kek is provided, the function will unseal the key at key_path before use.
    """
    # Load the metadata encryption key (accepts file path or raw key bytes)
    key = _resolve_metadata_key(key_path, kek)

    # Encrypt using AES-256-GCM
    pt = _to_bytes(metadata)
    token = AESHelper.encrypt_with_aes(key, pt, aad)
    return base64.b64encode(token).decode("ascii")


def decrypt_metadata(
    token_b64: str,
    key_path: Union[str, bytes, bytearray, None],
    *,
    aad: Optional[bytes] = None,
    kek: Optional[Union[bytes, str]] = None,
) -> Union[dict, list, str, bytes]:
    """
    Decrypts a Base64 string using AES-GCM.

    Args:
        token_b64: Base64-encoded encrypted metadata string
        key_path: Path to the decryption key file (can be sealed or unsealed)
        aad: Additional authenticated data (optional)
        kek: Key Encryption Key for unsealing the metadata key (bytes or path to KEK file, optional)

    Returns:
        Union[dict, list, str, bytes]: Decrypted metadata in its original format.
                                      If the original was dict/list, returns the parsed object.
                                      If the original was str/bytes, returns the string/bytes.

    Note:
        This function attempts to restore the original metadata format.
        The Go backend stores metadata as string, so this function handles
        the conversion back to the appropriate Python type.
        If kek is provided, the function will unseal the key at key_path before use.
    """
    # Load the metadata encryption key (accepts file path or raw key bytes)
    key = _resolve_metadata_key(key_path, kek)

    # Decode and decrypt
    raw = base64.b64decode(token_b64)
    pt = AESHelper.decrypt_with_aes(key, raw, aad)

    # Try to decode as UTF-8 and parse as JSON if possible
    try:
        text = pt.decode("utf-8")
        try:
            return json.loads(text)
        except Exception:
            return text
    except Exception:
        return pt
