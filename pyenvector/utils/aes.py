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
import warnings
from pathlib import Path
from typing import Optional, Union

import evi
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from pyenvector.utils.utils import get_key_stream


class AESHelper:
    """Helper class for AES encryption operations."""

    # Constants
    AES256_KEY_SIZE = 32
    AES256_IV_SIZE = 16  # CTR: 16 bytes (legacy)
    GCM_IV_SIZE = 12  # GCM: 12 bytes (NIST recommended)
    GCM_TAG_SIZE = 16  # GCM: 16 bytes auth tag
    MIN_SEALED_KEY_SIZE = AES256_IV_SIZE + AES256_KEY_SIZE  # 48 bytes (CTR legacy)
    MIN_GCM_SEALED_SIZE = GCM_IV_SIZE + GCM_TAG_SIZE + AES256_KEY_SIZE  # 60 bytes

    @staticmethod
    def validate_key_length(key: bytes, expected_length: int = AES256_KEY_SIZE) -> None:
        """Validate key length."""
        if len(key) != expected_length:
            raise ValueError(f"Key must be {expected_length} bytes, got {len(key)}")

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random IV for AES-CTR (legacy)."""
        return _get_random_bytes(AESHelper.AES256_IV_SIZE)

    @staticmethod
    def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt plaintext using AES-256-GCM. Returns IV(12) + tag(16) + ciphertext."""
        iv = _get_random_bytes(AESHelper.GCM_IV_SIZE)
        cipher = CryptoCipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        if aad is not None:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ct

    @staticmethod
    def decrypt_aes_gcm(key: bytes, sealed: bytes, aad: Optional[bytes] = None) -> bytes:
        """Decrypt AES-256-GCM. Input: IV(12) + tag(16) + ciphertext."""
        min_len = AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE
        if len(sealed) < min_len:
            raise ValueError(f"GCM ciphertext too short: need >= {min_len} bytes, got {len(sealed)}")
        iv = sealed[: AESHelper.GCM_IV_SIZE]
        tag = sealed[AESHelper.GCM_IV_SIZE : AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE]
        ct = sealed[AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE :]
        cipher = CryptoCipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if aad is not None:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(ct) + decryptor.finalize()

    @staticmethod
    def encrypt_aes_ctr(key: bytes, plaintext: bytes) -> bytes:
        """Encrypt plaintext using AES-256-CTR (legacy). Returns IV(16) + ciphertext."""
        iv = AESHelper.generate_iv()
        cipher = CryptoCipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def decrypt_aes_ctr(key: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using AES-256-CTR (legacy). Input: IV(16) + ciphertext."""
        if len(ciphertext) < AESHelper.AES256_IV_SIZE:
            raise ValueError("Ciphertext too short")
        iv = ciphertext[: AESHelper.AES256_IV_SIZE]
        ct = ciphertext[AESHelper.AES256_IV_SIZE :]
        cipher = CryptoCipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    # Backward-compatible aliases
    encrypt_with_aes = encrypt_aes_ctr
    decrypt_with_aes = decrypt_aes_ctr

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


def _get_random_bytes(size: int) -> bytes:
    if size < 0:
        raise ValueError(f"size must be non-negative, got {size}")
    try:
        rng = getattr(getattr(evi, "utils", None), "get_random_bytes", None)
        if callable(rng):
            return bytes(rng(size))
    except Exception:
        pass
    # Backward compatibility: older evi bindings may not expose utils.get_random_bytes.
    return secrets.token_bytes(size)


def generate_aes256_key(path: str, save: bool) -> bytes:
    """
    Generates a 32-byte random key (AES-256) and saves it to a file.
    Returns: The generated key (bytes)
    """
    key = _get_random_bytes(AESHelper.AES256_KEY_SIZE)
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


def _try_unwrap_metadata_key(key_blob: bytes, kek: Union[bytes, str]) -> Optional[bytes]:
    try:
        km = evi.KeyManager()
    except Exception:
        return None

    try:
        seal_info = evi.SealInfo(evi.SealMode.AES_KEK, list(_get_kek_bytes(kek)))
        return km.unwrap_metadata_key_bytes(key_blob, seal_info)
    except Exception:
        pass

    # Backward compatibility: accept provider envelopes that were wrapped with SealMode.NONE.
    try:
        return km.unwrap_metadata_key_bytes(key_blob)
    except Exception:
        return None


def seal_metadata_enc_key(metadata_enc_key: bytes, kek: Union[bytes, str], output_path: str = None) -> bytes:
    """
    Seals a metadata encryption key using KEK (Key Encryption Key) with AES-256-GCM.

    Returns IV(12) + tag(16) + ciphertext (60 bytes for a 32-byte key).
    """
    AESHelper.validate_key_length(metadata_enc_key, AESHelper.AES256_KEY_SIZE)
    kek_bytes = _get_kek_bytes(kek)
    sealed_key = AESHelper.encrypt_aes_gcm(kek_bytes, metadata_enc_key)
    if output_path is not None:
        AESHelper.save_key_to_file(sealed_key, output_path)
    return sealed_key


def unseal_metadata_enc_key(
    sealed_key_source: Union[str, bytes, bytearray],
    kek: Union[bytes, str],
    *,
    seal_alg: Optional[str] = None,
) -> bytes:
    """
    Unseals a metadata encryption key using KEK.

    Args:
        sealed_key_source: Raw sealed key bytes or path to sealed key file
        kek: The Key Encryption Key (32 bytes or path to KEK file)
        seal_alg: Explicit algorithm hint ("AES-GCM-256" or "AES-CTR-256").
                  If None, tries GCM first then CTR fallback.

    Returns:
        bytes: The unsealed metadata encryption key (32 bytes)
    """
    kek_bytes = _get_kek_bytes(kek)

    if isinstance(sealed_key_source, (bytes, bytearray)):
        sealed_data = bytes(sealed_key_source)
    elif isinstance(sealed_key_source, str):
        sealed_data = get_key_stream(sealed_key_source)
    else:
        raise TypeError("sealed_key_source must be a path or bytes-like object.")

    if len(sealed_data) < AESHelper.MIN_SEALED_KEY_SIZE:
        raise ValueError(
            f"Sealed key too small: expected >= {AESHelper.MIN_SEALED_KEY_SIZE} bytes, got {len(sealed_data)}"
        )

    # Build context string for warnings (S-6)
    _source_ctx = ""
    if isinstance(sealed_key_source, str):
        _source_ctx = f" (source: {sealed_key_source})"

    if seal_alg == "AES-GCM-256":
        # Explicit GCM — never fall back (B-3)
        metadata_enc_key = AESHelper.decrypt_aes_gcm(kek_bytes, sealed_data)
    elif seal_alg == "AES-CTR-256":
        warnings.warn(
            f"Legacy AES-CTR-256 sealed key detected{_source_ctx}. Re-seal with AES-GCM-256.",
            DeprecationWarning,
            stacklevel=2,
        )
        metadata_enc_key = AESHelper.decrypt_aes_ctr(kek_bytes, sealed_data)
    else:
        # Auto-detect: try GCM first, fall back to CTR
        try:
            metadata_enc_key = AESHelper.decrypt_aes_gcm(kek_bytes, sealed_data)
        except (InvalidTag, ValueError):
            warnings.warn(
                f"Legacy AES-CTR-256 sealed key detected{_source_ctx}. Re-seal with AES-GCM-256.",
                DeprecationWarning,
                stacklevel=2,
            )
            metadata_enc_key = AESHelper.decrypt_aes_ctr(kek_bytes, sealed_data)

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
    elif isinstance(key_source, str):
        if kek is not None:
            path = Path(key_source).expanduser()
            if path.exists() and path.suffix.lower() == ".json":
                native_key = _try_unwrap_metadata_key(path.read_bytes(), kek)
                if native_key is not None:
                    AESHelper.validate_key_length(native_key, AESHelper.AES256_KEY_SIZE)
                    return native_key
            stripped = key_source.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                native_key = _try_unwrap_metadata_key(stripped.encode("utf-8"), kek)
                if native_key is not None:
                    AESHelper.validate_key_length(native_key, AESHelper.AES256_KEY_SIZE)
                    return native_key
        key_bytes = get_key_stream(key_source)
    else:
        raise TypeError("key_source must be a path or bytes-like object.")

    if kek is not None:
        # Backward compatibility: allow callers to pass already-unsealed 32-byte keys with kek configured.
        if len(key_bytes) == AESHelper.AES256_KEY_SIZE:
            return key_bytes
        native_key = _try_unwrap_metadata_key(key_bytes, kek)
        if native_key is not None:
            AESHelper.validate_key_length(native_key, AESHelper.AES256_KEY_SIZE)
            return native_key
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
    token = AESHelper.encrypt_aes_gcm(key, pt, aad)
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

    # Decode and decrypt (GCM first, CTR fallback for legacy data)
    raw = base64.b64decode(token_b64)
    if aad is not None:
        # AAD was provided — GCM only, never fall back to CTR (B-3)
        pt = AESHelper.decrypt_aes_gcm(key, raw, aad)
    else:
        try:
            pt = AESHelper.decrypt_aes_gcm(key, raw)
        except (InvalidTag, ValueError):
            source = f" (source: {key_path})" if isinstance(key_path, str) else ""
            warnings.warn(
                f"Legacy AES-CTR-256 encrypted metadata detected{source}. Re-encrypt with AES-GCM-256.",
                DeprecationWarning,
                stacklevel=2,
            )
            pt = AESHelper.decrypt_aes_ctr(key, raw)

    # Try to decode as UTF-8 and parse as JSON if possible
    try:
        text = pt.decode("utf-8")
        try:
            return json.loads(text)
        except Exception:
            return text
    except Exception:
        return pt
