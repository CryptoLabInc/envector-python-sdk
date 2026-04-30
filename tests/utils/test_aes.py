"""Tests for AES-GCM / AES-CTR encryption utilities (GAP-001)."""

import base64
import secrets
import warnings

import pytest
from cryptography.exceptions import InvalidTag

from pyenvector.utils.aes import (
    AESHelper,
    decrypt_metadata,
    encrypt_metadata,
    seal_metadata_enc_key,
    unseal_metadata_enc_key,
)

# ---------------------------------------------------------------------------
# AES-GCM round-trip
# ---------------------------------------------------------------------------


class TestAesGcm:
    def test_gcm_round_trip(self):
        key = secrets.token_bytes(32)
        pt = b"Hello, enVector!"
        sealed = AESHelper.encrypt_aes_gcm(key, pt)
        assert len(sealed) == AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE + len(pt)
        result = AESHelper.decrypt_aes_gcm(key, sealed)
        assert result == pt

    def test_gcm_with_aad(self):
        key = secrets.token_bytes(32)
        pt = b"payload"
        aad = b"kid:test-key-1"
        sealed = AESHelper.encrypt_aes_gcm(key, pt, aad=aad)
        result = AESHelper.decrypt_aes_gcm(key, sealed, aad=aad)
        assert result == pt

    def test_gcm_wrong_aad_fails(self):
        key = secrets.token_bytes(32)
        pt = b"secret"
        aad = b"correct"
        sealed = AESHelper.encrypt_aes_gcm(key, pt, aad=aad)
        with pytest.raises(InvalidTag):
            AESHelper.decrypt_aes_gcm(key, sealed, aad=b"wrong")

    def test_gcm_tampered_ciphertext_fails(self):
        key = secrets.token_bytes(32)
        pt = b"data"
        sealed = bytearray(AESHelper.encrypt_aes_gcm(key, pt))
        sealed[-1] ^= 0xFF  # flip last byte
        with pytest.raises(InvalidTag):
            AESHelper.decrypt_aes_gcm(key, bytes(sealed))

    def test_gcm_too_short_raises(self):
        key = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="too short"):
            AESHelper.decrypt_aes_gcm(key, b"short")


# ---------------------------------------------------------------------------
# AES-CTR legacy round-trip
# ---------------------------------------------------------------------------


class TestAesCtrLegacy:
    def test_ctr_round_trip(self):
        key = secrets.token_bytes(32)
        pt = b"legacy data"
        sealed = AESHelper.encrypt_aes_ctr(key, pt)
        result = AESHelper.decrypt_aes_ctr(key, sealed)
        assert result == pt

    def test_backward_compat_aliases(self):
        key = secrets.token_bytes(32)
        pt = b"alias test"
        sealed = AESHelper.encrypt_with_aes(key, pt)
        result = AESHelper.decrypt_with_aes(key, sealed)
        assert result == pt


# ---------------------------------------------------------------------------
# Seal / unseal metadata encryption key
# ---------------------------------------------------------------------------


class TestSealUnseal:
    def test_seal_unseal_gcm(self):
        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        sealed = seal_metadata_enc_key(metadata_key, kek)
        # GCM sealed: 12 (IV) + 16 (tag) + 32 (key) = 60 bytes
        assert len(sealed) == 60
        unsealed = unseal_metadata_enc_key(sealed, kek)
        assert unsealed == metadata_key

    def test_seal_unseal_gcm_explicit_alg(self):
        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        sealed = seal_metadata_enc_key(metadata_key, kek)
        unsealed = unseal_metadata_enc_key(sealed, kek, seal_alg="AES-GCM-256")
        assert unsealed == metadata_key

    def test_unseal_v0_ctr_compat(self):
        """CTR-sealed bytes from legacy code should still unseal with auto-detect."""
        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        # Simulate legacy CTR sealing
        sealed_ctr = AESHelper.encrypt_aes_ctr(kek, metadata_key)
        assert len(sealed_ctr) == 48  # 16 (IV) + 32 (key)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            unsealed = unseal_metadata_enc_key(sealed_ctr, kek)
            assert unsealed == metadata_key
            assert any("Legacy AES-CTR" in str(warning.message) for warning in w)

    def test_unseal_ctr_explicit_alg(self):
        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        sealed_ctr = AESHelper.encrypt_aes_ctr(kek, metadata_key)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            unsealed = unseal_metadata_enc_key(sealed_ctr, kek, seal_alg="AES-CTR-256")
            assert unsealed == metadata_key
            assert any("Legacy AES-CTR" in str(warning.message) for warning in w)


# ---------------------------------------------------------------------------
# encrypt_metadata / decrypt_metadata
# ---------------------------------------------------------------------------


class TestEncryptDecryptMetadata:
    def test_gcm_round_trip(self):
        key = secrets.token_bytes(32)
        original = {"name": "test", "value": 42}
        token = encrypt_metadata(original, key)
        result = decrypt_metadata(token, key)
        assert result == original

    def test_gcm_with_aad(self):
        key = secrets.token_bytes(32)
        original = "hello"
        aad = b"context"
        token = encrypt_metadata(original, key, aad=aad)
        result = decrypt_metadata(token, key, aad=aad)
        assert result == original

    def test_decrypt_ctr_fallback(self):
        """Legacy CTR-encrypted metadata should decrypt via auto-detect fallback."""
        key = secrets.token_bytes(32)
        pt = b'{"legacy":true}'
        # Simulate legacy CTR encryption
        sealed_ctr = AESHelper.encrypt_aes_ctr(key, pt)
        token_b64 = base64.b64encode(sealed_ctr).decode("ascii")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = decrypt_metadata(token_b64, key)
            assert result == {"legacy": True}
            assert any("Legacy AES-CTR" in str(warning.message) for warning in w)

    def test_decrypt_with_aad_does_not_fall_back_to_ctr(self):
        """When aad is provided, GCM failure must propagate -- no CTR fallback (B-3)."""
        key = secrets.token_bytes(32)
        pt = b'{"data":"value"}'
        # Encrypt with CTR (no AAD support)
        sealed_ctr = AESHelper.encrypt_aes_ctr(key, pt)
        token_b64 = base64.b64encode(sealed_ctr).decode("ascii")
        # Decrypting with aad should fail (GCM only), not silently fall back
        with pytest.raises(Exception):
            decrypt_metadata(token_b64, key, aad=b"some-aad")


# ---------------------------------------------------------------------------
# seal_metadata_enc_key always returns bytes (B-1)
# ---------------------------------------------------------------------------


class TestSealMetadataEncKeyReturn:
    def test_seal_returns_bytes_with_output_path(self, tmp_path):
        """seal_metadata_enc_key must return sealed bytes even when output_path is set (B-1)."""
        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        out_file = str(tmp_path / "sealed.bin")
        result = seal_metadata_enc_key(metadata_key, kek, output_path=out_file)
        assert isinstance(result, bytes)
        assert len(result) == 60
        # File should also exist
        with open(out_file, "rb") as f:
            assert f.read() == result


# ---------------------------------------------------------------------------
# _load_wrapped_metadata_key v2 path (S-5)
# ---------------------------------------------------------------------------


class TestLoadWrappedMetadataKeyV2:
    def test_load_wrapped_metadata_key_v2(self):
        """_load_wrapped_metadata_key should extract iv+tag+edk from v2 envelope."""
        import json

        from pyenvector.utils.utils import _load_wrapped_metadata_key

        kek = secrets.token_bytes(32)
        metadata_key = secrets.token_bytes(32)
        sealed = seal_metadata_enc_key(metadata_key, kek)

        # Split sealed bytes: IV(12) + tag(16) + ciphertext
        iv = sealed[: AESHelper.GCM_IV_SIZE]
        tag = sealed[AESHelper.GCM_IV_SIZE : AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE]
        edk = sealed[AESHelper.GCM_IV_SIZE + AESHelper.GCM_TAG_SIZE :]

        # Build a v2 envelope (base64url no padding)
        envelope = {
            "format": "sealed-key-v2",
            "version": 2,
            "kid": "test",
            "aad_hash": "",
            "provider_meta": {},
            "entries": [
                {
                    "name": "meta_aes",
                    "usage": "metadata",
                    "alg": "AES-GCM-256",
                    "edk": base64.urlsafe_b64encode(edk).rstrip(b"=").decode("ascii"),
                    "iv": base64.urlsafe_b64encode(iv).rstrip(b"=").decode("ascii"),
                    "tag": base64.urlsafe_b64encode(tag).rstrip(b"=").decode("ascii"),
                }
            ],
        }
        raw_bytes = json.dumps(envelope).encode("utf-8")
        result = _load_wrapped_metadata_key(raw_bytes)
        # Should reassemble to original sealed bytes
        assert result == sealed
        # Verify unseal works
        from pyenvector.utils.aes import unseal_metadata_enc_key

        recovered = unseal_metadata_enc_key(result, kek)
        assert recovered == metadata_key

    def test_load_wrapped_metadata_key_unknown_format_raises(self):
        """_load_wrapped_metadata_key should fail-closed on unknown format."""
        import json

        from pyenvector.utils.utils import _load_wrapped_metadata_key

        envelope = {"format": "sealed-key-v99", "entries": []}
        raw_bytes = json.dumps(envelope).encode("utf-8")
        with pytest.raises(ValueError, match="Unknown sealed-key format"):
            _load_wrapped_metadata_key(raw_bytes)
