import base64
import json
import secrets
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyenvector.crypto.key_manager import KeyGenerator, KeyManager
from pyenvector.utils.aes import seal_metadata_enc_key


@pytest.mark.parametrize(
    [
        "preset",
        "dim_list",
        "key_path",
        "seal_mode",
        "eval_mode",
        "expected_preset",
        "seal_kek_path",
        "expected_seal_mode",
        "metadata_encryption",
    ],
    [
        ("IP1", [32, 64, 128], "./tmp/test_keys", "NONE", "MM", "IP1", None, "NONE", False),
        ("IP1", [256, 512], "./tmp/test_keys_rmp", "NONE", "MM", "IP1", None, "NONE", True),
        ("IP1", [32], "./tmp/test_keys_aes", "AES", "MM", "IP1", "./temp/keys/aes.kek", "AES_KEK", True),
    ],
)
def test_generate_keys_creates_metadata(
    preset,
    dim_list,
    key_path,
    seal_mode,
    eval_mode,
    expected_preset,
    seal_kek_path,
    expected_seal_mode,
    metadata_encryption,
    tmp_path,
):
    if seal_kek_path is not None:
        kek_path = tmp_path / "aes.kek"
        kek_path.write_bytes(b"\x01" * 32)
        seal_kek_path = str(kek_path)

    # Mock dependencies
    mock_key_generator = MagicMock()
    mock_is_empty_dir = MagicMock(return_value=True)

    with patch("pyenvector.crypto.key_manager.evi.MultiKeyGenerator", return_value=mock_key_generator):
        with patch("pyenvector.crypto.key_manager.is_empty_dir", mock_is_empty_dir):
            with patch.object(KeyManager, "eval_bin_to_json"):
                # Create KeyGenerator instance
                keygen = KeyGenerator(
                    key_path=key_path,
                    preset=preset,
                    dim_list=dim_list,
                    seal_mode=seal_mode,
                    eval_mode=eval_mode,
                    seal_kek_path=seal_kek_path,
                    metadata_encryption=metadata_encryption,
                )
                # Call generate_keys
                keygen.generate_keys()

                # Validate internal configuration stayed consistent
                assert keygen._context_param.preset_name == expected_preset
                assert keygen._context_param.eval_mode_name == eval_mode
                assert keygen._key_param.seal_mode_name == expected_seal_mode
                assert keygen._dim_list == dim_list

                # Ensure metadata key file aligns with encryption flag
                metadata_key_path = Path(keygen._key_param.metadata_enc_key_path)
                if metadata_encryption:
                    assert metadata_key_path.exists()
                    metadata_key_path.unlink()
                else:
                    assert not metadata_key_path.exists()

                # Cleanup generated directory tree if created
                shutil.rmtree(key_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# metadata envelope compatibility tests
# ---------------------------------------------------------------------------


class TestMetadataKeyEnvelope:
    def setup_method(self):
        self.km = KeyManager()
        self.kek = secrets.token_bytes(32)
        self.metadata_key = secrets.token_bytes(32)

    def test_wrap_gcm_sealed_produces_v0_envelope(self):
        """Pre-sealed metadata key should keep legacy v0 envelope shape."""
        sealed = seal_metadata_enc_key(self.metadata_key, self.kek)
        assert len(sealed) == 60
        wrapped_bytes = self.km.wrap_metadata_key_bytes(sealed, "test-key-1", is_sealed=True)
        payload = json.loads(wrapped_bytes.decode("utf-8"))
        assert "format" not in payload
        assert payload["key_id"] == "test-key-1"
        assert "metadata_blob" in payload

    def test_unwrap_v0_round_trip(self):
        """wrap v0 -> unwrap -> unseal -> original key."""
        from pyenvector.utils.aes import unseal_metadata_enc_key

        sealed = seal_metadata_enc_key(self.metadata_key, self.kek)
        wrapped_bytes = self.km.wrap_metadata_key_bytes(sealed, "test-key-2", is_sealed=True)
        unwrapped = self.km.unwrap_metadata_key_bytes(wrapped_bytes)
        assert unwrapped == sealed
        recovered = unseal_metadata_enc_key(unwrapped, self.kek)
        assert recovered == self.metadata_key

    def test_unwrap_v0_backward_compat(self):
        """v0 envelope (metadata_blob) should still unwrap correctly."""
        plaintext_key = secrets.token_bytes(32)
        # Build a v0 envelope manually
        v0_payload = {
            "metadata_blob": base64.b64encode(plaintext_key).decode("ascii"),
            "key_id": "legacy-key",
            "created_at": "2025-01-01T00:00:00Z",
        }
        v0_bytes = json.dumps(v0_payload).encode("utf-8")
        unwrapped = self.km.unwrap_metadata_key_bytes(v0_bytes)
        assert unwrapped == plaintext_key

    def test_wrap_plaintext_key_uses_provider_envelope(self):
        """32-byte plaintext key should use evi provider envelope by default."""
        wrapped_bytes = self.km.wrap_metadata_key_bytes(self.metadata_key, "test-key-3")
        payload = json.loads(wrapped_bytes.decode("utf-8"))
        assert isinstance(payload.get("entries"), list)
        assert payload["entries"]
        unwrapped = self.km.unwrap_metadata_key_bytes(wrapped_bytes)
        assert unwrapped == self.metadata_key

    def test_unwrap_unknown_format_raises(self):
        """Unknown format value should fail-closed (spec Section 4.2)."""
        payload = json.dumps({"format": "sealed-key-v99", "entries": []}).encode()
        with pytest.raises(ValueError, match="Unknown sealed-key format"):
            self.km.unwrap_metadata_key_bytes(payload)
