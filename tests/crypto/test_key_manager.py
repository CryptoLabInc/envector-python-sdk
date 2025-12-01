import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyenvector.crypto.key_manager import KeyGenerator


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
        ("IP", [32, 64, 128], "./tmp/test_keys", "NONE", "RMP", "IP0", None, "NONE", False),
        ("IP", [256, 512], "./tmp/test_keys_rmp", "NONE", "RMP", "IP0", None, "NONE", True),
        ("IP", [32], "./tmp/test_keys_aes", "AES", "RMP", "IP0", "./temp/keys/aes.kek", "AES_KEK", True),
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
):
    # Mock dependencies
    mock_key_generator = MagicMock()
    mock_is_empty_dir = MagicMock(return_value=True)

    with patch("pyenvector.crypto.key_manager.evi.MultiKeyGenerator", return_value=mock_key_generator):
        with patch("pyenvector.crypto.key_manager.is_empty_dir", mock_is_empty_dir):
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

            # Verify metadata file
            metadata_path = Path(keygen._key_param.key_dir) / "metadata.json"
            assert metadata_path.exists()

            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            assert metadata["preset"] == expected_preset
            assert metadata["eval_mode"] == eval_mode
            assert metadata["seal_mode"] == expected_seal_mode
            assert metadata["dim_list"] == dim_list
            assert metadata["metadata_encryption"] == keygen._key_param.metadata_encryption

            # Cleanup
            metadata_path.unlink()
            # Remove MetadataKey.bin if it exists (created when metadata_encryption is enabled)
            metadata_enc_key_path = Path(keygen._key_param.metadata_enc_key_path)
            if metadata_enc_key_path.exists():
                metadata_enc_key_path.unlink()
            Path(key_path).rmdir()
