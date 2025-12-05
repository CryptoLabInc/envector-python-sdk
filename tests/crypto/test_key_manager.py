import shutil
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
