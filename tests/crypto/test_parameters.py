import pytest

from pyenvector.crypto.parameter import ContextParameter, IndexParameter, KeyParameter


@pytest.mark.parametrize(
    "preset, dim, eval_mode, device_type, expected_preset_name, expected_search_type",
    [
        ("IP", 32, "RMP", "CPU", "IP0", "IP"),
        ("IP0", 64, "RMP", "CPU", "IP0", "IP"),
        ("QF0", 128, "RMP", "GPU", "QF0", "QF"),
        ("IP0", 64, "RMP", "GPU", "IP0", "IP"),
    ],
)
def test_context_parameter_combinations(
    preset, dim, eval_mode, device_type, expected_preset_name, expected_search_type
):
    if preset == "QF0" or device_type == "GPU":
        with pytest.raises(ValueError):
            ContextParameter(preset=preset, dim=dim, eval_mode=eval_mode, device_type=device_type)
    else:
        param = ContextParameter(preset=preset, dim=dim, eval_mode=eval_mode, device_type=device_type)
        assert param.preset_name == expected_preset_name
        assert param.dim == dim
        assert param.eval_mode_name == eval_mode
        assert param.device_type_name == device_type
        assert param.search_type == expected_search_type


@pytest.mark.parametrize(
    "key_path, key_id, seal_mode, seal_kek_path, "
    "expected_seal_mode_name, expected_eval_key_path, "
    "expected_enc_key_path, expect_error",
    [
        ("/keys", "123", "NONE", None, "NONE", "/keys/123/EvalKey.bin", "/keys/123/EncKey.bin", False),
        ("/keys", "456", "NONE", None, "NONE", "/keys/456/EvalKey.bin", "/keys/456/EncKey.bin", False),
        ("/keys", None, "NONE", None, "NONE", "/keys/EvalKey.bin", "/keys/EncKey.bin", False),
        ("/keys", "789", "AES", None, "AES_KEK", "/keys/789/EvalKey.bin", "/keys/789/EncKey.bin", True),
        ("/keys", None, "AES", None, "AES_KEK", "/keys/EvalKey.bin", "/keys/EncKey.bin", True),
        (
            "/keys",
            "789",
            "AES",
            "./temp/keys/aes.kek",
            "AES_KEK",
            "/keys/789/EvalKey.bin",
            "/keys/789/EncKey.bin",
            False,
        ),
        ("/keys", None, "AES", "./temp/keys/aes.kek", "AES_KEK", "/keys/EvalKey.bin", "/keys/EncKey.bin", False),
    ],
)
def test_key_parameter_initialization(
    key_path,
    key_id,
    seal_mode,
    seal_kek_path,
    expected_seal_mode_name,
    expected_eval_key_path,
    expected_enc_key_path,
    expect_error,
):
    if expect_error:
        with pytest.raises(ValueError):
            KeyParameter(key_path=key_path, key_id=key_id, seal_mode=seal_mode, seal_kek_path=seal_kek_path)
    else:
        param = KeyParameter(key_path=key_path, key_id=key_id, seal_mode=seal_mode, seal_kek_path=seal_kek_path)
        assert param.key_path == key_path
        assert param.key_id == key_id
        assert param.seal_mode_name == expected_seal_mode_name
        assert param.eval_key_path == expected_eval_key_path
        assert param.enc_key_path == expected_enc_key_path


def test_key_parameter_with_invalid_seal_mode():
    with pytest.raises(ValueError):
        KeyParameter(key_path="/keys", key_id="123", seal_mode="INVALID")


@pytest.mark.parametrize(
    "index_encryption, query_encryption, index_type, expected_index_type",
    [
        ("cipher", "plain", "FLAT", "FLAT"),
        ("cipher", "cipher", "FLAT", "FLAT"),
    ],
)
def test_index_parameter_initialization_cases(index_encryption, query_encryption, index_type, expected_index_type):
    param = IndexParameter(
        index_encryption=index_encryption, query_encryption=query_encryption, index_params={"index_type": index_type}
    )
    assert param.index_encryption == index_encryption
    assert param.query_encryption == query_encryption
    assert param.index_type == expected_index_type


def test_index_parameter_with_invalid_index_type():
    with pytest.raises(ValueError):
        IndexParameter(index_encryption="cipher", query_encryption="plain", index_params={"index_type": "INVALID"})
    with pytest.raises(ValueError):
        IndexParameter(index_encryption="cipher", query_encryption="cipher", index_params={"index_type": "UNKNOWN"})
