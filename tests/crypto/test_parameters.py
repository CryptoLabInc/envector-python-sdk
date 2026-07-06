import evi
import pytest

from pyenvector.crypto.parameter import ContextParameter, IndexParameter, KeyParameter

_EVI_HAS_IP3 = hasattr(evi.ParameterPreset, "IP3")
_skip_unless_ip3 = pytest.mark.skipif(
    not _EVI_HAS_IP3, reason="evi extension built without IP3 preset"
)


@pytest.mark.parametrize(
    "preset, dim, eval_mode, device_type, expected_preset_name, expected_search_type",
    [
        ("IP1", 32, "MM", "CPU", "IP1", "IP"),
        ("IP1", 64, "MM", "CPU", "IP1", "IP"),
        # Explicit user preset is honored (no silent coercion). IP2 + MM is a
        # valid combo after the u64 demotion (companion to evi PR #698): IP2
        # was demoted from the u32 path to the u64 MM/MMS path.
        ("IP2", 32, "MM", "CPU", "IP2", "IP"),
        ("IP2", 64, "MM", "CPU", "IP2", "IP"),
        # preset=None lets the eval_mode default kick in. After the u64
        # demotion mm32/mms32 default to ip3 (was ip2). These require an evi
        # extension built with IP3.
        pytest.param(None, 32, "MM32", "CPU", "IP3", "IP", marks=_skip_unless_ip3),
        pytest.param(None, 32, "MMS32", "CPU", "IP3", "IP", marks=_skip_unless_ip3),
        (None, 32, "MM", "CPU", "IP1", "IP"),
        pytest.param("IP3", 32, "MM32", "CPU", "IP3", "IP", marks=_skip_unless_ip3),
        pytest.param("IP3", 64, "MMS32", "CPU", "IP3", "IP", marks=_skip_unless_ip3),
        ("QF0", 128, "MM", "GPU", "QF0", "QF"),
        ("IP1", 64, "MM", "GPU", "IP1", "IP"),
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
        ("/keys", "123", "NONE", None, "NONE", "/keys/123/EvalKey.json", "/keys/123/EncKey.json", False),
        ("/keys", "456", "NONE", None, "NONE", "/keys/456/EvalKey.json", "/keys/456/EncKey.json", False),
        ("/keys", None, "NONE", None, "NONE", "/keys/EvalKey.json", "/keys/EncKey.json", False),
        ("/keys", "789", "AES", None, "AES_KEK", "/keys/789/EvalKey.json", "/keys/789/EncKey.json", True),
        ("/keys", None, "AES", None, "AES_KEK", "/keys/EvalKey.json", "/keys/EncKey.json", True),
        (
            "/keys",
            "789",
            "AES",
            "./temp/keys/aes.kek",
            "AES_KEK",
            "/keys/789/EvalKey.json",
            "/keys/789/EncKey.json",
            False,
        ),
        ("/keys", None, "AES", "./temp/keys/aes.kek", "AES_KEK", "/keys/EvalKey.json", "/keys/EncKey.json", False),
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
    tmp_path,
):
    if seal_kek_path is not None:
        kek_path = tmp_path / "aes.kek"
        kek_path.write_bytes(b"\x01" * 32)
        seal_kek_path = str(kek_path)

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


def test_key_parameter_check_key_dir_strict_behavior(tmp_path):
    base_dir = tmp_path / "keys"
    key_id = "test-key"
    key_dir = base_dir / key_id
    key_dir.mkdir(parents=True)
    # create required files
    (key_dir / "EncKey.json").write_bytes(b"enc")
    (key_dir / "EvalKey.json").write_bytes(b"eval")
    (key_dir / "SecKey.json").write_bytes(b"sec")

    param = KeyParameter(key_path=str(base_dir), key_id=key_id, seal_mode="NONE")
    assert param.check_key_dir(strict=True) is True

    # remove EvalKey to trigger strict failure
    (key_dir / "EvalKey.json").unlink()
    with pytest.raises(ValueError):
        param.check_key_dir(strict=True)
    assert param.check_key_dir(strict=False) is False


def test_key_parameter_check_key_dir_missing_optional(tmp_path):
    base_dir = tmp_path / "keys"
    key_id = "partial-key"
    key_dir = base_dir / key_id
    key_dir.mkdir(parents=True)
    (key_dir / "EncKey.json").write_bytes(b"enc")
    (key_dir / "EvalKey.json").write_bytes(b"eval")
    # SecKey.json is optional (fully-managed mode has no local SK)

    param = KeyParameter(key_path=str(base_dir), key_id=key_id, seal_mode="NONE")
    assert param.check_key_dir(strict=True) is True
    assert param.check_key_dir(strict=False) is True
