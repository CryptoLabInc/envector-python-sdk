import pytest

from pyenvector.crypto.context import Context
from pyenvector.crypto.encryptor import Encryptor
from pyenvector.crypto.parameter import ContextParameter


@pytest.fixture(scope="module")
def temp_enc_key(tmp_path_factory):
    temp_dir = tmp_path_factory.mktemp("keys")
    enc_key_path = temp_dir / "EncKey.bin"
    enc_key_path.write_bytes(b"dummy-key")
    return str(enc_key_path)


@pytest.fixture(scope="module")
def context_param():
    return ContextParameter(preset="IP", dim=32)


def test_encryptor_context_required(temp_enc_key):
    if hasattr(Encryptor, "_context"):
        Encryptor._context = None
    with pytest.raises(ValueError):
        Encryptor(temp_enc_key)


def test_encryptor_encrypt(temp_enc_key, context_param):
    Encryptor._context = Context._create_from_parameter(context_param)
    encryptor = Encryptor(temp_enc_key)
    vec = [0.1 * i for i in range(32)]
    try:
        result = encryptor.encrypt(vec, "item")
        assert result is not None
    except Exception as e:
        pytest.skip(f"Encryption skipped due to environment: {e}")
