import importlib
import os
import shutil

import pytest


def _should_use_mock_evi() -> bool:
    flag = os.environ.get("PYENVECTOR_USE_MOCK_EVI", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True
    try:
        importlib.import_module("evi")
    except (ImportError, OSError):
        return True
    return False


USE_MOCK_EVI = _should_use_mock_evi()

if USE_MOCK_EVI:
    from tests.mock_evi import install_mock_evi

    install_mock_evi()


def _prepare_test_key_layout() -> None:
    shutil.rmtree("./temp/", ignore_errors=True)
    os.makedirs("./temp/keys/none", exist_ok=True)
    os.makedirs("./temp/keys/aes", exist_ok=True)
    with open("./temp/keys/aes.kek", "wb") as handle:
        handle.write(b"\x01" * 32)
    for key_dir in ("./temp/keys/none", "./temp/keys/aes"):
        for name in ("EncKey.json", "EvalKey.json", "SecKey.json"):
            with open(os.path.join(key_dir, name), "wb") as handle:
                handle.write(b"mock-key")


def pytest_collection_modifyitems(config, items):
    if not USE_MOCK_EVI:
        return

    skip_native = pytest.mark.skip(reason="requires native evi bindings")
    native_only = {
        "tests/crypto/test_cipher.py",
    }
    for item in items:
        item_path = str(getattr(item, "path", getattr(item, "fspath", ""))).replace("\\", "/")
        if any(item_path.endswith(path) for path in native_only):
            item.add_marker(skip_native)


@pytest.fixture(scope="session", autouse=True)
def setup_and_cleanup_keys():
    if USE_MOCK_EVI:
        _prepare_test_key_layout()
        yield
        shutil.rmtree("./temp/", ignore_errors=True)
        return

    from pyenvector.crypto.key_manager import KeyGenerator

    shutil.rmtree("./temp/", ignore_errors=True)
    keygen = KeyGenerator(key_path="./temp/keys/none", seal_mode=None, eval_mode="MM")
    keygen.generate_keys()
    kek = os.urandom(32)
    with open("./temp/keys/aes.kek", "wb") as f:
        f.write(kek)
    keygen = KeyGenerator(
        key_path="./temp/keys/aes",
        seal_mode="aes",
        seal_kek_path="./temp/keys/aes.kek",
        eval_mode="MM",
    )
    keygen.generate_keys()
    yield
    shutil.rmtree("./temp/", ignore_errors=True)
