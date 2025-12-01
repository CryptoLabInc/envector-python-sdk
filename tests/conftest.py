import os
import shutil

import pytest

from pyenvector.crypto.key_manager import KeyGenerator


@pytest.fixture(scope="session", autouse=True)
def setup_and_cleanup_keys():
    # Clean up key directories before key generation
    shutil.rmtree("./temp/", ignore_errors=True)
    os.makedirs("./temp/keys/none", exist_ok=True)
    os.makedirs("./temp/keys/aes", exist_ok=True)

    keygen = KeyGenerator(key_path="./temp/keys/none", seal_mode=None)
    keygen.generate_keys()
    kek = os.urandom(32)
    with open("./temp/keys/aes.kek", "wb") as f:
        f.write(kek)
    keygen = KeyGenerator(key_path="./temp/keys/aes", seal_mode="aes", seal_kek_path="./temp/keys/aes.kek")
    keygen.generate_keys()
    yield
    shutil.rmtree("./temp/", ignore_errors=True)
