import pytest

from pyenvector.crypto.cipher import Cipher
from pyenvector.utils import utils


def test_cipher_initialization():
    dim = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    for d in dim:
        cipher = Cipher(dim=d, enc_key_path="./temp/keys/none/EncKey.bin", sec_key_path="./temp/keys/none/SecKey.bin")
        vec = [0.001 * i for i in range(d)]
        enc_vec = cipher.encrypt(vec, "item")
        print(f"Encrypted vector for dimension {d}: {enc_vec}")
        dec_vec = cipher.decrypt(enc_vec)

        absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
        assert absolute_error < 1e-3, f"Decryption failed for dimension {d} with absolute error {absolute_error}"


def test_cipher_without_keys():
    cipher = Cipher(dim=512)
    vec = [0.0] * 512
    with pytest.raises(ValueError, match="Encryptor is not initialized. Ensure the encryption key path is set."):
        cipher.encrypt(vec, "item")

    with pytest.raises(ValueError, match="The encrypted vector must be an instance of CipherBlock."):
        cipher.decrypt(vec)

    enc_vec = cipher.encrypt(vec, "item", enc_key_path="./temp/keys/none/EncKey.bin")
    with pytest.raises(ValueError, match="Secret key path is not set. Ensure the secret key file exists."):
        cipher.decrypt(enc_vec)
    dec_vec = cipher.decrypt(enc_vec, sec_key_path="./temp/keys/none/SecKey.bin")

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Decryption failed with absolute error {absolute_error}"


def test_cipher_with_aes_seal_mode():
    dim = 64
    enc_key_path = "./temp/keys/aes/EncKey.bin"
    sec_key_path = "./temp/keys/aes/SecKey_sealed.bin"
    seal_mode = "AES"
    seal_kek_path = "./temp/keys/wrong_aes.kek"
    # Expect FileNotFoundError if KEK file does not exist
    with pytest.raises(FileNotFoundError):
        Cipher(
            dim=dim,
            enc_key_path=enc_key_path,
            sec_key_path=sec_key_path,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
        )


def test_cipher_with_aes_seal_mode_with_mocked_kek(tmp_path):
    dim = 64
    enc_key_path = "./temp/keys/aes/EncKey.bin"
    sec_key_path = "./temp/keys/aes/SecKey_sealed.bin"
    seal_kek_path = "./temp/keys/aes.kek"
    seal_mode = "AES"
    # Create a temporary mock KEK file

    cipher = Cipher(
        dim=dim,
        enc_key_path=enc_key_path,
        sec_key_path=sec_key_path,
        seal_mode=seal_mode,
        seal_kek_path=str(seal_kek_path),
    )
    vec = [0.001 * i for i in range(dim)]
    enc_vec = cipher.encrypt(vec, "item")
    dec_vec = cipher.decrypt(enc_vec)
    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Decryption failed for AES seal_mode with mocked KEK file, error {absolute_error}"


def test_cipher_encrypt_decrypt_with_key_stream():
    dim = 64
    enc_key_stream = utils.get_key_stream("./temp/keys/none/EncKey.bin")
    sec_key_stream = utils.get_key_stream("./temp/keys/none/SecKey.bin")
    cipher = Cipher(dim=dim, use_key_stream=True, enc_key=enc_key_stream, sec_key=sec_key_stream)

    vec = [0.001 * i for i in range(dim)]
    enc_vec = cipher.encrypt(vec, "item")
    dec_vec = cipher.decrypt(enc_vec)

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Key stream decrypt mismatch with error {absolute_error}"


def test_cipher_decrypt_with_runtime_key_stream():
    dim = 64
    enc_key_stream = utils.get_key_stream("./temp/keys/none/EncKey.bin")
    sec_key_stream = utils.get_key_stream("./temp/keys/none/SecKey.bin")
    cipher = Cipher(dim=dim, use_key_stream=True, enc_key=enc_key_stream)

    vec = [0.001 * i for i in range(dim)]
    enc_vec = cipher.encrypt(vec, "item")
    dec_vec = cipher.decrypt(enc_vec, sec_key=sec_key_stream)

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Runtime key stream decrypt mismatch with error {absolute_error}"
