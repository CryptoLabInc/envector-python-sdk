from unittest.mock import MagicMock

import numpy as np
import pytest

from pyenvector.crypto.cipher import Cipher
from pyenvector.utils import utils


def _skip_if_not_supported(exc: RuntimeError):
    msg = str(exc)
    if "NotSupportedError" in msg or "Encryption is not supported" in msg:
        pytest.skip(f"Encryption not supported in this eval mode: {msg}")
    raise exc


def test_cipher_initialization():
    dim = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    for d in dim:
        cipher = Cipher(
            dim=d,
            enc_key_path="./temp/keys/none/EncKey.json",
            sec_key_path="./temp/keys/none/SecKey.json",
            eval_mode="MM",
        )
        vec = [0.001 * i for i in range(d)]
        try:
            enc_vec = cipher.encrypt(vec, "item")
        except RuntimeError as exc:
            _skip_if_not_supported(exc)
        print(f"Encrypted vector for dimension {d}: {enc_vec}")
        dec_vec = cipher.decrypt(enc_vec)

        absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
        assert absolute_error < 1e-3, f"Decryption failed for dimension {d} with absolute error {absolute_error}"


def test_cipher_without_keys():
    cipher = Cipher(dim=512, eval_mode="MM")
    vec = [0.0] * 512
    try:
        with pytest.raises(ValueError, match="Encryptor is not initialized. Ensure the encryption key path is set."):
            cipher.encrypt(vec, "item")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)

    with pytest.raises(ValueError, match="The encrypted vector must be an instance of CipherBlock."):
        cipher.decrypt(vec)

    try:
        enc_vec = cipher.encrypt(vec, "item", enc_key_path="./temp/keys/none/EncKey.json")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    with pytest.raises(ValueError, match="Secret key path is not set. Ensure the secret key file exists."):
        cipher.decrypt(enc_vec)
    dec_vec = cipher.decrypt(enc_vec, sec_key_path="./temp/keys/none/SecKey.json")

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Decryption failed with absolute error {absolute_error}"


def test_cipher_with_aes_seal_mode():
    dim = 64
    enc_key_path = "./temp/keys/aes/EncKey.json"
    sec_key_path = "./temp/keys/aes/SecKey.json"
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
            eval_mode="MM",
        )


def test_cipher_with_aes_seal_mode_with_mocked_kek(tmp_path):
    dim = 64
    enc_key_path = "./temp/keys/aes/EncKey.json"
    sec_key_path = "./temp/keys/aes/SecKey.json"
    seal_kek_path = "./temp/keys/aes.kek"
    seal_mode = "AES"
    # Create a temporary mock KEK file

    cipher = Cipher(
        dim=dim,
        enc_key_path=enc_key_path,
        sec_key_path=sec_key_path,
        seal_mode=seal_mode,
        seal_kek_path=str(seal_kek_path),
        eval_mode="MM",
    )
    vec = [0.001 * i for i in range(dim)]
    try:
        enc_vec = cipher.encrypt(vec, "item")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    dec_vec = cipher.decrypt(enc_vec)
    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Decryption failed for AES seal_mode with mocked KEK file, error {absolute_error}"


def test_cipher_encrypt_decrypt_with_key_stream():
    dim = 64
    enc_key_stream = utils.get_key_stream("./temp/keys/none/EncKey.json")
    sec_key_stream = utils.get_key_stream("./temp/keys/none/SecKey.json")
    cipher = Cipher(dim=dim, use_key_stream=True, enc_key=enc_key_stream, sec_key=sec_key_stream, eval_mode="MM")

    vec = [0.001 * i for i in range(dim)]
    try:
        enc_vec = cipher.encrypt(vec, "item")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    dec_vec = cipher.decrypt(enc_vec)

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Key stream decrypt mismatch with error {absolute_error}"


def test_cipher_decrypt_with_runtime_key_stream():
    dim = 64
    enc_key_stream = utils.get_key_stream("./temp/keys/none/EncKey.json")
    sec_key_stream = utils.get_key_stream("./temp/keys/none/SecKey.json")
    cipher = Cipher(dim=dim, use_key_stream=True, enc_key=enc_key_stream, eval_mode="MM")

    vec = [0.001 * i for i in range(dim)]
    try:
        enc_vec = cipher.encrypt(vec, "item")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    dec_vec = cipher.decrypt(enc_vec, sec_key=sec_key_stream)

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Runtime key stream decrypt mismatch with error {absolute_error}"


def test_cipher_encrypt_defaults_to_item():
    dim = 64
    cipher = Cipher(
        dim=dim,
        enc_key_path="./temp/keys/none/EncKey.json",
        sec_key_path="./temp/keys/none/SecKey.json",
        eval_mode="MM",
    )
    vec = [0.001 * i for i in range(dim)]
    try:
        enc_vec = cipher.encrypt(vec)
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    dec_vec = cipher.decrypt(enc_vec)

    absolute_error = max(abs(o - m) for o, m in zip(vec, dec_vec))
    assert absolute_error < 1e-3, f"Default item encrypt mismatch with error {absolute_error}"


def test_cipher_encrypt_query_compat():
    dim = 64
    cipher = Cipher(
        dim=dim,
        enc_key_path="./temp/keys/none/EncKey.json",
        sec_key_path="./temp/keys/none/SecKey.json",
        eval_mode="MM",
    )
    vec = [0.001 * i for i in range(dim)]
    try:
        encrypted_query = cipher.encrypt_query(vec)
        compat_query = cipher.encrypt(vec, encode_type="query")
    except RuntimeError as exc:
        _skip_if_not_supported(exc)
    assert encrypted_query.is_score is False
    assert compat_query.is_score is False


def test_cipher_encrypt_accepts_list_of_lists_format():
    cipher = Cipher(dim=32, eval_mode="MM")
    result_block = MagicMock()
    result_block.enc_type = "multiple"
    cipher.encrypt_multiple = MagicMock(return_value=result_block)

    data = [[0.1 * i for i in range(32)], [0.2 * i for i in range(32)]]
    result = cipher.encrypt(data)

    assert result is result_block
    called_vectors = cipher.encrypt_multiple.call_args.args[0]
    assert called_vectors == data


def test_cipher_encrypt_accepts_2d_ndarray_format():
    cipher = Cipher(dim=32, eval_mode="MM")
    result_block = MagicMock()
    result_block.enc_type = "multiple"
    cipher.encrypt_multiple = MagicMock(return_value=result_block)

    data = np.zeros((2, 32), dtype=np.float32)
    _ = cipher.encrypt(data)

    called_vectors = cipher.encrypt_multiple.call_args.args[0]
    assert len(called_vectors) == 2
    assert isinstance(called_vectors[0], np.ndarray)


def test_cipher_encrypt_accepts_list_of_ndarray_format():
    cipher = Cipher(dim=32, eval_mode="MM")
    result_block = MagicMock()
    result_block.enc_type = "multiple"
    cipher.encrypt_multiple = MagicMock(return_value=result_block)

    data = [np.zeros(32), np.zeros(32)]
    _ = cipher.encrypt(data)

    called_vectors = cipher.encrypt_multiple.call_args.args[0]
    assert len(called_vectors) == 2
    assert isinstance(called_vectors[0], np.ndarray)


def test_cipher_encrypt_single_vector_list_wrapped_and_marked_single():
    cipher = Cipher(dim=32, eval_mode="MM")
    result_block = MagicMock()
    result_block.enc_type = "multiple"
    cipher.encrypt_multiple = MagicMock(return_value=result_block)

    vec = [0.1] * 32
    result = cipher.encrypt(vec)

    called_vectors = cipher.encrypt_multiple.call_args.args[0]
    assert called_vectors == [vec]
    assert result.enc_type == "single"


def test_cipher_encrypt_query_rejects_batch_input():
    cipher = Cipher(dim=32, eval_mode="MM")

    with pytest.raises(ValueError, match="expects a single vector"):
        cipher.encrypt([[0.1, 0.2, 0.3, 0.4]], encode_type="query")


def test_cipher_encrypt_splits_large_batch_and_returns_cipherblock_list():
    cipher = Cipher(dim=32, eval_mode="MM")
    block1 = MagicMock()
    block2 = MagicMock()
    block3 = MagicMock()
    cipher.encrypt_multiple = MagicMock(side_effect=[block1, block2, block3])

    data = np.random.rand(10, 32).astype(np.float32)
    result = cipher.encrypt(data, split_batch_size=4)

    assert result == [block1, block2, block3]
    assert cipher.encrypt_multiple.call_count == 3
    chunk_sizes = [len(call.args[0]) for call in cipher.encrypt_multiple.call_args_list]
    assert chunk_sizes == [4, 4, 2]


def test_cipher_encrypt_splits_centroids_idx_along_chunks():
    cipher = Cipher(dim=32, eval_mode="MM")
    block1 = MagicMock()
    block2 = MagicMock()
    block3 = MagicMock()
    cipher.encrypt_multiple = MagicMock(side_effect=[block1, block2, block3])

    data = np.random.rand(10, 32).astype(np.float32)
    centroids_idx = list(range(10))
    _ = cipher.encrypt(data, centroids_idx=centroids_idx, split_batch_size=4)

    centroid_chunks = [call.kwargs["centroids_idx"] for call in cipher.encrypt_multiple.call_args_list]
    assert centroid_chunks == [list(range(4)), list(range(4, 8)), list(range(8, 10))]


def test_cipher_encrypt_rejects_invalid_centroids_idx_length_for_batch():
    cipher = Cipher(dim=32, eval_mode="MM")
    data = np.random.rand(5, 32).astype(np.float32)

    with pytest.raises(ValueError, match="centroids_idx length"):
        cipher.encrypt(data, centroids_idx=[0, 1], split_batch_size=4)


def test_normalize_item_encrypt_input_rejects_mixed_type_flat_list():
    cipher = Cipher(dim=32, eval_mode="MM")
    with pytest.raises(ValueError, match="must be numeric"):
        cipher._normalize_item_encrypt_input([0.1, "bad", 0.3])


def test_normalize_item_encrypt_input_rejects_mixed_type_list_of_lists():
    cipher = Cipher(dim=32, eval_mode="MM")
    with pytest.raises(ValueError, match="must be lists"):
        cipher._normalize_item_encrypt_input([[0.1, 0.2, 0.3], "not_a_list"])
