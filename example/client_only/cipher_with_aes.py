import argparse
import os

import numpy as np

from pyenvector.crypto import Cipher, KeyGenerator
from pyenvector.utils import utils

DIM = 512  # Dimension for the context


def get_random_vector(dim, seed=None):
    if seed is not None:
        np.random.seed(seed)

    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec = vec / norm  # L2 norm
    return vec


def _run_example(eval_mode: str, key_id: str, preset: str):
    # Key Path
    key_path = "./keys"
    seal_mode = "aes"
    key_dir = f"{key_path}/{key_id}-{seal_mode}"
    seal_kek_path = "./aes.kek"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir, seal_mode=seal_mode, seal_kek_path=seal_kek_path, eval_mode=eval_mode, preset=preset)
        keygen.generate_keys()

    # Generate random vector
    num_data = 10
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]

    # Encrypt vector
    enc_key_path = key_dir + "/EncKey.json"
    sec_key_path = key_dir + "/SecKey.json"
    cipher = Cipher(
        dim=DIM,
        preset=preset,
        eval_mode=eval_mode,
        seal_mode=seal_mode,
        seal_kek_path=seal_kek_path,
        enc_key_path=enc_key_path,
        sec_key_path=sec_key_path,
    )
    sec_key_stream = utils.get_key_stream(sec_key_path)

    single_ctxt = cipher.encrypt_multiple([vectors[0]], "item")
    print("Vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {single_ctxt.serialize()[0:100]}")
    decrypted = cipher.decryptor.decrypt(single_ctxt.data[0], sec_key=sec_key_stream)
    print(f"Get Decrypted Vector: first 10:\n  {decrypted[0:10]}")

    bulk_db_ctxt = cipher.encrypt_multiple(vectors, "item")
    print("Bulk vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")

    print(f"Get Serialized CipherText: first 100 bytes:\n  {bulk_db_ctxt.serialize()[0:100]}")
    bulk_decrypted = cipher.decryptor.decrypt(bulk_db_ctxt.data[0], sec_key=sec_key_stream)
    print(f"Get Decrypted Vector: first 10:\n  {bulk_decrypted[0:10]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Encryption/Decryption Example")
    parser.add_argument("--eval_mode", "--eval-mode", dest="eval_mode", type=str, choices=["mm", "mms", "mm32", "mms32"], default="mm32", help="Evaluation mode")
    parser.add_argument("--key-id", type=str, default="test-key-seal-mm32-ip3", help="Key ID")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    _run_example(args.eval_mode, args.key_id, args.preset)
