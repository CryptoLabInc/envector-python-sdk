import argparse
import os

import numpy as np

from pyenvector.crypto import Cipher, KeyGenerator
from pyenvector.utils.utils import get_key_stream

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
    key_dir = f"{key_path}/{key_id}"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir, eval_mode=eval_mode, preset=preset)
        keygen.generate_keys()

    enc_key_stream = get_key_stream(key_dir + "/EncKey.json")
    sec_key_stream = get_key_stream(key_dir + "/SecKey.json")

    # Generate random vector
    num_data = 10
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]

    # Encrypt vector
    cipher = Cipher(
        dim=DIM,
        preset=preset,
        eval_mode=eval_mode,
        use_key_stream=True,
        sec_key=sec_key_stream,
    )

    single_ctxt = cipher.encrypt_multiple([vectors[0]], "item", enc_key=enc_key_stream)
    print("Vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {single_ctxt.serialize()[0:100]}")
    dec_single = cipher.decryptor.decrypt(single_ctxt.data[0], sec_key=sec_key_stream)
    print(f"Get Decrypted Vector: first 10:\n  {dec_single[0:10]}")

    bulk_db_ctxt = cipher.encrypt_multiple(vectors, "item", enc_key=enc_key_stream)
    print("Bulk vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {bulk_db_ctxt.serialize()[0:100]}")
    dec_bulk = cipher.decryptor.decrypt(bulk_db_ctxt.data[0], sec_key=sec_key_stream)
    print(f"Get Decrypted Vector: first 10:\n  {dec_bulk[0:10]}")


def main(args):
    _run_example(args.eval_mode, args.key_id, args.preset)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Encryption/Decryption Example")
    parser.add_argument("--eval_mode", "--eval-mode", dest="eval_mode", type=str, choices=["mm", "mms", "mm32", "mms32"], default="mm32", help="Evaluation mode")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    main(args)
