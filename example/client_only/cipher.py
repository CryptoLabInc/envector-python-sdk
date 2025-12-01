import argparse
import os

import numpy as np

from pyenvector.crypto import Cipher, KeyGenerator

PRESET = "ip"  # Preset for the context
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


def main(args):
    # Key Path
    key_path = "./keys"
    key_id = "test-key-mm" if args.eval_mode.upper() == "MM" else "test-key"
    key_dir = f"{key_path}/{key_id}"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir, eval_mode=args.eval_mode)
        keygen.generate_keys()

    # Generate random vector
    num_data = 10
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]

    # Encrypt vector
    cipher = Cipher(dim=DIM, preset=PRESET, eval_mode=args.eval_mode)

    db_ctxt = [cipher.encrypt(vec, "item", key_dir + "/EncKey.bin") for vec in vectors]
    print("Vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {db_ctxt[0].serialize()[0:100]}")
    print(
        f"Get Decrypted Vector: first 10:\n  {cipher.decrypt(db_ctxt[0], sec_key_path=key_dir + '/SecKey.bin')[0:10]}"
    )

    bulk_db_ctxt = cipher.encrypt_multiple(vectors, "item", key_dir + "/EncKey.bin")
    print("Bulk vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {bulk_db_ctxt.serialize()[0:100]}")
    print(
        f"Get Decrypted Vector: first 10:\n  {cipher.decrypt(bulk_db_ctxt, sec_key_path=key_dir + '/SecKey.bin')[0:10]}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Encryption/Decryption Example")
    parser.add_argument("--eval_mode", type=str, default="RMP", help="Evaluation mode (RMP or MM)")
    args = parser.parse_args()
    main(args)
