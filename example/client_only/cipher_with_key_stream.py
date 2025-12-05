import argparse

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
    key_id = "test-key-mm" if args.eval_mode.upper() == "MM" else "test-key"

    keygen = KeyGenerator(key_id=key_id, eval_mode=args.eval_mode)
    key_dict = keygen.generate_keys_stream()

    enc_key_stream = key_dict["enc_blob"]
    sec_key_stream = key_dict["sec_blob"]

    # Generate random vector
    num_data = 10
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]

    # Encrypt vector
    cipher = Cipher(dim=DIM, preset=PRESET, eval_mode=args.eval_mode, use_key_stream=True)

    db_ctxt = [cipher.encrypt(vec, "item", enc_key=enc_key_stream) for vec in vectors]
    print("Vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {db_ctxt[0].serialize()[0:100]}")
    print(f"Get Decrypted Vector: first 10:\n  {cipher.decrypt(db_ctxt[0], sec_key=sec_key_stream)[0:10]}")

    bulk_db_ctxt = cipher.encrypt_multiple(vectors, "item", enc_key=enc_key_stream)
    print("Bulk vector encrypted successfully.")

    print(f"Get plaintext vector: first 10:\n  {vectors[0][0:10]}")
    print(f"Get Serialized CipherText: first 100 bytes:\n  {bulk_db_ctxt.serialize()[0:100]}")
    print(f"Get Decrypted Vector: first 10:\n  {cipher.decrypt(bulk_db_ctxt, sec_key=sec_key_stream)[0:10]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Encryption/Decryption Example")
    parser.add_argument("--eval_mode", type=str, default="RMP", help="Evaluation mode (RMP or MM)")
    args = parser.parse_args()
    main(args)
