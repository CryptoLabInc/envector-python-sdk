import argparse
import os

import numpy as np

import pyenvector as ev
from pyenvector.crypto import KeyGenerator

DIM = 512  # Dimension for the context


def get_random_vector(dim):
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec = vec / norm  # L2 norm)
    return vec


def main():
    # Key Path
    key_path = "./keys"
    key_id = "test-key"
    key_dir = f"{key_path}/{key_id}"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir)
        keygen.generate_keys()

    # Connect to endpoint of enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    ev.init(address=ENVECTOR_ADDRESS, key_path=key_path, auto_key_setup=False)
    if ev.is_connected():
        print("Connected to Indexer.")
    else:
        print("Failed to connect to Indexer.")
        return

    # # Register eval key to enVector
    print("Registering evaluation key...")
    ev.register_key(key_id)
    print("Evaluation key registered successfully.")
    print("Delete Key...")
    ev.delete_key(key_id)
    print("Key Deleted.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector API Example")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    args = parser.parse_args()
    main()
