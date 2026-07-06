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


def main(args):
    # Key Path
    key_path = "./keys"
    key_id = args.key_id
    key_dir = f"{key_path}/{key_id}"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir, eval_mode=args.eval_mode, preset=args.preset)
        keygen.generate_keys()

    # Connect to endpoint of enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    ev.init(address=ENVECTOR_ADDRESS, key_path=key_path, eval_mode=args.eval_mode, preset=args.preset, auto_key_setup=False)
    if ev.is_connected():
        print("Connected to Indexer.")
    else:
        print("Failed to connect to Indexer.")
        return

    # # Register eval key to enVector
    if key_id in ev.get_key_list():
        print("Skipping: Key is alread registered.")
        return
    print("Registering evaluation key...")
    ev.register_key(key_id)
    print("Evaluation key registered successfully.")
    print("Unload Key...")
    ev.unload_key(key_id)
    print("Key Unloaded.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector API Example")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID")
    parser.add_argument("--eval-mode", type=str, choices=["mm", "mms", "mm32", "mms32"], default="mm32", help="Evaluation mode")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    main(args)
