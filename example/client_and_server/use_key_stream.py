"""
enVector High-Level API End-to-End Example

This example demonstrates the following steps using the high-level enVector API:
- Initialize the enVector environment
- Create an index
- Insert random vector data
- Search vectors
- Clean up index and key

How to run:
    python ./example/e2e.py
"""

import argparse
import os

import numpy as np

import pyenvector as ev
from pyenvector.crypto import KeyGenerator
from pyenvector.utils.utils import get_key_stream

PRESET = "IP"  # Preset for the context
KEYPATH = "./keys"
KEYID = "test-key"


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
    # Check Key
    key_dir = f"{KEYPATH}/{KEYID}"

    # Skip key generation if keys already exist
    if os.path.exists(key_dir) and os.listdir(key_dir):
        print(f"Keys already exist in {key_dir}. Skipping key generation.")
    else:
        # Generate keys
        keygen = KeyGenerator(key_dir)
        keygen.generate_keys()
    # Initialize enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    DIM = args.dim

    enc_key = get_key_stream(key_dir + "/EncKey.json")
    eval_key = get_key_stream(key_dir + "/EvalKey.json")
    sec_key = get_key_stream(key_dir + "/SecKey.json")
    metadata_key = get_key_stream(key_dir + "/MetadataKey.json")
    ev.init(
        address=ENVECTOR_ADDRESS,
        key_id=KEYID,
        enc_key=enc_key,
        eval_key=eval_key,
        sec_key=sec_key,
        metadata_key=metadata_key,
    )

    print("enVector initialized.")

    # Create index
    index_name = "test_index"
    # Create index and send to server
    index = ev.create_index(index_name, DIM)
    print(f"Index: {index_name} created.")
    # Generate random vector
    num_data = 10
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]

    # Insert Data
    index.insert(vectors, metadata=db_metadata)
    rng = np.random.default_rng(seed + num_data)
    target_idx = int(rng.integers(0, num_data))
    query = [vectors[target_idx]]

    search_index = ev.Index(index_name)
    output_metadata = search_index.search(query, top_k=2, output_fields=["metadata"])
    print(output_metadata)
    assert abs(output_metadata[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

    ev.reset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    args = parser.parse_args()
    main(args)
