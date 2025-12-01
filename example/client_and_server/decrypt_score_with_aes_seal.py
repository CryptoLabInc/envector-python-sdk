"""
pyenvector High-Level API End-to-End Example

This example demonstrates the following steps using the high-level pyenvector API:
- Initialize the pyenvector environment
- Create an index
- Insert random vector data
- Search vectors
- Clean up index and key

How to run:
    python ./example/e2e.py
"""

import argparse

import numpy as np

import pyenvector as ev


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
    # Initialize pyenvector

    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    DIM = args.dim

    ev.init(
        address=ENVECTOR_ADDRESS,
        key_path="./keys",
        key_id="test-key-seal",
        seal_mode="aes",
        seal_kek_path="./aes.kek",
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

    # Search - PC
    search_index = ev.Index(index_name)
    query = [vectors[0]]
    score_ctxt = search_index.scoring(query)[0]
    dec_score = search_index.decrypt_score(score_ctxt, sec_key_path="./keys/test-key-seal/SecKey_sealed.bin")
    output_metadata = search_index.get_topk_metadata_results(dec_score, top_k=2, output_fields=["metadata"])
    print("\nTest PC Search")
    print(output_metadata)
    assert abs(output_metadata[0]["score"] - 1) < 0.001, "Search score should be close to 1"

    ev.reset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="pyenvector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    args = parser.parse_args()
    main(args)
