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
    # Initialize enVector

    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    DIM = args.dim

    ev.init(
        address=ENVECTOR_ADDRESS,
        key_path="./keys",
        key_id="test-key",
    )

    print("enVector initialized.")

    # Create index
    index_name = "test_index"

    # Generate random vector
    num_data = 1000
    n_list = 8
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]
    index_params = {"index_type": "IVF_FLAT", "nlist": n_list, "default_nprobe": 1}

    # Create index and send to server
    index = ev.create_index(index_name, DIM, index_params=index_params)
    print(f"Index: {index_name} created.")

    # Insert Data
    index.insert(vectors, metadata=db_metadata)

    # Search - PC
    search_index = ev.Index(index_name)
    query = [vectors[0]]
    result = search_index.search(query, top_k=2, output_fields=["metadata"])[0]
    print("\nTest PC Search")
    print(result)
    assert abs(result[0]["score"] - 1) < 0.001, "Search score should be close to 1"

    ev.reset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    args = parser.parse_args()
    main(args)
