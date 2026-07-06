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

    ev.init(address=ENVECTOR_ADDRESS, key_path="./keys", key_id=args.key_id, eval_mode=args.eval_mode, preset=args.preset)

    print("enVector initialized.")

    # Create index
    index_name = "basic_load_idx"
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
    print(f"Inserted {num_data} vectors.")

    index.unload()
    print(f"Index: {index_name} unloaded.")

    search_index = index

    result = search_index.indexer.get_index_summary(index_name=index_name)

    print("\n")
    print(result)
    print("\n")

    index.load()
    print(f"Index: {index_name} loaded.")

    search_index = index

    result = search_index.indexer.get_index_summary(index_name=index_name)

    print("\n")
    print(result)
    print("\n")

    # Search - PC
    query = [vectors[0]]
    output_metadata = search_index.search(query, top_k=2, output_fields=["metadata"])
    print("\nTest PC Search")
    print(output_metadata)
    assert abs(output_metadata[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

    if not args.eval_mode.startswith("mm"):
        search_index.index_config.query_encryption = "cipher"
        # Search - CC
        output_metadata = search_index.search(query, top_k=2, output_fields=["metadata"])
        print("\nTest CC Search")
        print(output_metadata)
        assert abs(output_metadata[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

    ev.drop_index(index_name)
    ev.unload_key(args.key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID")
    parser.add_argument("--eval-mode", "--eval_mode", dest="eval_mode", type=str, default="mm32", choices=["mm", "mms", "mm32", "mms32"], help="Evaluation mode")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    main(args)
