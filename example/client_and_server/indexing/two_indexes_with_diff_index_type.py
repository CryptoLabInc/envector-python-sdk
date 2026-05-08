"""
enVector Example

Two indexes with different index types (FLAT and IVF) are created, and searches are performed on both indexes.
"""

import argparse

import numpy as np

import pyenvector as ev


def main(args):
    # Initialize enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    DIM = args.dim
    NUM_DATA = args.num_vectors
    INDEX_NAME = args.index_name

    if args.reset:
        ev.init_connect(address=ENVECTOR_ADDRESS)
        ev.reset()

    ev.init(address=ENVECTOR_ADDRESS, key_path="./keys", key_id=args.key_id, eval_mode=args.eval_mode)
    print("enVector initialized.")

    # Generate sample vectors
    seed = 42
    np.random.seed(seed)
    vectors = np.random.rand(NUM_DATA, DIM)
    vectors = vectors / np.linalg.norm(vectors, axis=1, keepdims=True)  # normalize for IP
    metadata = [f"Item {i + 1}" for i in range(NUM_DATA)]

    # Create FLAT index
    flat_index = ev.create_index(f"{INDEX_NAME}_flat", DIM)
    print(f"FLAT Index: {INDEX_NAME}_flat created.")

    flat_index.insert(vectors, metadata=metadata)
    print(f"Inserted {NUM_DATA} vectors into FLAT index.")

    # Prepare a query vector
    rng = np.random.default_rng(seed + NUM_DATA)
    target_idx = int(rng.integers(0, NUM_DATA))
    query = [vectors[target_idx]]
    print(f"Target index for validation: {target_idx}, metadata: {metadata[target_idx]}")

    # Search flat index
    print("Running FLAT search...")
    output_metadata = flat_index.search(query, top_k=args.topk, output_fields=["metadata"])
    print(f"Result of FLAT Search: {output_metadata}")

    # Create IVF index
    index_params = {"index_type": "IVF_FLAT", "nlist": args.nlist, "default_nprobe": 1, "centroids": None}
    ivf_index = ev.create_index(f"{INDEX_NAME}_ivf", DIM, index_params=index_params)
    print(f"\nIVF Index: {INDEX_NAME}_ivf created.")

    ivf_index.insert(vectors, metadata=metadata)
    print(f"Inserted {NUM_DATA} vectors into IVF index.")

    print("\nRunning IVF-FLAT search...")
    search_params = {"nprobe": args.nprobe}
    output_metadata = ivf_index.search(query, top_k=args.topk, output_fields=["metadata"], search_params=search_params)
    print(f"Result of IVF-FLAT Search: {output_metadata}")

    # Validate search result
    assert abs(output_metadata[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

    if target_idx is not None:
        top_result = output_metadata[0][0]
        expected_metadata = metadata[target_idx]
        assert (
            top_result["metadata"] == expected_metadata
        ), f"Expected metadata '{expected_metadata}', got '{top_result['metadata']}'"
        matched_idx = metadata.index(top_result["metadata"])
        assert matched_idx == target_idx, f"Top-1 result index {matched_idx} does not match expected {target_idx}"

    # Cleanup
    ev.reset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=10000, help="Number of vectors to insert")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--eval-mode", type=str, choices=["mm32"], default="mm32", help="Evaluation mode: mm32")
    parser.add_argument("--index-name", type=str, default="test_index", help="Name of the index to create/use")
    parser.add_argument("--key-id", type=str, default="test-key", help="Name of the key to use")
    parser.add_argument("--topk", type=int, default=3, help="k value for top-k")

    parser.add_argument("--nlist", type=int, default=8, help="Number of clusters (nlist) for IVF index")
    parser.add_argument("--nprobe", type=int, default=4, help="Number of probes (nprobe) for IVF index")

    parser.add_argument(
        "--reset", action="store_true", default=False, help="Flag for resetting the server before tests"
    )

    args = parser.parse_args()
    main(args)
