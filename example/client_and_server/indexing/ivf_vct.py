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
from sklearn.cluster import KMeans

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

    if args.reset:
        ev.init_connect(address=ENVECTOR_ADDRESS)
        ev.reset()

    ev.init(
        address=ENVECTOR_ADDRESS,
        key_path="./keys",
        key_id="test-key-ip1",
        eval_mode="mm32",
        preset="ip2",
    )

    print("enVector initialized.")

    # Create index
    index_name = "test_index"

    # Generate random vector
    num_data = 10000
    n_list = args.nlist
    seed = 42
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]
    index_params = {
        "index_type": "IVF_VCT",
        "nlist": n_list,
        "default_nprobe": args.nprobe,
    }

    if args.random_centroid:
        print("Using server-generated random centroids.")
    else:
        if n_list > num_data:
            raise ValueError("nlist must be less than or equal to the number of vectors.")
        kmeans = KMeans(n_clusters=n_list, random_state=seed)
        kmeans.fit(np.stack(vectors))
        index_params["centroids"] = kmeans.cluster_centers_.tolist()
        print(f"Generated {n_list} centroids with KMeans.")

    # Create index and send to server
    index = ev.create_index(index_name, DIM, index_params=index_params)
    print(f"Index: {index_name} created.")

    # Insert Data (capture server-generated request_ids for completion tracking)
    request_ids = []
    index.insert(vectors, metadata=db_metadata, request_ids=request_ids)
    print(
        "Waiting for inserted rows to become searchable (Index Operation Status v0)... "
        f"(requests={len(request_ids)}, timeout={args.insert_timeout_s}s)"
    )
    index.indexer.wait_for_inserts_searchable(
        index_name=index_name,
        request_ids=request_ids,
        timeout_s=args.insert_timeout_s,
        poll_interval_s=args.insert_poll_interval_s,
    )

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
    parser.add_argument("--nlist", type=int, default=8, help="Number of IVF lists (centroids)")
    parser.add_argument("--nprobe", type=int, default=4, help="Number of probes during search")
    parser.add_argument(
        "--insert-timeout-s",
        type=float,
        default=600.0,
        help="Timeout (seconds) to wait for insert operations to become searchable",
    )
    parser.add_argument(
        "--insert-poll-interval-s",
        type=float,
        default=5.0,
        help="Polling interval (seconds) for insert completion status",
    )
    parser.add_argument(
        "--random_centroid",
        action="store_true",
        help="Let the server generate random centroids instead of fitting KMeans locally",
    )
    parser.add_argument(
        "--reset", action="store_true", default=False, help="Flag for resetting the server before tests"
    )
    args = parser.parse_args()
    main(args)
