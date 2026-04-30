"""
enVector High-Level API End-to-End Example (Pre-encrypted Insert)

This example demonstrates the following steps using the high-level enVector API:
- Initialize the enVector environment
- Create an index
- Generate random vectors
- Encrypt vectors in advance on client side
- Insert encrypted vectors
- Search vectors and validate results
- Clean up index and key

How to run:
    python ./example/client_and_server/e2e/e2e_encrypted_insert.py
"""

import argparse

import numpy as np
from sklearn.cluster import KMeans

import pyenvector as ev

BASE_VECTOR_SEED = 42


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
    if args.num_vectors < 1:
        raise ValueError("Number of vectors must be at least 1")
    if args.topk < 1 or args.topk > args.num_vectors:
        raise ValueError("topk must be between 1 and number of vectors")
    if args.type in ("ivf", "vct") and args.nprobe > args.nlist:
        raise ValueError("nprobe must be less than or equal to nlist for ivf/vct index")

    address = f"{args.host}:{args.port}"

    if args.reset:
        ev.init_connect(address=address)
        ev.reset()

    mode_to_preset = {
        "mm": "ip1",
        "mms": "ip1",
        "mm32": "ip2",
        "mms32": "ip2",
    }
    preset = mode_to_preset[args.eval_mode]
    key_id = args.key_id or f"test-key-{args.eval_mode}-{preset}"

    index_name = f"{args.index_name}_{args.eval_mode}"

    ev.init(address=address, key_path="./keys", key_id=key_id, eval_mode=args.eval_mode, preset=preset)
    print("enVector initialized.")
    print(ev.info())

    index_exists = index_name in ev.get_index_list()
    if index_exists:
        index = ev.Index(index_name)
        print(f"Index: {index_name} already exists. Using existing index.")
    else:
        index = None

    print(f"Index Info: {index}")

    existing_count = index.num_entities if index else 0
    vector_seed_offset = existing_count
    metadata_start = existing_count
    print(
        f"Generating vectors with seed offset={vector_seed_offset} (existing entities={existing_count})..."
    )
    vectors = [get_random_vector(args.dim, seed=BASE_VECTOR_SEED + vector_seed_offset + i) for i in range(args.num_vectors)]
    db_metadata = [f"Item {metadata_start + i + 1}" for i in range(args.num_vectors)]

    centroids = None
    centroids_idx = None
    if args.type in ("ivf", "vct") and not index_exists:
        print(f"Generating {args.type.upper()} centroids with KMeans (nlist={args.nlist})...")
        vector_matrix = np.stack(vectors)
        kmeans = KMeans(n_clusters=args.nlist, random_state=BASE_VECTOR_SEED + vector_seed_offset)
        kmeans.fit(vector_matrix)
        centroids = kmeans.cluster_centers_
        centroids_idx = kmeans.predict(vector_matrix).tolist()
        print("Centroids and centroids_idx generated.")
    elif args.type in ("ivf", "vct"):
        vector_matrix = np.stack(vectors)
        kmeans = KMeans(n_clusters=args.nlist, random_state=BASE_VECTOR_SEED + vector_seed_offset)
        kmeans.fit(vector_matrix)
        centroids_idx = kmeans.predict(vector_matrix).tolist()

    if not index_exists:
        if args.type == "ivf":
            index_params = {
                "index_type": "IVF_FLAT",
                "nlist": args.nlist,
                "default_nprobe": 1,
                "centroids": centroids,
            }
        elif args.type == "vct":
            index_params = {
                "index_type": "IVF_VCT",
                "nlist": args.nlist,
                "default_nprobe": 1,
                "centroids": centroids,
            }
        else:
            index_params = {"index_type": "FLAT"}

        index = ev.create_index(index_name, args.dim, index_params=index_params)
        print(f"Index: {index_name} created.")

    print(f"Encrypting {args.num_vectors} vectors of dimension {args.dim}...")
    if args.type in ("ivf", "vct"):
        encrypted_block = index.cipher.encrypt(vectors, "item", centroids_idx=centroids_idx)
    else:
        encrypted_block = index.cipher.encrypt(vectors, "item")
    print("Vector encryption completed.")

    print(f"Inserting {args.num_vectors} pre-encrypted vectors into '{index_name}'...")
    index.insert(encrypted_block, metadata=db_metadata)

    target_idx = 0
    query = [vectors[target_idx]]
    expected_metadata = db_metadata[target_idx]

    search_index = ev.Index(index_name)
    print("Running search...")
    search_params = {"nprobe": args.nprobe} if args.type in ("ivf", "vct") else {}
    output = search_index.search(query, top_k=args.topk, output_fields=["metadata"], search_params=search_params)

    if args.print_result:
        print("Search results:")
        print(output)

    assert output and output[0], "Expected at least one search hit"

    top_result = output[0][0]
    assert (
        top_result["metadata"] == expected_metadata
    ), f"Expected metadata '{expected_metadata}', got '{top_result['metadata']}'"

    if "score" in top_result:
        print(f"Top-1 score: {top_result['score']}")

    print("Validation passed.")

    if not args.skip_cleanup:
        ev.drop_index(index_name)
        ev.unload_key(key_id)
        print("Cleanup complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector E2E example with pre-encrypted insert")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=10000, help="Number of vectors to insert")
    parser.add_argument(
        "--eval-mode",
        type=str,
        choices=["mm", "mms", "mm32", "mms32"],
        default="mm32",
        help="Evaluation mode: mm (IP1), mms (IP1 + shared-A), mm32 (IP2 u32), mms32 (IP2 u32 + shared-A)",
    )
    parser.add_argument("--index-name", type=str, default="test_index", help="Name of the index to create/use")
    parser.add_argument(
        "--type",
        type=str,
        choices=["flat", "ivf", "vct"],
        default="flat",
        help="Index type: flat, ivf, or vct",
    )
    parser.add_argument("--nlist", type=int, default=8, help="Number of clusters (nlist) for ivf/vct index")
    parser.add_argument("--nprobe", type=int, default=4, help="Number of probes (nprobe) for ivf/vct search")
    parser.add_argument("--key-id", type=str, default=None, help="Name of the key to use")
    parser.add_argument("--topk", type=int, default=3, help="k value for top-k")
    parser.add_argument(
        "--print-result",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Flag for printing the search result",
    )
    parser.add_argument("--skip-cleanup", action="store_true", default=False, help="Skip cleanup after test")
    parser.add_argument("--reset", action="store_true", default=False, help="Reset server before tests")

    main(parser.parse_args())
