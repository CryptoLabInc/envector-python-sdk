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
import multiprocessing
import time

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


def parallel_search(ENVECTOR_ADDRESS, index_name, query, top_k, output_fields):
    # Reinitialize pyenvector context in each worker process to avoid pickling/grpc issues
    try:
        ev.init_connect(address=ENVECTOR_ADDRESS)
        search_idx = ev.Index(index_name)
        res = search_idx.search(query, top_k=top_k, output_fields=output_fields)
        return ("ok", res)
    except Exception as e:
        # Ensure return is picklable even if underlying libs attach locks
        print(f"Error in parallel search: {e}")
        return ("err", f"{type(e).__name__}: {e}")


def main(args):
    if args.repeat < 1:
        raise ValueError("Repeat at least once")
    if args.num_vectors < 1:
        raise ValueError("Number of vectors must be at least 1")
    if args.topk < 1 or args.topk > args.num_vectors:
        raise ValueError("topk must be between 1 and number of vectors")

    if args.reset and args.skip_insert:
        raise ValueError("Cannot reset server when skipping insert")

    # Initialize enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    DIM = args.dim
    NUM_DATA = args.num_vectors

    index_name = args.index_name

    ev.init(
        address=ENVECTOR_ADDRESS,
        key_path=args.key_path,
        key_id=args.key_id,
        eval_mode=args.eval_mode,
        preset=args.preset,
        auto_key_setup=args.auto_key_setup,
    )

    print("enVector initialized.")
    if args.reset:
        if index_name in ev.get_index_list():
            ev.drop_index(index_name)
        if args.key_id in ev.get_key_list():
            ev.unload_key(args.key_id)

    vectors = []
    db_metadata = []
    target_idx = None

    if not args.skip_insert:
        # Create index and send to server
        index = ev.create_index(index_name, DIM)
        print(f"Index: {index_name} created.")

        # Generate random vector
        seed = 42
        vectors = [get_random_vector(DIM, seed=seed + i) for i in range(NUM_DATA)]
        db_metadata = [f"Item {i + 1}" for i in range(NUM_DATA)]

        # Append Data
        vec_idx = 0

        while vec_idx < NUM_DATA:
            batch_size = np.random.randint(100, DIM * 2)

            if vec_idx + batch_size > NUM_DATA:
                batch_size = NUM_DATA - vec_idx

            insert_vectors = [vectors[vec_idx + i] for i in range(batch_size)]
            insert_metadata = db_metadata[vec_idx : vec_idx + batch_size]

            index.insert(insert_vectors, metadata=insert_metadata)
            print(f"Inserted {batch_size} vectors")

            vec_idx += batch_size

        rng = np.random.default_rng(seed + NUM_DATA)
        target_idx = int(rng.integers(0, NUM_DATA))
        query = [vectors[target_idx]]
    else:
        query = [get_random_vector(DIM, seed=NUM_DATA + 1)]

    search_index = ev.Index(index_name)

    search_type = args.search_type
    if not search_type:
        search_type = ["pc"]
    if any(st not in ["pc", "cc"] for st in search_type):
        raise ValueError("search_type must be 'pc', 'cc', or both")

    for st in search_type:
        print(f"\nRunning {st.upper()} search...")
        search_index.index_config.query_encryption = "cipher" if st == "cc" else "plain"

        # Test throuput with multiprocessing
        if args.parallel > 1:
            # Use spawn to avoid inheriting non-picklable state into workers
            try:
                multiprocessing.set_start_method("spawn", force=True)
            except RuntimeError:
                pass

            start_time = time.perf_counter()
            with multiprocessing.Pool(processes=args.parallel) as pool:
                results = pool.starmap(
                    parallel_search,
                    [
                        (ENVECTOR_ADDRESS, index_name, query, args.topk, ["metadata"])  # per-process init
                        for _ in range(args.parallel)
                    ],
                )
            # Validate results and extract first successful payload
            output_metadata = [msg for status, msg in results if status == "ok"]
            if len(output_metadata) == 0:
                raise RuntimeError(f"Parallel search failed: {results[0][1]}")

            if args.print_result:
                print("\nResult of PC Search with parallel processes")
                print(output_metadata)
            end_time = time.perf_counter()
            print(f"{st.upper()} Search time with parallel {args.parallel} processes: {end_time - start_time} seconds")
            print(f"QPS: {args.parallel / (end_time - start_time)}")

            output_metadata = output_metadata[0]  # Use first successful result for validation

        # Test single query latency
        else:
            start_time = time.perf_counter()
            output_metadata = search_index.search(query, top_k=args.topk, output_fields=["metadata"])
            end_time = time.perf_counter()
            print(f"{st.upper()} Single query latency: {end_time - start_time} seconds")
            if args.print_result:
                print(f"\nResult of {st.upper()} Search with single query")
                print(output_metadata)

        # Validate search result
        assert abs(output_metadata[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

        if not args.skip_insert and target_idx is not None:
            top_result = output_metadata[0][0]
            expected_metadata = db_metadata[target_idx]
            assert (
                top_result["metadata"] == expected_metadata
            ), f"Expected metadata '{expected_metadata}', got '{top_result['metadata']}'"
            matched_idx = db_metadata.index(top_result["metadata"])
            assert matched_idx == target_idx, f"Top-1 result index {matched_idx} does not match expected {target_idx}"

    if not args.skip_cleanup:
        ev.drop_index(index_name)
        ev.unload_key(args.key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="pyenVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=1000, help="Number of vectors to insert")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")

    parser.add_argument("--index-name", type=str, default="basic_append_idx", help="Name of the index to create/use")
    parser.add_argument("--key-path", type=str, default="./keys", help="Path to the key directory")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID for encryption/decryption")
    parser.add_argument(
        "--auto-key-setup",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Automatically generate and register keys (default: enabled)",
    )
    parser.add_argument("--topk", type=int, default=3, help="k value for top-k")
    parser.add_argument("--search-type", nargs="*", help="Type of search: pc, cc", default=["pc"])
    parser.add_argument(
        "--eval-mode", type=str, default="mm32", help="Evaluation mode", choices=["mm", "mms", "mm32", "mms32"]
    )
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")

    parser.add_argument("--repeat", type=int, default=1, help="Number of times to repeat the search")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel threads for search")

    parser.add_argument(
        "--skip-insert", action="store_true", default=False, help="Flag for skipping insert for using existing index"
    )
    parser.add_argument(
        "--skip-cleanup", action="store_true", default=False, help="Flag for cleaning up index after test"
    )
    parser.add_argument(
        "--reset", action="store_true", default=False, help="Flag for resetting the server before tests"
    )
    parser.add_argument(
        "--print-result",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Flag for printing the search result",
    )

    args = parser.parse_args()
    main(args)
