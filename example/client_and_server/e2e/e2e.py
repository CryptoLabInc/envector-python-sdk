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
import multiprocessing
import time

import numpy as np

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


def parallel_search(ENVECTOR_ADDRESS, index_name, query, key_id, eval_mode, top_k, output_fields, search_params):
    # Reinitialize enVector context in each worker process to avoid pickling/grpc issues
    try:
        ev.init(address=ENVECTOR_ADDRESS, key_path="./keys", key_id=key_id, eval_mode=eval_mode, auto_key_setup=False)
        search_idx = ev.Index(index_name)
        res = search_idx.search(query, top_k=top_k, output_fields=output_fields, search_params=search_params)
        return ("ok", res)
    except Exception as e:
        # Ensure return is picklable even if underlying libs attach locks
        print(f"Error in parallel search: {e}")
        return ("err", f"{type(e).__name__}: {e}")


def parallel_insert_worker(ENVECTOR_ADDRESS, index_name, vectors, metadata, key_id, eval_mode):
    # Reinitialize enVector context in each worker process
    try:
        ev.init(address=ENVECTOR_ADDRESS, key_path="./keys", key_id=key_id, eval_mode=eval_mode, auto_key_setup=False)
        insert_idx = ev.Index(index_name)
        req_ids = []
        # Do not block here; let the parent process handle waiting with CLI-configured timeouts.
        insert_idx.insert(vectors, metadata=metadata, request_ids=req_ids, execute_until="flush", load=False)
        return ("ok", (len(vectors), req_ids))
    except Exception as e:
        print(f"Error in parallel insert: {e}")
        return ("err", f"{type(e).__name__}: {e}")


def spawn_pool(processes):
    """Return a spawn-based multiprocessing pool."""
    ctx = multiprocessing.get_context("spawn")
    return ctx.Pool(processes=processes)


def chunk_vector_batches(vectors, metadata, chunk_size):
    """Yield vector/metadata chunks of roughly chunk_size."""
    for start in range(0, len(vectors), chunk_size):
        end = min(start + chunk_size, len(vectors))
        if start >= end:
            continue
        chunk_metadata = metadata[start:end] if metadata else None
        yield vectors[start:end], chunk_metadata


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

    if args.reset:
        ev.init_connect(address=ENVECTOR_ADDRESS)
        ev.reset()

    # Eval mode determines the preset — they are coupled:
    #   mm / mms          -> IP1 (server base-converts to IP0 during makeSearchable)
    #   mm32 / mms32      -> IP2 (u32 storage, no base conversion)
    # Only the eval mode is user-facing; the preset is derived from it.
    mode_to_preset = {
        "mm": "ip1",
        "mms": "ip1",
        "mm32": "ip2",
        "mms32": "ip2",
    }
    preset = mode_to_preset[args.eval_mode]
    key_id = args.key_id or f"test-key-{args.eval_mode}-{preset}"

    index_name = args.index_name
    ev.init(address=ENVECTOR_ADDRESS, key_path="./keys", key_id=key_id, eval_mode=args.eval_mode, preset=preset)
    print("enVector initialized.")
    print(ev.info())

    vectors = []
    db_metadata = []
    target_local_idx = None
    existing_entity_count = 0

    # When running different eval modes against the same stack, each run gets
    # its own index so there is no residual binding from a previous mode's key.
    index_name = f"{index_name}_{args.eval_mode}"

    if not args.skip_insert:
        # 인덱스 타입에 따라 params 설정
        if args.type == "ivf":
            index_params = {"index_type": "IVF_FLAT", "nlist": args.nlist, "default_nprobe": 1}
        elif args.type == "vct":
            index_params = {"index_type": "IVF_VCT", "nlist": args.nlist, "default_nprobe": 1}
        else:
            index_params = {"index_type": "FLAT"}
        if index_name in ev.get_index_list():
            index = ev.Index(index_name)
            print(f"Index: {index_name} already exists. Using existing index.")
        else:
            index = ev.create_index(index_name, DIM, index_params=index_params)
            print(f"Index: {index_name} created.")
        print(f"Index Info: {index}")
        existing_entity_count = index.num_entities or 0

        # Generate random vectors whose seeds continue from the current entity count
        seed_offset = BASE_VECTOR_SEED + existing_entity_count
        vectors = [get_random_vector(DIM, seed=seed_offset + i) for i in range(NUM_DATA)]
        db_metadata = [f"Item {existing_entity_count + i + 1}" for i in range(NUM_DATA)]

        print(f"Inserting {NUM_DATA} vectors of dimension {DIM}...")
        # Insert Data (capture server-generated request_ids for completion tracking)
        request_ids = []
        if args.parallel_insert > 1:
            chunk_size = max(1, (len(vectors) + args.parallel_insert - 1) // args.parallel_insert)
            tasks = [
                (
                    ENVECTOR_ADDRESS,
                    index_name,
                    vector_chunk,
                    metadata_chunk,
                    key_id,
                    args.eval_mode,
                )
                for vector_chunk, metadata_chunk in chunk_vector_batches(vectors, db_metadata, chunk_size)
            ]

            start_time = time.perf_counter()
            with spawn_pool(args.parallel_insert) as pool:
                insert_results = pool.starmap(parallel_insert_worker, tasks)
                pool.close()
                pool.join()
            errors = [payload for status, payload in insert_results if status == "err"]
            if errors:
                raise RuntimeError(f"Parallel insert failed: {errors[0]}")
            ok_payloads = [payload for status, payload in insert_results if status == "ok"]
            total_inserted = sum(count for count, _ in ok_payloads)
            for _, req_ids in ok_payloads:
                request_ids.extend(req_ids)
            end_time = time.perf_counter()
            print(
                f"Inserted {total_inserted} vectors with parallel {args.parallel_insert} processes "
                f"in {end_time - start_time} seconds"
            )
        else:
            start_time = time.perf_counter()
            index.insert(vectors, metadata=db_metadata, request_ids=request_ids, execute_until="flush", load=False)
            end_time = time.perf_counter()
            print(
                f"Inserted {len(vectors)} vectors in {end_time - start_time} seconds"
            )

        start_time = time.perf_counter()
        print(f"Trigger Indexing ...")
        index.indexing(request_ids)
        end_time = time.perf_counter()
        print(f"Indexing trigger completed in {end_time - start_time} seconds")
        start_time = time.perf_counter()
        index.load()
        end_time = time.perf_counter()
        print(f"Loading index completed in {end_time - start_time} seconds")
        rng = np.random.default_rng(seed_offset + NUM_DATA)
        target_local_idx = int(rng.integers(0, NUM_DATA))
        target_global_idx = existing_entity_count + target_local_idx
        query = [vectors[target_local_idx]]

        print(f"Target index for validation: {target_global_idx}, metadata: {db_metadata[target_local_idx]}")

    else:
        index = ev.Index(index_name)
        print(f"Using existing index: {index_name}")

        num_entities = index.num_entities
        if num_entities == 0:
            raise ValueError(f"Index '{index_name}' is empty. Cannot skip insert without existing data.")
        rng = np.random.default_rng(BASE_VECTOR_SEED + num_entities)
        target_global_idx = int(rng.integers(0, num_entities))
        query = [get_random_vector(DIM, seed=BASE_VECTOR_SEED + target_global_idx)]

        print(f"Target index for validation: {target_global_idx}")

    search_index = ev.Index(index_name)

    search_type = args.search_type
    search_params = {"nprobe": args.nprobe} if args.type == "ivf" else {}
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
            start_time = time.perf_counter()
            with spawn_pool(args.parallel) as pool:
                results = pool.starmap(
                    parallel_search,
                    [
                        (
                            ENVECTOR_ADDRESS,
                            index_name,
                            query,
                            key_id,
                            args.eval_mode,
                            args.topk,
                            ["metadata"],
                            search_params,
                        )  # per-process init
                        for _ in range(args.parallel)
                    ],
                )
                pool.close()
                pool.join()
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
            output_metadata = search_index.search(
                query, top_k=args.topk, output_fields=["metadata"], search_params=search_params
            )
            end_time = time.perf_counter()
            print(f"{st.upper()} Single query latency: {end_time - start_time} seconds")
            if args.print_result:
                print(f"\nResult of {st.upper()} Search with single query")
                print(output_metadata)

        # Validate search result
        assert output_metadata and output_metadata[0], "Expected at least one search hit"

        if not args.skip_insert and target_local_idx is not None:
            top_result = output_metadata[0][0]
            expected_metadata = db_metadata[target_local_idx]
            assert (
                top_result["metadata"] == expected_metadata
            ), f"Expected metadata '{expected_metadata}', got '{top_result['metadata']}'"
            matched_idx = db_metadata.index(top_result["metadata"])
            assert (
                matched_idx == target_local_idx
            ), f"Top-1 result index {matched_idx} does not match expected {target_local_idx}"

    if not args.skip_cleanup:
        ev.drop_index(index_name)
        ev.unload_key(key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector Example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=10, help="Number of vectors to insert")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument(
        "--eval-mode",
        type=str,
        choices=["mm", "mms", "mm32", "mms32"],
        default="mm32",
        help="Evaluation mode: mm (IP1), mms (IP1 + shared-A), mm32 (IP2 u32), mms32 (IP2 u32 + shared-A)",
    )
    parser.add_argument("--index-name", type=str, default="test_index", help="Name of the index to create/use")
    parser.add_argument("--key-id", type=str, default=None, help="Name of the key to use (default: test-key-<preset>)")
    parser.add_argument("--topk", type=int, default=3, help="k value for top-k")
    parser.add_argument("--search-type", nargs="*", help="Type of search: pc, cc", default=["pc"])
    parser.add_argument("--repeat", type=int, default=1, help="Number of times to repeat the search")
    parser.add_argument("--parallel", type=int, default=1, help="Number of parallel threads for search")
    parser.add_argument("--parallel-insert", type=int, default=1, help="Number of parallel processes for insert")
    parser.add_argument("--type", type=str, choices=["ivf", "flat", "vct"], default="flat", help="Index type: ivf or flat or vct")
    parser.add_argument("--nlist", type=int, default=8, help="Number of clusters (nlist) for IVF index")
    parser.add_argument("--nprobe", type=int, default=4, help="Number of probes (nprobe) for IVF index")
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
    parser.add_argument(
        "--insert-timeout-s",
        type=float,
        default=30000000.0,
        help="Timeout (seconds) to wait for insert operations to become searchable",
    )
    parser.add_argument(
        "--insert-poll-interval-s",
        type=float,
        default=1.0,
        help="Polling interval (seconds) for insert completion status",
    )

    args = parser.parse_args()
    main(args)
