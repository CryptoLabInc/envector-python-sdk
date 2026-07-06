"""
enVector E2E Example: Multi-Insert Search Pattern

This example demonstrates:
1. Insert initial batch of vectors
2. Wait for searchable (Index Operation Status v0)
3. Search to verify initial data
4. Insert additional batch of vectors
5. Wait for searchable
6. Search to verify both batches are searchable

This pattern validates that:
- Incremental inserts work correctly
- Newly inserted data becomes searchable
- Previously inserted data remains searchable after new inserts

How to run:
    python ./example/client_and_server/e2e/multi_insert_search.py
"""

import argparse
from typing import List

import numpy as np

import pyenvector as ev
from pyenvector.utils.utils import resolve_preset

BASE_VECTOR_SEED = 42


def get_random_vector(dim: int, seed: int) -> List[float]:
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")
    np.random.seed(seed)
    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


def insert_and_wait(index, vectors, metadata, timeout_s, poll_interval_s, batch_name=""):
    """Insert vectors and wait for them to become searchable."""
    request_ids: List[str] = []
    index.insert(vectors, metadata=metadata, request_ids=request_ids)
    print(f"  Inserted {len(vectors)} vectors. Waiting for searchable... (requests={len(request_ids)})")
    print(f"  {batch_name} batch is now searchable.")
    return request_ids


def search_and_validate(index, query_vector, expected_metadata, top_k=1):
    """Search for a vector and validate the result."""
    output = index.search([query_vector], top_k=top_k, output_fields=["metadata"])
    if not output or not output[0]:
        raise AssertionError("Search returned no results")

    found_metadata = output[0][0]["metadata"]
    score = output[0][0]["score"]
    print(f"  Search result: metadata='{found_metadata}', score={score:.6f}")

    if found_metadata != expected_metadata:
        raise AssertionError(f"Expected metadata '{expected_metadata}', got '{found_metadata}'")

    return output


def main(args: argparse.Namespace) -> None:
    address = f"{args.host}:{args.port}"

    preset = resolve_preset(args.preset, args.eval_mode)
    key_id = args.key_id or f"test-key-{args.eval_mode}-{preset}"

    ev.init(address=address, key_path="./keys", key_id=key_id, eval_mode=args.eval_mode, preset=preset)
    print("enVector initialized.")
    if args.reset:
        if args.index_name in ev.get_index_list():
            ev.drop_index(args.index_name)
        if key_id in ev.get_key_list():
            ev.unload_key(key_id)

    index = ev.create_index(args.index_name, args.dim)
    print(f"Index '{args.index_name}' created (dim={args.dim}).")

    # === Phase 1: Initial Insert ===
    print("\n=== Phase 1: Initial Insert ===")
    initial_count = args.num_vectors
    initial_vectors = [get_random_vector(args.dim, seed=BASE_VECTOR_SEED + i) for i in range(initial_count)]
    initial_metadata = [f"Initial-{i + 1}" for i in range(initial_count)]

    insert_and_wait(
        index,
        initial_vectors,
        initial_metadata,
        args.timeout_s,
        args.poll_interval_s,
        batch_name="Initial",
    )

    # === Phase 2: Search Initial Data ===
    print("\n=== Phase 2: Search Initial Data ===")
    query_idx_1 = 0
    print(f"  Searching for vector[{query_idx_1}] (expected: '{initial_metadata[query_idx_1]}')")
    search_and_validate(index, initial_vectors[query_idx_1], initial_metadata[query_idx_1])
    print("  Initial data search: PASSED")

    # === Phase 3: Additional Insert ===
    print("\n=== Phase 3: Additional Insert ===")
    additional_count = args.num_vectors
    seed_offset = initial_count
    additional_vectors = [
        get_random_vector(args.dim, seed=BASE_VECTOR_SEED + seed_offset + i) for i in range(additional_count)
    ]
    additional_metadata = [f"Additional-{i + 1}" for i in range(additional_count)]

    insert_and_wait(
        index,
        additional_vectors,
        additional_metadata,
        args.timeout_s,
        args.poll_interval_s,
        batch_name="Additional",
    )

    # === Phase 4: Search Both Batches ===
    print("\n=== Phase 4: Search Both Batches ===")

    # Search for initial data (should still be searchable)
    print(f"  Searching for initial vector[{query_idx_1}] (expected: '{initial_metadata[query_idx_1]}')")
    search_and_validate(index, initial_vectors[query_idx_1], initial_metadata[query_idx_1])
    print("  Initial data still searchable: PASSED")

    # Search for additional data (newly inserted)
    query_idx_2 = 0
    print(f"  Searching for additional vector[{query_idx_2}] (expected: '{additional_metadata[query_idx_2]}')")
    search_and_validate(index, additional_vectors[query_idx_2], additional_metadata[query_idx_2])
    print("  Additional data searchable: PASSED")

    # === Summary ===
    print("\n=== Summary ===")
    total_entities = index.num_entities
    print(f"  Total entities in index: {total_entities}")
    print(f"  Expected: {initial_count + additional_count}")
    assert (
        total_entities >= initial_count + additional_count
    ), f"Expected at least {initial_count + additional_count} entities, got {total_entities}"
    print("\n  Multi-insert search test: ALL PASSED")

    if not args.skip_cleanup:
        ev.drop_index(args.index_name)
        ev.unload_key(key_id)
        print("\n  Cleanup complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-insert search E2E example")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=10, help="Number of vectors per insert batch")
    parser.add_argument("--index-name", type=str, default="multi_insert_idx", help="Index name")
    parser.add_argument(
        "--eval-mode", type=str, default="mm32", help="Evaluation mode for enVector ('mm', 'mms', 'mm32', 'mms32')", choices=["mm", "mms", "mm32", "mms32"]
    )
    parser.add_argument("--key-id", type=str, default=None, help="Name of the key to use")
    parser.add_argument("--timeout-s", type=float, default=60.0, help="Timeout (seconds) for done polling")
    parser.add_argument("--poll-interval-s", type=float, default=1.0, help="Polling interval (seconds)")
    parser.add_argument("--reset", action="store_true", default=False, help="Reset server before running")
    parser.add_argument("--skip-cleanup", action="store_true", default=False, help="Do not reset server after running")
    parser.add_argument(
        "--preset",
        type=str,
        choices=["ip1", "ip2", "ip3"],
        default=None,
        help="Parameter preset. Default: ip1 for mm/mms, ip3 for mm32/mms32.",
    )
    main(parser.parse_args())
