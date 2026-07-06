"""
enVector E2E Example: INSERT completion tracking (Index Operation Status v0)

This example demonstrates how a client can:
- Insert data and capture the server-generated request_id (from response header.id)
- Poll GetIndexOperationStatus until done=true
- Validate that the inserted data is searchable

Notes
-----
- v0 supports INSERT only.
- The server generates request_id; clients capture it from the insert response header.id.
- This example uses Indexer.insert_data_bulk directly to demonstrate the out_request_id pattern.
"""

import argparse
from typing import List

import numpy as np

import pyenvector as ev

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


def main(args: argparse.Namespace) -> None:
    address = f"{args.host}:{args.port}"

    ev.init(address=address, key_path="./keys", key_id=args.key_id, eval_mode=args.eval_mode, preset=args.preset)

    if args.reset:
        if args.index_name in ev.get_index_list():
            ev.drop_index(args.index_name)
        if args.key_id in ev.get_key_list():
            ev.unload_key(args.key_id)

    index = ev.create_index(args.index_name, args.dim)

    vectors = [get_random_vector(args.dim, seed=BASE_VECTOR_SEED + i) for i in range(args.num_vectors)]
    metadata = [f"Item {i + 1}" for i in range(args.num_vectors)]

    if index.cipher is None:
        raise RuntimeError("Cipher is not initialized. Ensure index encryption is enabled.")

    encrypted = index.cipher.encrypt_multiple(vectors, encode_type="item")
    # Keep metadata encryption behavior consistent with high-level Index.insert().
    # The lower-level Indexer APIs expect metadata to already be encrypted when metadata_encryption is enabled.
    metadata_for_insert = index._encrypt_metadata_list(metadata)
    prepared_metadata = index._prepare_metadata_for_chunk(metadata_for_insert, encrypted.num_item_list)

    # Capture server-generated request_id via out_request_id parameter
    out_request_id: List[str] = []
    item_ids = index.indexer.insert_data_bulk(
        index_name=args.index_name,
        enc_vec=encrypted.data,
        numitems=encrypted.num_item_list,
        metadata=prepared_metadata,
        centroid_idx=0,
        out_request_id=out_request_id,
    )

    assert len(out_request_id) == 1, f"Expected 1 request_id, got {len(out_request_id)}"
    request_id = out_request_id[0]

    status = index.indexer.wait_for_insert_searchable(
        index_name=args.index_name,
        request_id=request_id,
        timeout_s=args.timeout_s,
        poll_interval_s=args.poll_interval_s,
    )

    assert status.done, "Expected done=true after wait_for_insert_searchable"
    assert status.total_row_count > 0, "Expected total_row_count > 0"
    assert status.searchable_row_count == status.total_row_count, "Expected searchable_row_count == total_row_count"
    assert status.total_row_count == len(item_ids), f"Expected total_row_count==len(item_ids) ({len(item_ids)})"

    # Validate search hits the inserted row.
    search_index = ev.Index(args.index_name)
    output = search_index.search([vectors[0]], top_k=1, output_fields=["metadata"])
    assert output and output[0], "Expected at least one search hit"
    assert (
        output[0][0]["metadata"] == metadata[0]
    ), f"Expected metadata '{metadata[0]}', got '{output[0][0]['metadata']}'"

    if not args.skip_cleanup:
        ev.drop_index(args.index_name)
        ev.unload_key(args.key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Index operation status E2E example")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--num-vectors", type=int, default=10, help="Number of vectors to insert")
    parser.add_argument("--index-name", type=str, default="op_status_idx", help="Index name")
    parser.add_argument(
        "--eval-mode",
        type=str,
        default="mm32",
        help="Evaluation mode for enVector ('rmp', 'mm32')",
        choices=["rmp", "mm32"],
    )
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    parser.add_argument("--timeout-s", type=float, default=60.0, help="Timeout (seconds) for done polling")
    parser.add_argument("--poll-interval-s", type=float, default=1.0, help="Polling interval (seconds)")
    parser.add_argument("--reset", action="store_true", default=False, help="Reset server before running")
    parser.add_argument("--skip-cleanup", action="store_true", default=False, help="Do not reset server after running")
    main(parser.parse_args())
