"""
enVector High-Level API End-to-End Example

Scenario:
1. Connect as app-a and create/search an index.
2. Reconnect as app-b and verify index delete is denied by ownership check.
3. Reconnect as app-a and clean up.
"""

import argparse
from pathlib import Path

import numpy as np

import pyenvector as ev
from pyenvector.errors import InternalError


def read_token(path: str) -> str:
    token = Path(path).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError(f"Token file is empty: {path}")
    return token


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
    address = f"{args.host}:{args.port}"
    dim = args.dim

    token_a = args.access_token if args.access_token else read_token(args.access_token_file)
    token_b = read_token(args.other_token_file)

    ev.init(
        address=address,
        access_token=token_a,
        secure=args.secure,
        key_path="./keys",
        key_id=args.key_id,
    )
    print("enVector initialized as app-a.")

    index_name = args.index_name
    index = ev.create_index(index_name, dim)
    print(f"Index created: {index_name}")

    num_data = 10
    seed = 42
    vectors = [get_random_vector(dim, seed=seed + i) for i in range(num_data)]
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]

    index.insert(vectors, metadata=db_metadata)

    search_index = ev.Index(index_name)
    query = [vectors[0]]
    score_ctxt = search_index.scoring(query)[0]
    dec_score = search_index.decrypt_score(score_ctxt, sec_key_path=f"./keys/{args.key_id}/SecKey.json")
    output_metadata = search_index.get_topk_metadata_results(dec_score, top_k=2, output_fields=["metadata"])
    print("\nSearch result")
    print(output_metadata)
    assert abs(output_metadata[0]["score"] - 1) < 0.001, "Search score should be close to 1"

    # Reconnect as app-b and confirm owner check blocks delete.
    ev.init_connect(address=address, access_token=token_b, secure=args.secure)
    try:
        ev.drop_index(index_name)
        raise AssertionError("Expected owner-check failure, but drop_index succeeded")
    except InternalError as exc:
        msg = str(exc)
        if "PermissionDenied" not in msg or "owned by another subject" not in msg:
            raise AssertionError(f"Unexpected error message: {msg}") from exc
        print("\nExpected owner-check error")
        print(msg)

    # Reconnect as app-a and clean up.
    ev.init_connect(address=address, access_token=token_a, secure=args.secure)
    ev.drop_index(index_name)
    try:
        ev.delete_key(args.key_id)
    except Exception as exc:
        print(f"delete_key skipped: {exc}")

    print("\nDone.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector ownership check example")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--index-name", type=str, default="test_index", help="Index name")
    parser.add_argument("--key-id", type=str, default="test-key", help="Key ID")
    parser.add_argument("--access-token", type=str, default=None, help="app-a token string (optional)")
    parser.add_argument("--access-token-file", type=str, default="app-a.id_token", help="app-a token file")
    parser.add_argument("--other-token-file", type=str, default="app-b.id_token", help="app-b token file")
    parser.add_argument("--secure", action="store_true", help="Use a secure (TLS) connection")
    args = parser.parse_args()
    main(args)
