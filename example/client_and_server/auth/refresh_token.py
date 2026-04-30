"""
enVector High-Level API End-to-End Example (refresh-token auth)

Same scenario as basic_auth.py, but the SDK is initialized with an OIDC
refresh token instead of a pre-issued access token. The SDK exchanges the
refresh token at the IdP's token endpoint and renews the bearer transparently.

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


def build_auth_kwargs(refresh_token: str, args) -> dict:
    kwargs = {
        "refresh_token": refresh_token,
        "client_id": args.client_id,
    }
    if not args.token_endpoint and not args.oidc_issuer:
        raise ValueError("Either --token-endpoint or --oidc-issuer must be provided")
    elif args.token_endpoint:
        kwargs["token_endpoint"] = args.token_endpoint
    elif args.oidc_issuer:
        kwargs["oidc_issuer"] = args.oidc_issuer
    if args.client_secret:
        kwargs["client_secret"] = args.client_secret
    if args.scope:
        kwargs["scope"] = args.scope
    return kwargs


def main(args):
    if not (args.token_endpoint or args.oidc_issuer):
        raise ValueError("Either --token-endpoint or --oidc-issuer must be provided")

    address = f"{args.host}:{args.port}"
    dim = args.dim

    refresh_a = args.refresh_token if args.refresh_token else read_token(args.refresh_token_file)
    refresh_b = read_token(args.other_refresh_token_file)

    auth_a = build_auth_kwargs(refresh_a, args)
    auth_b = build_auth_kwargs(refresh_b, args)

    ev.init(
        address=address,
        secure=args.secure,
        key_path="./keys",
        key_id=args.key_id,
        **auth_a,
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
    ev.init_connect(address=address, secure=args.secure, **auth_b)
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
    ev.init_connect(address=address, secure=args.secure, **auth_a)
    ev.drop_index(index_name)
    try:
        ev.delete_key(args.key_id)
    except Exception as exc:
        print(f"delete_key skipped: {exc}")

    print("\nDone.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector ownership check example (refresh-token auth)")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--index-name", type=str, default="test_index", help="Index name")
    parser.add_argument("--key-id", type=str, default="test-key", help="Key ID")
    parser.add_argument("--refresh-token", type=str, default=None, help="app-a refresh token string (optional)")
    parser.add_argument("--refresh-token-file", type=str, default="app-a.refresh_token", help="app-a refresh token file")
    parser.add_argument(
        "--other-refresh-token-file", type=str, default="app-b.refresh_token", help="app-b refresh token file"
    )
    parser.add_argument("--client-id", type=str, required=True, help="OIDC client ID for refresh exchange")
    parser.add_argument("--client-secret", type=str, default=None, help="OIDC client secret (optional)")
    parser.add_argument("--token-endpoint", type=str, default=None, help="OIDC token endpoint URL")
    parser.add_argument(
        "--oidc-issuer",
        type=str,
        default=None,
        help="OIDC issuer URL; token endpoint is discovered from /.well-known/openid-configuration",
    )
    parser.add_argument("--scope", type=str, default=None, help="Optional OIDC scope")
    parser.add_argument("--secure", action="store_true", help="Use a secure (TLS) connection")
    args = parser.parse_args()
    main(args)
