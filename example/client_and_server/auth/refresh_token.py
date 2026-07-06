"""
enVector High-Level API End-to-End Example (refresh-token auth)

Same scenario as basic_auth.py, but the SDK is initialized with an OIDC
refresh token instead of a pre-issued access token. The SDK exchanges the
refresh token at the IdP's token endpoint and renews the bearer transparently.

Scenario:
1. Connect as app-a and create/search an index.
2. Reconnect as app-b and verify index delete is denied by ownership check.
3. Reconnect as app-a and clean up.

Pass ``--kms-address`` to exercise the KMS-managed path: the SDK creates an
internal KMSClient that shares a single ``_AuthSession`` with the indexer, so
one OIDC refresh updates the bearer token for both envector and KMS RPCs.

Example:
python refresh_token.py \
    --port 50050 \
    --kms-address localhost:50090 \
    --refresh-token-file app-a.refresh_token \
    --client-id envector-cli \
    --token-endpoint http://localhost:8082/realms/envector/protocol/openid-connect/token \
    --oidc-issuer http://localhost:8082/realms/envector  \
    --scope "openid profile email offline_access"
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


def rebind_kms_to_indexer() -> None:
    """Re-share the KMSClient's ``_AuthSession`` with the new indexer.

    ``ev.init`` wires the internal KMSClient to the indexer's ``_AuthSession``
    so a single OIDC refresh updates the bearer for both clients. ``ev.init_connect``
    (the identity-swap call) only replaces the indexer, so for the KMS-managed
    path we re-thread the new session into the existing KMSClient here.
    """
    client = ev.pyenvector_client
    if client.kms_client is not None and client.indexer is not None:
        client.kms_client._auth_session = client.indexer._auth_session


def assert_kms_shares_session() -> None:
    """Sanity check that the only auth-state coordination point is one shared session."""
    client = ev.pyenvector_client
    if client.kms_client is None:
        raise AssertionError("Expected an internal KMSClient when --kms-address is set")
    if client.kms_client._auth_session is not client.indexer._auth_session:
        raise AssertionError("KMSClient and Indexer should share the same _AuthSession")
    print("Shared _AuthSession verified: one OIDC refresh updates both clients.")


def main(args):
    if not (args.token_endpoint or args.oidc_issuer):
        raise ValueError("Either --token-endpoint or --oidc-issuer must be provided")

    address = f"{args.host}:{args.port}"
    dim = args.dim
    use_kms = bool(args.kms_address)

    refresh_a = args.refresh_token if args.refresh_token else read_token(args.refresh_token_file)
    refresh_b = read_token(args.other_refresh_token_file)

    auth_a = build_auth_kwargs(refresh_a, args)
    auth_b = build_auth_kwargs(refresh_b, args)

    # init arguments
    init_kwargs = {
        "address": address,
        "secure": args.secure,
        "key_id": args.key_id,
        "eval_mode": args.eval_mode,
        "preset": args.preset,
        **auth_a,
    }
    if use_kms:
        init_kwargs["kms_address"] = args.kms_address
        init_kwargs["auto_key_setup"] = False
        init_kwargs["metadata_encryption"] = True

    ev.init(**init_kwargs)
    print(f"enVector initialized as app-a (kms={'on' if use_kms else 'off'}).")

    if use_kms:
        # Drive the KMS-managed key lifecycle explicitly. Each call below is
        # authenticated through the same shared _AuthSession.
        assert_kms_shares_session()
        print("Generating KMS-managed key bundle...")
        ev.generate_key(args.key_id)
        print("Registering KMS public keys with envector...")
        ev.register_key(args.key_id)
        print("Loading key into envector...")
        ev.load_key(args.key_id)

    index_name = args.index_name
    index = ev.create_index(index_name, dim)
    print(f"Index created: {index_name}")

    num_data = 10
    seed = 42
    vectors = [get_random_vector(dim, seed=seed + i) for i in range(num_data)]
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]

    # In KMS-managed mode this insert exercises KMS EncryptMetadata under the
    # same refresh-aware auth session as the envector RPCs.
    index.insert(vectors, metadata=db_metadata)

    search_index = ev.Index(index_name)
    query = [vectors[0]]
    if use_kms:
        # Managed search() runs the full pipeline including KMS TopK and
        # KMS DecryptMetadata, all on the shared bearer.
        results = search_index.search(query=query, top_k=2, output_fields=["metadata"])
        output_metadata = results[0]
    else:
        score_ctxt = search_index.scoring(query)[0]
        dec_score = search_index.decrypt_score(score_ctxt, sec_key_path=f"./keys/{args.key_id}/SecKey.json")
        output_metadata = search_index.get_topk_metadata_results(dec_score, top_k=2, output_fields=["metadata"])
    print("\nSearch result")
    print(output_metadata)
    assert abs(output_metadata[0]["score"] - 1) < 0.001, "Search score should be close to 1"

    # Reconnect as app-b and confirm owner check blocks delete.
    ev.init_connect(address=address, secure=args.secure, **auth_b)
    if use_kms:
        # init_connect only replaces the indexer; rebind the KMSClient to the
        # new app-b session so any subsequent KMS calls would carry app-b's
        # bearer (drop_index itself is envector-side, but this keeps the
        # invariant intact for any follow-up KMS RPC).
        rebind_kms_to_indexer()
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
    if use_kms:
        rebind_kms_to_indexer()
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
    parser.add_argument("--index-name", type=str, default="auth_refresh_idx", help="Index name")
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
    parser.add_argument("--eval-mode", "--eval_mode", dest="eval_mode", type=str, default="mm32", choices=["mm", "mms", "mm32", "mms32"], help="Evaluation mode")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    parser.add_argument("--kms-address", type=str, default=None, help="Optional ``host:port`` of the KMS gateway (gRPC)")
    args = parser.parse_args()
    main(args)
