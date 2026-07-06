"""Example: verify SDK and KMS deterministic seed compatibility through MSA.

The local envector-msa gRPC endpoint is plaintext in this flow; KMS uses the
SDK default TLS connection.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import uuid
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parents[3]
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

import numpy as np
from _kms_e2e_common import (
    cleanup_msa_artifacts,
    configure_local_kms_tls_roots,
    generate_local_secret_key_from_seed,
    load_key_with_cleanup,
    local_topk_from_seeded_secret,
    manual_kms_round_trip,
    normalized_vectors,
    parse_key_seed,
    short_key_id,
    wait_for_registered_key,
)

from pyenvector.client.client import EnvectorClient
from pyenvector.crypto.key_manager import KeyGenerator
from pyenvector.kms.client import KMSClient


def resolve_msa_address(args: argparse.Namespace) -> str:
    if args.msa_address:
        return args.msa_address
    return f"{args.host}:{args.port}"


def main(args: argparse.Namespace) -> None:
    msa_addr = resolve_msa_address(args)
    kms_addr = args.kms_address
    key_id = args.key_id or short_key_id("seed")
    index_name = args.index_name or f"e2e_kms_seed_{uuid.uuid4().hex[:8]}"
    key_seed = parse_key_seed(args.key_seed_hex, args.seed)

    print(f"[config] MSA={msa_addr}", flush=True)
    print(f"[config] KMS={kms_addr}", flush=True)
    print("[config] MSA TLS=disabled", flush=True)
    print(f"[config] KMS TLS={'disabled' if args.notls else 'enabled'}", flush=True)
    kms_ca = configure_local_kms_tls_roots(kms_addr, secure=not args.notls)
    if kms_ca:
        print(f"[config] KMS CA={kms_ca}", flush=True)
    print(f"[config] key_id={key_id}", flush=True)
    print(f"[config] eval_mode={args.eval_mode}", flush=True)
    print(f"[config] preset={args.preset}", flush=True)
    print(f"[config] index_name={index_name}", flush=True)
    print(f"[config] msa_access_token={'set' if args.access_token else 'unset'}", flush=True)
    print(f"[config] key_seed={'provided' if args.key_seed_hex else 'derived'}", flush=True)

    print("[cleanup] remove leftover seed e2e indexes/keys", flush=True)
    cleanup_msa_artifacts(msa_addr, "e2e_kms_seed_", access_token=args.access_token, secure=False)

    client = EnvectorClient()
    kms_client = KMSClient(
        address=kms_addr,
        secure=not args.notls,
        access_token=args.access_token,
        ca_cert=kms_ca,
    )
    index = None
    key_tmp = None
    try:
        key_tmp = tempfile.TemporaryDirectory(prefix="envector-sdk-kms-seed-e2e-")
        key_path = key_tmp.name
        sdk_key_dir = os.path.join(key_path, key_id)

        print("[step] SDK local KeyGenerator creates key bundle from deterministic seed", flush=True)
        KeyGenerator(
            key_path=sdk_key_dir,
            key_id=key_id,
            preset=args.preset,
            eval_mode=args.eval_mode,
            metadata_encryption=True,
            seed=key_seed,
        ).generate_keys()
        local_sec_key = generate_local_secret_key_from_seed(
            key_id=key_id,
            preset=args.preset,
            eval_mode=args.eval_mode,
            seed=key_seed,
        )

        print("[step] KMS GenerateKey creates matching key bundle from same seed", flush=True)
        kms_result = kms_client.generate_key(
            key_id=key_id,
            metadata_encryption=True,
            preset=args.preset,
            eval_mode=args.eval_mode,
            seed=key_seed,
        )
        if "READY" not in str(kms_result.get("status", "")):
            kms_client.wait_for_key(key_id)

        print("[step] Init SDK client with SDK-generated local keys", flush=True)
        client = EnvectorClient().init(
            address=msa_addr,
            access_token=args.access_token,
            secure=False,
            index_name=index_name,
            dim=args.dim,
            key_path=key_path,
            key_id=key_id,
            preset=args.preset,
            eval_mode=args.eval_mode,
            query_encryption="plain",
            index_encryption="cipher",
            index_type="flat",
            metadata_encryption=True,
            auto_key_setup=False,
        )

        print("[step] Register SDK-generated EvalKey with MSA", flush=True)
        client.register_key(key_id=key_id)
        wait_for_registered_key(client, key_id)

        print("[step] Load SDK-generated key on MSA", flush=True)
        load_key_with_cleanup(client, key_id)

        print("[step] CreateIndex", flush=True)
        index = client.create_index(index_name=index_name, dim=args.dim, index_type="flat", metadata_encryption=True)

        print("[step] Insert data encrypted by SDK-generated key material", flush=True)
        vectors = normalized_vectors(args.num_vectors, args.dim, seed=args.seed)
        metadata = [{"name": f"item_{i}", "rank": i} for i in range(args.num_vectors)]
        query = vectors[0]
        index.insert(data=vectors, metadata=metadata)

        print("[step] SDK scoring() returns encrypted scores; KMS TopK decrypts them", flush=True)
        result_ctxt = index.scoring(query=query)[0]
        kms_rows = manual_kms_round_trip(
            index=index,
            kms_client=kms_client,
            result_ctxt=result_ctxt,
            top_k=args.topk,
        )
        for row in kms_rows:
            print(f"  - kms id={row['id']} score={row['score']:.6f} metadata={row['metadata']}", flush=True)

        print("[step] Local SDK secret decrypts the same score ciphertext", flush=True)
        local_rows = local_topk_from_seeded_secret(
            result_ctxt=result_ctxt,
            sec_key=local_sec_key,
            dim=args.dim,
            preset=args.preset,
            eval_mode=args.eval_mode,
            top_k=args.topk,
        )
        for row in local_rows:
            print(
                "  - local "
                f"shard={row['metadata_idx']['shard_idx']} "
                f"row={row['metadata_idx']['row_idx']} "
                f"score={row['score']:.6f}",
                flush=True,
            )

        index_match = [row["metadata_idx"] for row in kms_rows] == [row["metadata_idx"] for row in local_rows]
        score_match = np.allclose(
            [row["score"] for row in kms_rows],
            [row["score"] for row in local_rows],
            rtol=1e-5,
            atol=1e-6,
        )

        print("[step] Verify KMS-decrypted metadata matches original inserted metadata", flush=True)
        kms_metadata = [row["metadata"] for row in kms_rows]
        expected_topk_metadata = [metadata[row["metadata_idx"]["row_idx"]] for row in kms_rows]
        metadata_match = kms_metadata == expected_topk_metadata
        for row in kms_rows:
            print(
                f"  - kms id={row['id']} score={row['score']:.6f} metadata={row['metadata']}",
                flush=True,
            )

        print("[result] seed_consistency_flow = True", flush=True)
        print("[result] seeded_decrypt_index_match =", index_match, flush=True)
        print("[result] seeded_decrypt_score_match =", score_match, flush=True)
        print("[result] seeded_metadata_match =", metadata_match, flush=True)
        if not (index_match and score_match):
            raise RuntimeError("SDK seeded key and KMS seeded key do not decrypt scores consistently")
        if not metadata_match:
            raise RuntimeError(
                f"KMS-decrypted metadata does not match original: got {kms_metadata}, expected {expected_topk_metadata}"
            )
    finally:
        try:
            if index is not None:
                try:
                    print(f"[cleanup] delete index: {index_name}", flush=True)
                    client.indexer.delete_index(index_name)
                except Exception as exc:
                    print(f"[cleanup] delete index warning: {exc}", flush=True)
            try:
                print(f"[cleanup] unload key: {key_id}", flush=True)
                client.unload_key(key_id=key_id)
            except Exception:
                pass
            if not args.skip_cleanup:
                try:
                    print(f"[cleanup] delete key: {key_id}", flush=True)
                    client.indexer.delete_key(key_id=key_id)
                except Exception:
                    pass
        finally:
            if key_tmp is not None:
                key_tmp.cleanup()
            try:
                client.disconnect()
            except ValueError:
                pass
            kms_client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="KMS seeded-key compatibility E2E example. MSA gRPC is plaintext; KMS uses TLS."
    )
    parser.add_argument("--host", type=str, default="localhost", help="MSA host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MSA_PORT", "50050")), help="MSA gRPC port")
    parser.add_argument("--msa-address", type=str, default=None, help="MSA gRPC address override")
    parser.add_argument("--kms-address", type=str, default=os.environ.get("KMS_INTEGRATION_ADDR", "localhost:50100"))
    parser.add_argument("--notls", action="store_true", help="Use plaintext for the KMS gRPC connection")
    parser.add_argument("--access-token", type=str, default=os.environ.get("ENVECTOR_ACCESS_TOKEN"))
    parser.add_argument("--key-id", type=str, default=None, help="Key ID for this run")
    parser.add_argument("--index-name", type=str, default=None, help="Index name override")
    parser.add_argument("--dim", type=int, default=int(os.environ.get("E2E_DIM", "128")), help="Vector dimension")
    parser.add_argument("--num-vectors", type=int, default=int(os.environ.get("E2E_NUM_VECTORS", "10")))
    parser.add_argument("--topk", type=int, default=int(os.environ.get("E2E_TOP_K", "3")))
    parser.add_argument("--seed", type=int, default=20260329, help="Random seed")
    parser.add_argument(
        "--key-seed-hex",
        type=str,
        default=os.environ.get("E2E_KEY_SEED_HEX"),
        help="128-character hex seed for deterministic KMS/local key generation",
    )
    parser.add_argument(
        "--preset",
        type=str,
        default=os.environ.get("KMS_PRESET", "ip3"),
        help="Key preset (must match between SDK local KeyGenerator and KMS)",
    )
    parser.add_argument(
        "--eval-mode",
        type=str,
        default=os.environ.get("KMS_EVAL_MODE", "mm32"),
        help="Eval mode (must match between SDK local KeyGenerator and KMS)",
    )
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep MSA key state after the run")
    main(parser.parse_args())
