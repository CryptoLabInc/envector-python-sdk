"""Example: KMS <-> SDK <-> envector-msa server end-to-end flow.

This is the single MSA-backed KMS example kept in ``example/client_and_server/e2e``.
It covers both the managed SDK path and the explicit KMS round-trip:

1. SDK init creates an internal KMS client
2. SDK generates, registers, and loads a KMS-managed key
3. Insert triggers KMS metadata encryption
4. Managed search() returns decrypted rows
5. Explicit scoring() + KMS TopK + KMS DecryptMetadata matches managed search()
"""

from __future__ import annotations

import argparse
import os
import uuid

import numpy as np
from _kms_e2e_common import (
    cleanup_msa_artifacts,
    load_key_with_cleanup,
    manual_kms_round_trip,
    normalized_vectors,
    short_key_id,
    wait_for_registered_key,
)

from pyenvector.client.client import EnvectorClient


def resolve_msa_address(args: argparse.Namespace) -> str:
    if args.msa_address:
        return args.msa_address
    return f"{args.host}:{args.port}"


def main(args: argparse.Namespace) -> None:
    msa_addr = resolve_msa_address(args)
    kms_addr = args.kms_address
    key_id = args.key_id or short_key_id("msa")
    index_name = args.index_name or f"e2e_kms_msa_{uuid.uuid4().hex[:8]}"

    print(f"[config] MSA={msa_addr}", flush=True)
    print(f"[config] KMS={kms_addr}", flush=True)
    print(f"[config] key_id={key_id}", flush=True)
    print(f"[config] index_name={index_name}", flush=True)
    print(f"[config] secure={args.secure}", flush=True)
    print(f"[config] msa_access_token={'set' if args.access_token else 'unset'}", flush=True)

    print("[cleanup] remove leftover e2e indexes/keys", flush=True)
    cleanup_msa_artifacts(msa_addr, "e2e_kms_msa_", access_token=args.access_token, secure=args.secure)

    client = EnvectorClient()
    index = None
    try:
        print("[step] Init SDK client with internal KMS client", flush=True)
        client = EnvectorClient().init(
            address=msa_addr,
            access_token=args.access_token,
            secure=args.secure,
            index_name=index_name,
            dim=args.dim,
            key_path=None,
            key_id=key_id,
            preset="ip2",
            eval_mode="mm32",
            query_encryption="plain",
            index_encryption="cipher",
            index_type="flat",
            metadata_encryption=True,
            auto_key_setup=False,
            kms_address=kms_addr,
        )
        if client.kms_client is None:
            raise RuntimeError("EnvectorClient.init() did not create an internal KMS client")

        print("[step] GenerateKey via SDK-managed KMS client", flush=True)
        client.generate_key(key_id=key_id)

        print("[step] RegisterKey", flush=True)
        client.register_key(key_id=key_id)
        wait_for_registered_key(client, key_id)

        print("[step] LoadKey", flush=True)
        load_key_with_cleanup(client, key_id)

        print("[step] CreateIndex", flush=True)
        index = client.create_index(index_name=index_name, dim=args.dim, index_type="flat", metadata_encryption=True)
        if index.kms_client is not client.kms_client:
            raise RuntimeError("Index did not reuse the SDK internal KMS client")

        print("[step] Insert data (managed KMS EncryptMetadata)", flush=True)
        vectors = normalized_vectors(args.num_vectors, args.dim, seed=args.seed)
        metadata = [{"name": f"item_{i}", "rank": i} for i in range(args.num_vectors)]
        query = vectors[0]
        index.insert(data=vectors, metadata=metadata)

        print("[step] Managed search()", flush=True)
        managed_results = index.search(query=query, top_k=args.topk, output_fields=["metadata"])
        managed_rows = managed_results[0]
        for row in managed_rows:
            print(f"  - managed id={row['id']} score={row['score']:.6f} metadata={row['metadata']}", flush=True)

        print("[step] Explicit scoring() + KMS TopK + KMS DecryptMetadata", flush=True)
        explicit_rows = manual_kms_round_trip(
            index=index,
            kms_client=client.kms_client,
            result_ctxt=index.scoring(query=query)[0],
            top_k=args.topk,
        )
        for row in explicit_rows:
            print(f"  - explicit id={row['id']} score={row['score']:.6f} metadata={row['metadata']}", flush=True)

        ids_match = [row["id"] for row in explicit_rows] == [row["id"] for row in managed_rows]
        metadata_match = [row["metadata"] for row in explicit_rows] == [row["metadata"] for row in managed_rows]
        score_match = np.allclose(
            [row["score"] for row in explicit_rows],
            [row["score"] for row in managed_rows],
            rtol=1e-5,
            atol=1e-6,
        )
        print("[result] internal_kms_client_created = True", flush=True)
        print("[result] shared_kms_client_instance = True", flush=True)
        print("[result] ids_match =", ids_match, flush=True)
        print("[result] metadata_match =", metadata_match, flush=True)
        print("[result] score_match =", score_match, flush=True)

        if not (ids_match and metadata_match and score_match):
            raise RuntimeError("Managed search and explicit KMS/MSA flow do not match")
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
            client.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KMS <-> SDK <-> MSA E2E example")
    parser.add_argument("--host", type=str, default="localhost", help="MSA host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MSA_PORT", "50050")), help="MSA gRPC port")
    parser.add_argument("--msa-address", type=str, default=None, help="MSA gRPC address override")
    parser.add_argument("--kms-address", type=str, default=os.environ.get("KMS_INTEGRATION_ADDR", "localhost:50100"))
    parser.add_argument("--access-token", type=str, default=os.environ.get("ENVECTOR_ACCESS_TOKEN"))
    parser.add_argument("--secure", action="store_true", help="Use TLS for both MSA and KMS gRPC connections")
    parser.add_argument("--key-id", type=str, default=None, help="Key ID for this run")
    parser.add_argument("--index-name", type=str, default=None, help="Index name override")
    parser.add_argument("--dim", type=int, default=int(os.environ.get("E2E_DIM", "128")), help="Vector dimension")
    parser.add_argument("--num-vectors", type=int, default=int(os.environ.get("E2E_NUM_VECTORS", "10")))
    parser.add_argument("--topk", type=int, default=int(os.environ.get("E2E_TOP_K", "3")))
    parser.add_argument("--seed", type=int, default=20260329, help="Random seed")
    parser.add_argument("--skip-cleanup", action="store_true", help="Keep MSA key state after the run")
    main(parser.parse_args())
