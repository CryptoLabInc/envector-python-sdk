from __future__ import annotations

import base64
import re
import time
import uuid

import numpy as np

from pyenvector.client.client import EnvectorClient
from pyenvector.kms.client import KMSClient
from pyenvector.proto_gen.v2.common import type_pb2 as common_type_pb2


def short_key_id(prefix: str) -> str:
    return f"e2e-{prefix}-{uuid.uuid4().hex[:8]}"


def normalized_vectors(num_vectors: int, dim: int, seed: int) -> list[list[float]]:
    rng = np.random.default_rng(seed)
    vectors = rng.random((num_vectors, dim))
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1
    return (vectors / norms).tolist()


def cleanup_msa_artifacts(msa_addr: str, index_prefix: str, access_token: str | None = None, secure: bool = False) -> None:
    cleanup_client = EnvectorClient()
    cleanup_client.init_connect(address=msa_addr, access_token=access_token, secure=secure)
    try:
        for index_name in cleanup_client.indexer.get_index_list() or []:
            if not index_name.startswith(index_prefix):
                continue
            try:
                print(f"[cleanup] delete leftover index: {index_name}", flush=True)
                cleanup_client.indexer.delete_index(index_name)
            except Exception as exc:
                print(f"[cleanup] delete leftover index warning: {exc}", flush=True)
        for key_id in cleanup_client.indexer.get_key_list() or []:
            try:
                cleanup_client.indexer.unload_key(key_id=key_id)
            except Exception:
                pass
            try:
                cleanup_client.indexer.delete_key(key_id=key_id)
            except Exception:
                pass
    finally:
        cleanup_client.disconnect()


def wait_for_registered_key(client: EnvectorClient, key_id: str, timeout: float = 10.0, poll_interval: float = 0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if key_id in (client.get_key_list() or []):
                return
        except Exception:
            pass
        time.sleep(poll_interval)
    raise RuntimeError(f"Key '{key_id}' was not registered within {timeout}s")


def load_key_with_cleanup(client: EnvectorClient, key_id: str) -> None:
    try:
        client.load_key(key_id=key_id)
        return
    except Exception as exc:
        match = re.search(r"Another key \(ID: ([^)]+)\) is already loaded", str(exc))
        if not match:
            raise

    loaded_key_id = match.group(1)
    print(f"[cleanup] unloading previously loaded key: {loaded_key_id}", flush=True)
    try:
        client.unload_key(key_id=loaded_key_id)
    except Exception as unload_exc:
        print(f"[cleanup] unload warning: {unload_exc}", flush=True)
    client.load_key(key_id=key_id)


def kms_scores_from_result(result_ctxt):
    return [common_type_pb2.EVCiphertext(degree=score.degree, data=score.data) for score in result_ctxt.data.ctxt_score]


def manual_kms_round_trip(index, kms_client: KMSClient, result_ctxt, top_k: int):
    shard_indices = list(getattr(result_ctxt.data, "shard_idx", []))
    ranked_results = kms_client.topk(
        key_id=index.index_config.key_id,
        encrypted_scores=kms_scores_from_result(result_ctxt),
        k=top_k,
        shard_indices=shard_indices or None,
    )

    topk_indices = [
        {
            "shard_idx": ranked.metadata_idx.shard_idx,
            "row_idx": ranked.metadata_idx.row_idx,
        }
        for ranked in ranked_results
    ]
    metadata_result = index.indexer.get_metadata(index.index_config.index_name, topk_indices, fields=["metadata"])

    encrypted_metadata = []
    encrypted_positions = []
    for i, item in enumerate(metadata_result):
        payload = index._metadata_payload(item)
        if not payload:
            continue
        encrypted_metadata.append(base64.b64decode(payload))
        encrypted_positions.append(i)

    decrypted_metadata = [None] * len(metadata_result)
    if encrypted_metadata:
        plaintext_metadata = kms_client.decrypt_metadata(index.index_config.key_id, encrypted_metadata)
        for i, plaintext in zip(encrypted_positions, plaintext_metadata):
            decrypted_metadata[i] = index._parse_kms_plaintext_metadata(plaintext)

    return [
        {
            "id": metadata_result[i].id,
            "score": ranked_results[i].score,
            "metadata": decrypted_metadata[i],
        }
        for i in range(len(ranked_results))
    ]
