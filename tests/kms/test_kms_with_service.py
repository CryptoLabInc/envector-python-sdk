# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
# ========================================================================================

"""KMS tests that require a real KMS service.

This file is opt-in. Set:
- ``KMS_INTEGRATION_ADDR`` for real KMS lifecycle tests
- ``MSA_ADDR`` for SDK <-> MSA managed-mode end-to-end tests
"""

import base64
import os
import re
import time
import uuid

import numpy as np
import pytest

from pyenvector.errors import EnvectorTransportError, KeyManagementError
from pyenvector.kms.client import KMSClient
from pyenvector.proto_gen.v2.common import type_pb2
from pyenvector.proto_gen.v2.kms import kms_message_pb2 as kms_msg_pb2

KMS_ADDR = os.environ.get("KMS_INTEGRATION_ADDR", "")
MSA_ADDR = os.environ.get("MSA_ADDR", "")

pytestmark = pytest.mark.skipif(
    not KMS_ADDR,
    reason="KMS_INTEGRATION_ADDR not set; skipping KMS service tests",
)

_EVI_AVAILABLE = False
try:
    import importlib.util

    _EVI_AVAILABLE = importlib.util.find_spec("evi") is not None
except Exception:
    pass


def _unique_id(prefix: str = "integ") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _short_key_id(prefix: str) -> str:
    return f"e2e-{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def kms_client():
    client = KMSClient(address=KMS_ADDR, secure=False)
    yield client
    client.close()


@pytest.fixture(scope="module")
def msa_client():
    if not MSA_ADDR:
        pytest.skip("MSA_ADDR not set; skipping MSA-linked tests")

    from pyenvector.client.client import EnvectorClient

    client = EnvectorClient()
    client.init_connect(address=MSA_ADDR)
    yield client
    try:
        client.disconnect()
    except Exception:
        pass


def _cleanup_msa_test_artifacts(client):
    try:
        for index_name in client.indexer.get_index_list() or []:
            if index_name.startswith("e2e_kms_msa_"):
                try:
                    client.indexer.delete_index(index_name)
                except Exception:
                    pass
    except Exception:
        pass


def _load_key_with_cleanup(client, key_id: str):
    try:
        client.load_key(key_id=key_id)
        return
    except Exception as exc:
        match = re.search(r"Another key \(ID: ([^)]+)\) is already loaded", str(exc))
        if not match:
            raise

        loaded_key_id = match.group(1)
        try:
            client.unload_key(key_id=loaded_key_id)
        except Exception:
            pass
        client.load_key(key_id=key_id)


def _wait_for_registered_key(client, key_id: str, timeout: float = 10.0, poll_interval: float = 0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if key_id in (client.get_key_list() or []):
                return
        except Exception:
            pass
        time.sleep(poll_interval)
    raise AssertionError(f"Key ID '{key_id}' not found in server key list after register")


class TestKMSServiceLifecycle:
    def test_health_checks(self, kms_client):
        assert kms_client.health_check_keygen() is True
        assert kms_client.health_check_topk() is True

    def test_generate_key_and_wait(self, kms_client):
        key_id = _unique_id("keygen")
        result = kms_client.generate_key(key_id=key_id)
        assert result["key_id"] == key_id
        assert result["version"] == 1
        status = kms_client.wait_for_key(key_id, timeout=120)
        assert status["status"] == "KEY_GEN_STATUS_READY"

    def test_generate_key_without_metadata_encryption(self, kms_client):
        key_id = _unique_id("keygen-no-meta")
        result = kms_client.generate_key(key_id=key_id, metadata_encryption=False)
        assert result["key_id"] == key_id
        status = kms_client.wait_for_key(key_id, timeout=120)
        assert status["status"] == "KEY_GEN_STATUS_READY"

    def test_get_details_and_downloads(self, kms_client):
        key_id = _unique_id("admin-detail")
        kms_client.generate_key(key_id=key_id)
        kms_client.wait_for_key(key_id, timeout=120)

        details = kms_client.get_key_details(key_id)
        assert details["key_id"] == key_id
        assert len(details["versions"]) >= 1
        assert details["versions"][0]["version"] >= 1

        enc_key = kms_client.download_enc_key(key_id)
        eval_key = kms_client.download_eval_key(key_id)
        assert len(enc_key) > 0
        assert len(eval_key) > 0

    def test_transition_state_and_delete(self, kms_client):
        key_id = _unique_id("admin-state")
        kms_client.generate_key(key_id=key_id)
        kms_client.wait_for_key(key_id, timeout=120)

        assert kms_client.transition_state(
            key_id=key_id,
            new_state=kms_msg_pb2.KEY_STATE_ACTIVE,
            reason="integration test state transition",
        )

        details = kms_client.get_key_details(key_id)
        assert details["versions"][0]["state"] == "KEY_STATE_ACTIVE"

        assert kms_client.delete_key(key_id=key_id, reason="integration test cleanup")
        with pytest.raises((KeyManagementError, EnvectorTransportError)):
            kms_client.get_key_details(key_id)

    def test_full_lifecycle(self, kms_client):
        key_id = _unique_id("lifecycle")
        result = kms_client.generate_key(key_id=key_id)
        assert result["key_id"] == key_id
        kms_client.wait_for_key(key_id, timeout=120)

        details = kms_client.get_key_details(key_id)
        assert details["key_id"] == key_id
        assert len(kms_client.download_enc_key(key_id)) > 0
        assert len(kms_client.download_eval_key(key_id)) > 0

        assert kms_client.transition_state(
            key_id=key_id,
            new_state=kms_msg_pb2.KEY_STATE_ACTIVE,
            reason="lifecycle test state verification",
        )
        assert kms_client.delete_key(key_id=key_id, reason="lifecycle test cleanup")

    def test_topk_empty_scores_returns_empty(self, kms_client):
        key_id = _unique_id("topk-empty")
        result = kms_client.generate_key(key_id=key_id)
        kms_client.wait_for_key(result["key_id"], timeout=60)

        results = kms_client.topk(
            key_id=result["key_id"],
            encrypted_scores=[],
            k=5,
        )
        assert results == []

    def test_topk_nonexistent_key_fails(self, kms_client):
        ct = type_pb2.EVCiphertext(degree=65536, data=b"\x00" * 16)
        with pytest.raises(EnvectorTransportError):
            kms_client.topk(
                key_id="nonexistent-key-99999",
                encrypted_scores=[ct],
                k=3,
            )


class TestKMSManagedModeE2E:
    DIM = 128
    NUM_VECTORS = 10
    TOP_K = 3

    @staticmethod
    def _cipher_scores_to_kms_scores(result_ctxt):
        return [type_pb2.EVCiphertext(degree=score.degree, data=score.data) for score in result_ctxt.data.ctxt_score]

    @staticmethod
    def _manual_kms_round_trip(index, kms_client, result_ctxt, top_k, output_fields):
        shard_indices = list(getattr(result_ctxt.data, "shard_idx", []))
        ranked_results = kms_client.topk(
            key_id=index.index_config.key_id,
            encrypted_scores=TestKMSManagedModeE2E._cipher_scores_to_kms_scores(result_ctxt),
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
        metadata_result = index.indexer.get_metadata(index.index_config.index_name, topk_indices, fields=output_fields)

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

    @pytest.mark.skipif(not MSA_ADDR, reason="MSA_ADDR not set")
    @pytest.mark.skipif(not _EVI_AVAILABLE, reason="evi native bindings not available")
    def test_managed_mode_search_with_metadata(self, msa_client, kms_client):
        from pyenvector.client.client import EnvectorClient

        cleanup_client = EnvectorClient()
        cleanup_client.init_connect(address=MSA_ADDR)
        _cleanup_msa_test_artifacts(cleanup_client)
        cleanup_client.disconnect()

        client = None
        index = None
        key_id = _short_key_id("mng")
        index_name = f"e2e_kms_msa_{uuid.uuid4().hex[:8]}"

        try:
            client = EnvectorClient().init(
                address=MSA_ADDR,
                index_name=index_name,
                dim=self.DIM,
                key_path=None,
                key_id=key_id,
                preset="ip1",
                query_encryption="plain",
                index_encryption="cipher",
                index_type="flat",
                metadata_encryption=True,
                auto_key_setup=True,
                kms_address=KMS_ADDR,
            )
            index = client.create_index()

            rng = np.random.default_rng(7)
            vectors = rng.random((self.NUM_VECTORS, self.DIM)).tolist()
            metadata = [{"name": f"item_{i}"} for i in range(self.NUM_VECTORS)]
            index.insert(data=vectors, metadata=metadata)

            results = index.search(query=vectors[0], top_k=self.TOP_K, output_fields=["metadata"])
            assert isinstance(results, list)
            assert len(results) == 1
            assert len(results[0]) == self.TOP_K
            assert results[0][0]["score"] >= results[0][-1]["score"]
            actual_names = [row["metadata"]["name"] for row in results[0]]
            assert len(set(actual_names)) == self.TOP_K
            assert set(actual_names).issubset({item["name"] for item in metadata})
        finally:
            try:
                if index is not None:
                    index.delete_index()
            except Exception:
                pass
            try:
                if client is not None:
                    client.unload_key(key_id=key_id)
            except Exception:
                pass
            try:
                if client is not None:
                    client.delete_key(key_id)
            except Exception:
                pass
            try:
                if client is not None:
                    client.disconnect()
            except Exception:
                pass

    @pytest.mark.skipif(not MSA_ADDR, reason="MSA_ADDR not set")
    @pytest.mark.skipif(not _EVI_AVAILABLE, reason="evi native bindings not available")
    def test_explicit_kms_sdk_msa_flow_matches_managed_search(self, msa_client, kms_client):
        from pyenvector.client.client import EnvectorClient

        cleanup_client = EnvectorClient()
        cleanup_client.init_connect(address=MSA_ADDR)
        _cleanup_msa_test_artifacts(cleanup_client)
        cleanup_client.disconnect()

        client = None
        index = None
        key_id = _short_key_id("exp")
        index_name = f"e2e_kms_msa_{uuid.uuid4().hex[:8]}"

        try:
            generate_result = kms_client.generate_key(key_id=key_id)
            assert generate_result["key_id"] == key_id
            status = kms_client.wait_for_key(key_id, timeout=120)
            assert status["status"] == "KEY_GEN_STATUS_READY"

            client = EnvectorClient().init(
                address=MSA_ADDR,
                index_name=index_name,
                dim=self.DIM,
                key_path=None,
                key_id=key_id,
                preset="ip1",
                query_encryption="plain",
                index_encryption="cipher",
                index_type="flat",
                metadata_encryption=True,
                auto_key_setup=False,
                kms_address=KMS_ADDR,
            )
            client.register_key(key_id=key_id)
            _wait_for_registered_key(client, key_id)
            _load_key_with_cleanup(client, key_id)
            index = client.create_index()

            rng = np.random.default_rng(20260327)
            vectors = rng.random((self.NUM_VECTORS, self.DIM)).tolist()
            metadata = [{"name": f"item_{i}", "rank": i} for i in range(self.NUM_VECTORS)]
            query = vectors[0]

            index.insert(data=vectors, metadata=metadata)

            managed_results = index.search(query=query, top_k=self.TOP_K, output_fields=["metadata"])
            assert len(managed_results) == 1
            assert len(managed_results[0]) == self.TOP_K

            result_ctxt_list = index.scoring(query=query)
            assert len(result_ctxt_list) == 1
            manual_results = self._manual_kms_round_trip(
                index=index,
                kms_client=kms_client,
                result_ctxt=result_ctxt_list[0],
                top_k=self.TOP_K,
                output_fields=["metadata"],
            )

            managed_rows = managed_results[0]
            assert [row["id"] for row in manual_results] == [row["id"] for row in managed_rows]
            assert [row["metadata"] for row in manual_results] == [row["metadata"] for row in managed_rows]
            assert [row["score"] for row in manual_results] == pytest.approx(
                [row["score"] for row in managed_rows],
                rel=1e-5,
                abs=1e-6,
            )
        finally:
            try:
                if index is not None:
                    index.delete_index()
            except Exception:
                pass
            try:
                if client is not None:
                    client.unload_key(key_id=key_id)
            except Exception:
                pass
            try:
                if client is not None:
                    client.delete_key(key_id)
            except Exception:
                pass
            try:
                if client is not None:
                    client.disconnect()
            except Exception:
                pass
