import base64
import importlib
from unittest.mock import MagicMock, call, patch

import numpy as np
import pytest

from pyenvector.api import Indexer
from pyenvector.crypto.block import CipherBlock
from pyenvector.index.index import Index, IndexConfig
from pyenvector.proto_gen.v2.common import index_operation_message_pb2 as envector_op_pb2
from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb
from pyenvector.proto_gen.v2.kms import kms_message_pb2 as kms_msg_pb2

ENVECTOR_UTILS_AES = importlib.import_module("pyenvector.utils.aes")


@pytest.fixture
def mock_indexer():
    mock = MagicMock(spec=Indexer)
    mock.get_index_list.return_value = ["test_index"]
    mock.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 2,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
        "can_load_now": True,
        "remaining_insertable_shards": 8,
        "remaining_insertable_vectors_guaranteed": 32768,
        "remaining_insertable_vectors_best_effort": 32768,
    }
    mock.get_index_info.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 2,
        "search_type": "ip",  # Added search_type to fix KeyError
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "index_type": "FLAT",
        "description": "Test index",
    }
    mock.create_index.return_value = None
    bulk_request_ids = iter(["split-bulk-1", "split-bulk-2", "split-bulk-3"])
    row_request_ids = iter(["split-row-1", "split-row-2", "split-row-3"])

    def async_persist_data_bulk_side_effect(*args, **kwargs):
        out_request_id = kwargs.get("out_request_id")
        if out_request_id is not None:
            out_request_id.append(next(bulk_request_ids))
        return [1, 2]

    def async_persist_data_rows_batch_side_effect(*args, **kwargs):
        out_request_id = kwargs.get("out_request_id")
        if out_request_id is not None:
            out_request_id.append(next(row_request_ids))
        return [1, 1]

    mock.insert_data_bulk.return_value = [1, 2]
    mock.insert_data_rows_batch.return_value = [1, 1]
    mock.async_persist_data_bulk.side_effect = async_persist_data_bulk_side_effect
    mock.async_persist_data_rows_batch.side_effect = async_persist_data_rows_batch_side_effect
    mock.async_merge_by_request_ids.return_value = "merge-req-1"
    mock.wait_for_index_operations_state.return_value = []
    mock.wait_for_insert_searchable.return_value = MagicMock()
    mock.wait_for_inserts_searchable.return_value = []
    mock.wait_for_insert_persist_completed.return_value = MagicMock()
    mock.wait_for_merge_complete.return_value = MagicMock()
    mock.search.return_value = [[[0.01 * i for i in range(32)]]]  # shape: ((1, 32))
    mock.get_metadata.return_value = [
        MagicMock(id=1, infos="meta1"),
        MagicMock(id=2, infos="meta2"),
    ]
    return mock


@pytest.fixture
def index_config():
    return IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "flat"},
    )


def test_index_create_and_insert(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    # Patch Cipher to avoid real encryption
    cipher_mock = MagicMock()
    # Default insert now uses bulk path unless use_row_insert=True is passed.
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1, 1]
    cipher_block_mock.num_vectors = 2
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    # Mock encrypt_metadata to avoid loading the actual key file
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    index = Index("test_index", index_config)
    index.cipher = cipher_mock  # Explicitly set cipher mock
    assert index.index_config.index_name == "test_index"
    data = [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]]
    metadata = ["meta1", "meta2"]
    result = index.insert(data, metadata)
    assert result == [1, 2]
    mock_indexer.async_persist_data_bulk.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["split-bulk-1"])
    mock_indexer.wait_for_index_operations_state.assert_not_called()
    mock_indexer.load_index.assert_called_once_with("test_index")
    mock_indexer.wait_for_inserts_searchable.assert_not_called()


def test_insert_chunk_uses_centroids_idx_from_cipherblock(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index("test_index", index_config)
    data_chunk = MagicMock()
    data_chunk.data = [MagicMock()]
    data_chunk.num_item_list = [1]
    data_chunk.num_vectors = 1
    data_chunk.centroids_idx = [3]

    index._insert_chunk(data_chunk, metadata=["meta"])

    args, kwargs = mock_indexer.async_persist_data_bulk.call_args
    assert args[4] == [3]
    assert kwargs["out_request_id"] is None


def test_insert_chunk_ivf_requires_centroids_idx(monkeypatch, mock_indexer):
    ivf_config = IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "ivf_flat", "nlist": 2, "default_nprobe": 1},
    )
    mock_indexer.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
    }
    mock_indexer.get_index_info.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "ivf_detail": MagicMock(
            nlist=2,
            default_nprobe=1,
            centroids=[MagicMock(plain_vector=MagicMock(data=[0.0] * 32)) for _ in range(2)],
        ),
    }

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index("test_index", ivf_config)
    data_chunk = MagicMock()
    data_chunk.data = [MagicMock()]
    data_chunk.num_item_list = [1]
    data_chunk.num_vectors = 1
    data_chunk.centroids_idx = None

    with pytest.raises(ValueError, match="IVF insert requires centroids_idx"):
        index._insert_chunk(data_chunk, metadata=["meta"])


def test_insert_ivf_bulk_accepts_encrypted_cipherblock_with_centroids(monkeypatch, mock_indexer):
    ivf_config = IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "ivf_flat", "nlist": 2, "default_nprobe": 1},
    )
    mock_indexer.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
    }
    mock_indexer.get_index_info.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "ivf_detail": MagicMock(
            nlist=2,
            default_nprobe=1,
            centroids=[MagicMock(plain_vector=MagicMock(data=[0.0] * 32)) for _ in range(2)],
        ),
    }

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index("test_index", ivf_config)

    with patch("evi.Query", autospec=True) as MockQuery:
        q1 = MockQuery()
        q2 = MockQuery()
        q1.getInnerItemCount.return_value = 1
        q2.getInnerItemCount.return_value = 1

        encrypted_chunk_1 = CipherBlock(q1, centroids_idx=[0])
        encrypted_chunk_2 = CipherBlock(q2, centroids_idx=[1])

        index._knn = MagicMock()
        normalized_data = index._normalize_insert_data([encrypted_chunk_1, encrypted_chunk_2])
        item_ids = index._insert_ivf_bulk(normalized_data, metadata=["m1", "m2"])

        assert item_ids == [1, 2]
        assert mock_indexer.async_persist_data_bulk.call_count == 2
        index._knn.assert_not_called()


def test_insert_ivf_row_path_accepts_serialized_ciphertexts_with_centroids(monkeypatch, mock_indexer):
    ivf_config = IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "ivf_flat", "nlist": 2, "default_nprobe": 1},
    )
    mock_indexer.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
        "remaining_insertable_shards": 8,
        "remaining_insertable_vectors_guaranteed": 32768,
        "remaining_insertable_vectors_best_effort": 32768,
    }
    mock_indexer.get_index_info.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "index_type": "IVF_FLAT",
        "description": "Test index",
        "ivf_detail": MagicMock(
            nlist=2,
            default_nprobe=1,
            centroids=[MagicMock(plain_vector=MagicMock(data=[0.0] * 32)) for _ in range(2)],
        ),
        "remaining_insertable_shards": 8,
        "remaining_insertable_vectors_guaranteed": 32768,
        "remaining_insertable_vectors_best_effort": 32768,
    }

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_mock.encrypt_row.return_value = CipherBlock([b"ctxt-1", b"ctxt-2"], centroids_idx=[0, 1])
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", ivf_config)
    index.cipher = cipher_mock
    index._knn = MagicMock(return_value=[[0], [1]])

    item_ids = index.insert(
        [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]],
        ["meta1", "meta2"],
        use_row_insert=True,
        load=False,
    )

    assert item_ids == [1, 1]
    cipher_mock.encrypt_row.assert_called_once()
    mock_indexer.async_persist_data_rows_batch.assert_called_once()
    args, kwargs = mock_indexer.async_persist_data_rows_batch.call_args
    assert args[3] == [0, 1]
    assert kwargs["out_request_id"] == ["split-row-1"]


def test_index_init_uses_summary_instead_of_detail(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    Index("test_index", index_config)

    mock_indexer.get_index_summary.assert_called_once_with("test_index")
    mock_indexer.get_index_info.assert_not_called()


def test_index_search_and_topk(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    fake_cipher = MagicMock()
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=fake_cipher))
    monkeypatch.setattr("pyenvector.index.index.CipherBlock", MagicMock())  # 이 줄 추가
    # Mock encrypt_metadata and decrypt_metadata to avoid loading actual key files
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr("pyenvector.index.index.decrypt_metadata", MagicMock(return_value="decrypted_metadata"))
    monkeypatch.setattr(
        "pyenvector.index.index.Index._multiquery_get_topk_metadata_results",
        MagicMock(
            return_value=[
                [
                    {"id": 1, "score": 0.5, "metadata": "meta1"},
                    {"id": 2, "score": 0.4, "metadata": "meta2"},
                ]
            ]
        ),
    )
    index = Index("test_index", index_config)
    index.cipher = fake_cipher
    query = [0.01 * i for i in range(32)]
    results = index.search(query, top_k=2, output_fields=["metadata"])
    assert isinstance(results, list)
    assert len(results) == 1  # number of responsed result
    assert len(results[0]) == 2  # top_k
    assert "id" in results[0][0] and "score" in results[0][0] and "metadata" in results[0][0]


def test_get_topk_metadata_results(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    # Patch Cipher to avoid real encryption/decryption
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())
    # Mock encrypt_metadata and decrypt_metadata to avoid loading actual key files
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr("pyenvector.index.index.decrypt_metadata", MagicMock(return_value="decrypted_metadata"))
    index = Index("test_index", index_config)
    # result: 2D list, e.g. [[0.9, 0.8, 0.7, 0.6]]
    result = {"score": [[0.01 * i for i in range(32)]]}
    top_k = 2
    output_fields = ["metadata"]
    output = index.get_topk_metadata_results(result, top_k, output_fields)
    assert isinstance(output, list)
    assert len(output) == 2
    assert all("id" in o and "score" in o and "metadata" in o for o in output)


def test_index_search_uses_kms_topk_and_metadata_decrypt(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = None
    fake_cipher = MagicMock()
    fake_kms = MagicMock()
    fake_kms.topk.return_value = [
        kms_msg_pb2.TopKResult(
            item_id="item-0",
            score=0.91,
            metadata_idx=envector_type_pb.MetadataIdx(shard_idx=7, row_idx=1),
        ),
        kms_msg_pb2.TopKResult(
            item_id="item-1",
            score=0.72,
            metadata_idx=envector_type_pb.MetadataIdx(shard_idx=8, row_idx=3),
        ),
    ]
    fake_kms.decrypt_metadata.return_value = ['{"name": "meta1"}', "meta2"]
    monkeypatch.setattr(Index, "_default_kms_client", fake_kms, raising=False)

    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=fake_cipher))
    score_result = envector_type_pb.CiphertextScore(
        id="q0",
        shard_idx=[7, 8],
        ctxt_score=[
            envector_type_pb.EVCiphertext(degree=65536, data=b"score-1"),
            envector_type_pb.EVCiphertext(degree=65536, data=b"score-2"),
        ],
    )
    mock_indexer.get_metadata.return_value = [
        MagicMock(id=101, data=base64.b64encode(b"cipher-1").decode("ascii")),
        MagicMock(id=202, data=base64.b64encode(b"cipher-2").decode("ascii")),
    ]

    index = Index(
        "test_index",
        index_config.deepcopy(
            key_path=None,
            use_key_stream=True,
            enc_key=b"enc-key",
            eval_key=b"eval-key",
            sec_key=None,
            metadata_key=None,
            metadata_encryption=True,
        ),
    )
    index.cipher = fake_cipher
    index.scoring = MagicMock(return_value=[CipherBlock(score_result)])

    results = index.search([0.01 * i for i in range(32)], top_k=2, output_fields=["metadata"])

    assert results == [
        [
            {"id": 101, "score": pytest.approx(0.91), "metadata": {"name": "meta1"}},
            {"id": 202, "score": pytest.approx(0.72), "metadata": "meta2"},
        ]
    ]
    fake_kms.topk.assert_called_once()
    topk_kwargs = fake_kms.topk.call_args.kwargs
    assert topk_kwargs["shard_indices"] == [7, 8]
    assert all(isinstance(item, envector_type_pb.EVCiphertext) for item in topk_kwargs["encrypted_scores"])


def test_index_decrypt_score_not_supported_in_kms_mode(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = None
    monkeypatch.setattr(Index, "_default_kms_client", MagicMock(), raising=False)
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=MagicMock()))

    index = Index(
        "test_index",
        index_config.deepcopy(
            key_path=None,
            use_key_stream=True,
            enc_key=b"enc-key",
            eval_key=b"eval-key",
            sec_key=None,
        ),
    )
    with pytest.raises(NotImplementedError, match="KMS-managed mode"):
        index.decrypt_score(MagicMock(spec=CipherBlock))


def test_insert_list_of_lists(monkeypatch, mock_indexer, index_config):
    """Test insert with list[list[float]] data type"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1, 1]
    cipher_block_mock.num_vectors = 2
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    # Manually set the cipher mock to the index instance
    index.cipher = cipher_mock

    # Test with list[list[float]]
    data = [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]]
    metadata = ["meta1", "meta2"]
    result = index.insert(data, metadata)
    assert result == [1, 2]
    cipher_mock.encrypt_multiple.assert_called_once()


def test_insert_list_of_ndarrays(monkeypatch, mock_indexer, index_config):
    """Test insert with list[np.ndarray] data type"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1, 1]
    cipher_block_mock.num_vectors = 2
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    # Manually set the cipher mock to the index instance
    index.cipher = cipher_mock

    # Test with list[np.ndarray]
    data = [np.array([0.01 * i for i in range(32)]), np.array([0.02 * i for i in range(32)])]
    metadata = ["meta1", "meta2"]
    result = index.insert(data, metadata)
    assert result == [1, 2]
    cipher_mock.encrypt_multiple.assert_called_once()


def test_insert_2d_ndarray(monkeypatch, mock_indexer, index_config):
    """Test insert with 2D np.ndarray data type"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1, 1]
    cipher_block_mock.num_vectors = 2
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    # Manually set the cipher mock to the index instance
    index.cipher = cipher_mock

    # Test with 2D np.ndarray
    data = np.array([[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]])
    metadata = ["meta1", "meta2"]
    result = index.insert(data, metadata)
    assert result == [1, 2]
    cipher_mock.encrypt_multiple.assert_called_once()


def test_insert_single_cipherblock_is_normalized_to_list(monkeypatch, mock_indexer, index_config):
    """Single CipherBlock input should follow the CipherBlock bulk-insert path."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"

    class FakeCipherBlock:
        def __init__(self, data, num_item_list, num_vectors):
            self.data = data
            self.num_item_list = num_item_list
            self.num_vectors = num_vectors
            self.centroids_idx = None

    monkeypatch.setattr("pyenvector.index.index.CipherBlock", FakeCipherBlock)
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    single_block = FakeCipherBlock(data=[MagicMock(), MagicMock()], num_item_list=[1, 1], num_vectors=2)

    result = index.insert(single_block, ["meta1", "meta2"])

    assert result == [1, 2]
    mock_indexer.async_persist_data_bulk.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["split-bulk-1"])
    mock_indexer.load_index.assert_called_once_with("test_index")


def test_insert_await_completion_false_skips_wait_only(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1]
    cipher_block_mock.num_vectors = 1
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    result = index.insert([[0.01 * i for i in range(32)]], ["meta1"], await_completion=False)

    assert result == [1, 2]
    mock_indexer.wait_for_index_operations_state.assert_not_called()
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["split-bulk-1"])
    mock_indexer.load_index.assert_called_once_with("test_index")
    mock_indexer.wait_for_inserts_searchable.assert_not_called()


def test_insert_await_completion_requires_bool(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_mock.encrypt_row.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    with pytest.raises(TypeError, match="await_completion must be a bool when provided"):
        index.insert([[0.01 * i for i in range(32)]], ["meta1"], await_completion="false")


def test_insert_request_ids_capture_split_ids_only(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_block_mock.num_item_list = [1]
    cipher_block_mock.num_vectors = 1
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    request_ids = []
    index.insert([[0.01 * i for i in range(32)]], ["meta1"], request_ids=request_ids)

    assert request_ids == ["split-bulk-1"]


def test_insert_multiple_split_requests_waits_and_merges(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    bulk_cipher_block_1 = MagicMock()
    bulk_cipher_block_1.data = [MagicMock()]
    bulk_cipher_block_1.num_item_list = [1]
    bulk_cipher_block_1.num_vectors = 1
    bulk_cipher_block_2 = MagicMock()
    bulk_cipher_block_2.data = [MagicMock()]
    bulk_cipher_block_2.num_item_list = [1]
    bulk_cipher_block_2.num_vectors = 1
    cipher_mock.encrypt_multiple.side_effect = [bulk_cipher_block_1, bulk_cipher_block_2]
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr("pyenvector.index.index.ENCRYPTION_BATCH_SIZE", 32)

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    result = index.insert(
        np.random.rand(64, 32).astype(np.float32),
        [f"meta{i}" for i in range(64)],
        await_completion=True,
        load=True,
    )

    assert result == [1, 2]
    assert mock_indexer.async_persist_data_bulk.call_count == 2
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["split-bulk-1", "split-bulk-2"])
    mock_indexer.wait_for_index_operations_state.assert_called_once_with(
        "test_index",
        ["split-bulk-1", "split-bulk-2"],
        target_state=envector_op_pb2.MERGED_SAVED,
        timeout_s=86400.0,
        poll_interval_s=1.0,
    )
    mock_indexer.load_index.assert_called_once_with("test_index")
    mock_indexer.wait_for_inserts_searchable.assert_not_called()


def test_insert_large_2d_ndarray(monkeypatch, mock_indexer, index_config):
    """Test insert with large 2D np.ndarray (7000, 32) to test batch processing"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    # Create a proper CipherBlock mock
    cipher_block_mock = MagicMock()
    cipher_block_mock.num_item_list = [128]  # Mock the num_item_list attribute for batch processing
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    # Manually set the cipher mock to the index instance
    index.cipher = cipher_mock

    # Test with large 2D np.ndarray (7000, 32)
    data = np.random.rand(7000, 32).astype(np.float32)
    metadata = [f"meta_{i}" for i in range(7000)]
    index.insert(data, metadata)
    # assert result == [i for i in range(1, 7001)]
    # Should be called multiple times due to batch processing
    assert cipher_mock.encrypt_multiple.call_count > 1


def test_insert_flush_uses_async_persist_waits_for_split_and_loads(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_mock.encrypt_row.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    def capture_request_id(*args, **kwargs):
        kwargs["out_request_id"].append("req-1")
        return [1, 1]

    mock_indexer.async_persist_data_rows_batch.side_effect = capture_request_id

    request_ids = []
    result = index.insert(
        [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]],
        ["meta1", "meta2"],
        request_ids=request_ids,
        execute_until="flush",
        await_completion=True,
        use_row_insert=True,
    )

    assert result == [1, 1]
    mock_indexer.async_persist_data_rows_batch.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_not_called()
    mock_indexer.wait_for_index_operations_state.assert_called_once()
    _, wait_kwargs = mock_indexer.wait_for_index_operations_state.call_args
    assert wait_kwargs["target_state"] == envector_op_pb2.SPLIT_COMPLETED
    mock_indexer.load_index.assert_called_once_with("test_index")


def test_insert_segmentation_queues_manual_merge_and_load(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_mock.encrypt_row.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    def capture_request_id(*args, **kwargs):
        kwargs["out_request_id"].append("req-1")
        return [1, 1]

    mock_indexer.async_persist_data_rows_batch.side_effect = capture_request_id

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    index.insert(
        [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]],
        ["meta1", "meta2"],
        execute_until="segmentation",
        use_row_insert=True,
    )

    mock_indexer.async_persist_data_rows_batch.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["req-1"])
    mock_indexer.load_index.assert_called_once_with("test_index")


def test_insert_segmentation_with_load_waits_for_merge_only(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock(), MagicMock()]
    cipher_mock.encrypt_row.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    monkeypatch.setattr(ENVECTOR_UTILS_AES, "encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    def capture_request_id(*args, **kwargs):
        kwargs["out_request_id"].append("req-1")
        return [1, 1]

    mock_indexer.async_persist_data_rows_batch.side_effect = capture_request_id

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    result = index.insert(
        [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]],
        ["meta1", "meta2"],
        await_completion=True,
        load=True,
        use_row_insert=True,
    )

    assert result == [1, 1]
    mock_indexer.async_persist_data_rows_batch.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_called_once_with("test_index", ["req-1"])
    mock_indexer.wait_for_index_operations_state.assert_called_once_with(
        "test_index",
        ["req-1"],
        target_state=envector_op_pb2.MERGED_SAVED,
        timeout_s=86400.0,
        poll_interval_s=1.0,
    )
    mock_indexer.load_index.assert_called_once_with("test_index")
    mock_indexer.wait_for_inserts_searchable.assert_not_called()
    mock_indexer.insert_data_rows_batch.assert_not_called()


def test_insert_flush_with_load_is_allowed(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock()]
    cipher_block_mock.num_item_list = [1]
    cipher_block_mock.num_vectors = 1
    cipher_mock.encrypt_multiple.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

    index = Index("test_index", index_config)
    index.cipher = cipher_mock

    result = index.insert(
        [[0.01 * i for i in range(32)]],
        ["meta1"],
        execute_until="flush",
        load=True,
    )

    assert result == [1, 2]
    mock_indexer.async_persist_data_bulk.assert_called_once()
    mock_indexer.async_merge_by_request_ids.assert_not_called()
    mock_indexer.wait_for_index_operations_state.assert_not_called()
    mock_indexer.load_index.assert_called_once_with("test_index")


def test_insert_invalid_dimension_error(monkeypatch, mock_indexer, index_config):
    """Test insert with invalid dimension raises ValueError"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))

    index = Index("test_index", index_config)
    # Manually set the cipher mock to the index instance
    index.cipher = cipher_mock

    # Test with wrong dimension
    data = np.array([[0.01 * i for i in range(16)]])  # Wrong dimension (16 instead of 32)
    metadata = ["meta1"]

    with pytest.raises(ValueError, match="Data dimension 16 does not match index dimension 32"):
        index.insert(data, metadata)


def test_ivf_flat_lazy_loads_centroids_for_knn(monkeypatch, mock_indexer):
    mock_indexer.get_index_summary.return_value = {
        **mock_indexer.get_index_summary.return_value,
        "index_type": "IVF_FLAT",
    }
    mock_indexer.get_index_info.return_value = {
        **mock_indexer.get_index_info.return_value,
        "index_type": "IVF_FLAT",
        "ivf_detail": MagicMock(
            nlist=4,
            default_nprobe=2,
            centroids=[MagicMock(plain_vector=MagicMock(data=list(np.random.rand(32)))) for _ in range(4)],
        ),
    }

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index(
        "test_index",
        IndexConfig(
            index_name="test_index",
            dim=32,
            key_path="./keys",
            key_id="test_key",
            preset="ip1",
            query_encryption="plain",
            index_encryption="cipher",
            index_params={"index_type": "ivf_flat"},
        ),
    )

    assert mock_indexer.get_index_info.call_count == 0

    knn_result = index._knn(np.random.rand(2, 32).astype(np.float32), k=1)
    second_knn_result = index._knn(np.random.rand(1, 32).astype(np.float32), k=1)

    assert len(knn_result) == 2
    assert len(second_knn_result) == 1
    assert mock_indexer.get_index_info.call_count == 1
    assert index.index_config.default_nprobe == 2
    assert index.index_config.nlist == 4


def test_ivf_vct_lazy_loads_runtime_metadata_without_centroids(monkeypatch, mock_indexer):
    mock_indexer.get_index_summary.return_value = {
        **mock_indexer.get_index_summary.return_value,
        "index_type": "IVF_VCT",
    }
    mock_indexer.get_index_info.return_value = {
        **mock_indexer.get_index_info.return_value,
        "index_type": "IVF_VCT",
        "ivf_detail": MagicMock(
            nlist=8,
            default_nprobe=3,
            centroids=[MagicMock(plain_vector=MagicMock(data=list(np.random.rand(32)))) for _ in range(8)],
        ),
    }

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index(
        "test_index",
        IndexConfig(
            index_name="test_index",
            dim=32,
            key_path="./keys",
            key_id="test_key",
            preset="ip1",
            query_encryption="plain",
            index_encryption="cipher",
            index_params={"index_type": "ivf_vct"},
        ),
    )

    assert mock_indexer.get_index_info.call_count == 0

    index._ensure_ivf_runtime_metadata_loaded()

    assert mock_indexer.get_index_info.call_count == 1
    assert index.index_config.default_nprobe == 3
    assert index.index_config.nlist == 8
    assert "centroids" not in index.index_config.index_params


@pytest.mark.parametrize(
    "method,item_ids,metadata,numitems",
    [
        ("persist_batch", [101, 202], [["meta"]], [1]),
    ],
)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_insert_methods_return_item_ids(mock_stub, method, item_ids, metadata, numitems):
    connection = MagicMock()
    connection.is_connected.return_value = True
    connection.get_channel.return_value = MagicMock()

    indexer = Indexer(connection)
    response = MagicMock()
    response.header.return_code = envector_type_pb.ReturnCode.Success
    response.header.id = "split-batch-req"
    response.item_ids = item_ids

    stub_method = getattr(indexer.stub, method)
    stub_method.return_value = response

    vectors = [[0.01 * i for i in range(32)]]

    result = indexer.insert_data_bulk(
        "test-index",
        vectors,
        numitems=numitems,
        metadata=metadata,
    )

    assert result == item_ids
    stub_method.assert_called_once()


class TestBatchInsertFailureContract:
    """Tests for batch insert failure behavior.

    Contract: Batch insert operations fail fast with RuntimeError
    when any batch fails, rather than silently continuing.

    See: docs/specs/sdk/batch-insert-failure-contract-v1.md
    """

    def test_insert_ivf_bulk_raises_on_batch_failure(self, mock_indexer, index_config):
        """Verify that _insert_ivf_bulk raises RuntimeError on batch failure."""
        # Setup Index with mocked dependencies
        mock_indexer.get_index_info.return_value = {
            "index_name": "test_index",
            "dim": 32,
            "key_id": "test_key",
            "row_count": 0,
            "search_type": "ip",
            "index_encryption": "cipher",
            "query_encryption": "plain",
            "is_loaded": True,
            "index_type": "IVF_FLAT",
            "description": "Test index",
            "ivf_detail": MagicMock(
                nlist=4,
                default_nprobe=1,
                centroids=[MagicMock(plain_vector=MagicMock(data=list(np.random.rand(32)))) for _ in range(4)],
            ),
        }
        Index._default_indexer = mock_indexer
        Index._default_key_path = "./temp/keys/none"

        with patch("pyenvector.index.index.Cipher"):
            index = Index("test_index", index_config)

            # Make _encrypt_and_insert fail on the second batch
            call_count = [0]
            original_error = ValueError("Encryption failed")

            def mock_encrypt_and_insert(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 2:
                    raise original_error
                return [call_count[0]]

            index._encrypt_and_insert = mock_encrypt_and_insert
            # Mock _knn to return cluster 0 for all vectors
            # ENCRYPTION_BATCH_SIZE is 4096, so we need > 8192 items for 2+ batches
            num_vectors = 10000
            index._knn = MagicMock(return_value=[[0]] * num_vectors)

            # Generate enough data to trigger multiple batches
            vectors = np.random.rand(num_vectors, 32).astype(np.float32)
            normalized_data = index._normalize_insert_data(vectors)

            with pytest.raises(RuntimeError, match="Batch 1 insert failed"):
                index._insert_ivf_bulk(normalized_data, None)

    def test_insert_ivf_bulk_includes_original_error(self, mock_indexer, index_config):
        """Verify that the RuntimeError includes the original error as cause."""
        # Setup Index with mocked dependencies
        mock_indexer.get_index_info.return_value = {
            "index_name": "test_index",
            "dim": 32,
            "key_id": "test_key",
            "row_count": 0,
            "search_type": "ip",
            "index_encryption": "cipher",
            "query_encryption": "plain",
            "is_loaded": True,
            "index_type": "IVF_FLAT",
            "description": "Test index",
            "ivf_detail": MagicMock(
                nlist=4,
                default_nprobe=1,
                centroids=[MagicMock(plain_vector=MagicMock(data=list(np.random.rand(32)))) for _ in range(4)],
            ),
        }
        Index._default_indexer = mock_indexer
        Index._default_key_path = "./temp/keys/none"

        with patch("pyenvector.index.index.Cipher"):
            index = Index("test_index", index_config)

            original_error = ValueError("Original cause")

            def mock_encrypt_and_insert(*args, **kwargs):
                raise original_error

            index._encrypt_and_insert = mock_encrypt_and_insert
            # Mock _knn to return cluster 0 for all vectors
            index._knn = MagicMock(return_value=[[0]] * 100)

            vectors = np.random.rand(100, 32).astype(np.float32)
            normalized_data = index._normalize_insert_data(vectors)

            with pytest.raises(RuntimeError) as exc_info:
                index._insert_ivf_bulk(normalized_data, None)

            # Verify the cause chain
            assert exc_info.value.__cause__ is original_error


###################################
# DeleteData Tests
###################################


def test_delete_calls_indexer_and_waits(monkeypatch, mock_indexer, index_config):
    """Test that Index.delete() calls delete_data and wait_for_delete_completion by default."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    mock_indexer.delete_data.return_value = "del-req-1"
    mock_indexer.wait_for_delete_completion.return_value = MagicMock()

    index = Index("test_index", index_config)
    request_id = index.delete(item_ids=[10, 20])

    assert request_id == "del-req-1"
    mock_indexer.delete_data.assert_called_once_with(index_name="test_index", item_ids=[10, 20])
    mock_indexer.wait_for_delete_completion.assert_called_once_with(
        index_name="test_index",
        request_id="del-req-1",
        timeout_s=600.0,
        poll_interval_s=1.0,
    )


def test_delete_await_completion_false_skips_wait(monkeypatch, mock_indexer, index_config):
    """Test that Index.delete(await_completion=False) returns immediately."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    mock_indexer.delete_data.return_value = "del-req-2"

    index = Index("test_index", index_config)
    request_id = index.delete(item_ids=[5], await_completion=False)

    assert request_id == "del-req-2"
    mock_indexer.delete_data.assert_called_once()
    mock_indexer.wait_for_delete_completion.assert_not_called()


def test_delete_custom_timeout(monkeypatch, mock_indexer, index_config):
    """Test that custom timeout and poll_interval are forwarded."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    mock_indexer.delete_data.return_value = "del-req-3"
    mock_indexer.wait_for_delete_completion.return_value = MagicMock()

    index = Index("test_index", index_config)
    index.delete(item_ids=[1], timeout_s=120.0, poll_interval_s=2.0)

    mock_indexer.wait_for_delete_completion.assert_called_once_with(
        index_name="test_index",
        request_id="del-req-3",
        timeout_s=120.0,
        poll_interval_s=2.0,
    )


def test_delete_not_loaded_raises(monkeypatch, mock_indexer, index_config):
    """Test that delete raises ValueError when index is not loaded."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index("test_index", index_config)
    index._is_loaded = False

    with pytest.raises(ValueError, match="Index not loaded"):
        index.delete(item_ids=[1])


def test_delete_await_completion_requires_bool(monkeypatch, mock_indexer, index_config):
    """Test that non-bool await_completion raises TypeError."""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())

    index = Index("test_index", index_config)

    with pytest.raises(TypeError, match="await_completion must be a bool"):
        index.delete(item_ids=[1], await_completion="true")
