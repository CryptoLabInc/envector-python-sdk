import importlib
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from pyenvector.api import Indexer
from pyenvector.index.index import Index, IndexConfig
from pyenvector.proto_gen import type_pb2 as envector_type_pb

ENVECTOR_UTILS_AES = importlib.import_module("pyenvector.utils.aes")


@pytest.fixture
def mock_indexer():
    mock = MagicMock(spec=Indexer)
    mock.get_index_list.return_value = ["test_index"]
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
    mock.insert_data.return_value = [1, 2]
    mock.insert_data_bulk.return_value = [1, 2]  # 추가: bulk insert mock
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
        preset="ip",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "flat"},
    )


def test_index_create_and_insert(monkeypatch, mock_indexer, index_config):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    # Patch Cipher to avoid real encryption
    cipher_mock = MagicMock()
    cipher_mock.encrypt_multiple.return_value = (
        [MagicMock(data=[MagicMock()])],  # data_chunk
        [MagicMock()],  # enc_items
    )
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    # Mock encrypt_metadata to avoid loading the actual key file
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))
    index = Index("test_index", index_config)
    assert index.index_config.index_name == "test_index"
    data = [[0.01 * i for i in range(32)], [0.02 * i for i in range(32)]]
    metadata = ["meta1", "meta2"]
    result = index.insert(data, metadata)
    assert result == [1, 2]


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


def test_insert_list_of_lists(monkeypatch, mock_indexer, index_config):
    """Test insert with list[list[float]] data type"""
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    # Create a proper CipherBlock mock
    cipher_block_mock = MagicMock()
    cipher_block_mock.num_item_list = [2]  # Mock the num_item_list attribute
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
    # Create a proper CipherBlock mock
    cipher_block_mock = MagicMock()
    cipher_block_mock.num_item_list = [2]  # Mock the num_item_list attribute
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
    # Create a proper CipherBlock mock
    cipher_block_mock = MagicMock()
    cipher_block_mock.num_item_list = [2]  # Mock the num_item_list attribute
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


@pytest.mark.parametrize(
    "method,item_ids,metadata,numitems",
    [
        ("insert_data", [11, 22], ["meta"], None),
        ("batch_insert_data", [101, 202], [["meta"]], [1]),
    ],
)
@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_indexer_insert_methods_return_item_ids(mock_stub, method, item_ids, metadata, numitems):
    connection = MagicMock()
    connection.is_connected.return_value = True
    connection.get_channel.return_value = MagicMock()

    indexer = Indexer(connection)
    response = MagicMock()
    response.header.return_code = envector_type_pb.ReturnCode.Success
    response.item_ids = item_ids

    stub_method = getattr(indexer.stub, method)
    stub_method.return_value = response

    vectors = [[0.01 * i for i in range(32)]]

    if method == "insert_data":
        result = indexer.insert_data("test-index", vectors, metadata=metadata)
    else:
        result = indexer.insert_data_bulk(
            "test-index",
            vectors,
            numitems=numitems,
            metadata=metadata,
        )

    assert result == item_ids
    stub_method.assert_called_once()
