from unittest.mock import MagicMock

from pyenvector.errors import EnvectorApplicationError
from pyenvector.index.index import Index, IndexConfig


def test_index_init_does_not_auto_load(monkeypatch):
    mock_indexer = MagicMock()
    mock_indexer.get_index_list.return_value = ["test_index"]
    mock_indexer.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 0,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": False,
        "is_key_loaded": True,
        "index_type": "FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "unloaded",
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
            index_params={"index_type": "flat"},
        ),
    )

    assert index.is_loaded is False
    mock_indexer.load_index.assert_not_called()


def test_insert_refreshes_loaded_state_after_server_side_load(monkeypatch):
    mock_indexer = MagicMock()
    mock_indexer.get_index_list.return_value = ["test_index"]
    _capacity_fields = {
        "can_load_now": True,
        "remaining_insertable_shards": 8,
        "remaining_insertable_vectors_guaranteed": 32768,
        "remaining_insertable_vectors_best_effort": 32768,
    }
    _loaded_state = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 1,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
        **_capacity_fields,
    }
    mock_indexer.get_index_summary.side_effect = [
        {
            "index_name": "test_index",
            "dim": 32,
            "key_id": "test_key",
            "row_count": 0,
            "search_type": "ip",
            "index_encryption": "cipher",
            "query_encryption": "plain",
            "is_loaded": False,
            "is_key_loaded": True,
            "index_type": "FLAT",
            "description": "Test index",
            "created_time": "2026-01-01T00:00:00Z",
            "state": "unloaded",
            **_capacity_fields,
        },
        _loaded_state,  # capacity check call inside insert()
        _loaded_state,  # state refresh after insert completes
    ]

    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    cipher_mock = MagicMock()
    cipher_block_mock = MagicMock()
    cipher_block_mock.data = [MagicMock()]
    cipher_mock.encrypt_row.return_value = cipher_block_mock
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock(return_value=cipher_mock))
    monkeypatch.setattr("pyenvector.index.index.encrypt_metadata", MagicMock(return_value="encrypted_metadata"))

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
            index_params={"index_type": "flat"},
        ),
    )
    index.cipher = cipher_mock
    mock_indexer.async_persist_data_rows_batch.return_value = [1]
    mock_indexer.wait_for_inserts_searchable.return_value = MagicMock(done=True)

    result = index.insert(
        [[0.01 * i for i in range(32)]],
        ["meta"],
        request_ids=["client-ignored"],
        await_completion=True,
        use_row_insert=True,
    )

    assert result == [1]
    assert index.is_loaded is True


def test_load_retries_backend_even_when_index_is_already_loaded(monkeypatch):
    mock_indexer = MagicMock()
    mock_indexer.get_index_list.return_value = ["test_index"]
    mock_indexer.get_index_summary.return_value = {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 1,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": True,
        "is_key_loaded": True,
        "index_type": "FLAT",
        "description": "Test index",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
    }
    mock_indexer.load_index.side_effect = EnvectorApplicationError("Index already loaded: test_index")

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
            index_params={"index_type": "flat"},
        ),
    )

    out = index.load()

    assert out is index
    assert index.is_loaded is True
    mock_indexer.load_index.assert_called_once_with("test_index")
