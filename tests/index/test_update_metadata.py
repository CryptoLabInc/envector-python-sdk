"""Unit tests for Index.update_metadata (ES2-1997).

update_metadata overwrites each item's stored metadata WHOLESALE — there is no
read-modify-write merge. The AES envelope is replaced with a reversible JSON codec
so the encoded wire value can be asserted without real key material. The server
call is mocked.
"""

import json
from unittest.mock import MagicMock

import pytest

from pyenvector.errors import EnvectorValidationError
from pyenvector.index.index import Index, IndexConfig


def _summary(is_loaded=True):
    return {
        "index_name": "test_index",
        "dim": 32,
        "key_id": "test_key",
        "row_count": 3,
        "search_type": "ip",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "is_loaded": is_loaded,
        "is_key_loaded": True,
        "index_type": "FLAT",
        "description": "t",
        "created_time": "2026-01-01T00:00:00Z",
        "state": "insert/search",
        "can_load_now": True,
        "remaining_insertable_shards": 8,
        "remaining_insertable_vectors_guaranteed": 32768,
        "remaining_insertable_vectors_best_effort": 32768,
    }


@pytest.fixture
def mock_indexer():
    m = MagicMock()
    m.get_index_list.return_value = ["test_index"]
    m.get_index_summary.return_value = _summary()
    return m


def _make_index(monkeypatch, mock_indexer):
    Index._default_indexer = mock_indexer
    Index._default_key_path = "./keys"
    monkeypatch.setattr(Index, "_default_kms_client", None, raising=False)
    monkeypatch.setattr("pyenvector.index.index.Cipher", MagicMock())
    # Reversible JSON codec stand-in for the AES envelope so the encoded wire
    # value round-trips cleanly without real keys.
    monkeypatch.setattr(
        "pyenvector.index.index.encrypt_metadata",
        lambda m, key_path, *, aad=None, kek=None: json.dumps(m),
    )
    monkeypatch.setattr(
        "pyenvector.index.index.decrypt_metadata",
        lambda token, key_path, *, aad=None, kek=None: json.loads(token),
    )
    cfg = IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "flat"},
        metadata_encryption=True,
        metadata_key=b"dummy-metadata-key",
    )
    return Index("test_index", cfg)


def test_update_metadata_wholesale_replace(monkeypatch, mock_indexer):
    index = _make_index(monkeypatch, mock_indexer)
    captured = {}

    def fake_update(index_name, item_ids, data_strings, partition_name=None):
        captured["ids"] = list(item_ids)
        captured["data"] = list(data_strings)
        return {"updated_count": len(item_ids), "not_found_item_ids": []}

    mock_indexer.update_metadata.side_effect = fake_update

    report = index.update_metadata(item_ids=[10], metadata=[{"v": 2, "extra": True}])

    assert report == {"updated": [10], "skipped": []}
    assert captured["ids"] == [10]
    # No read-modify-write: stored value is exactly the supplied metadata.
    assert json.loads(captured["data"][0]) == {"v": 2, "extra": True}


def test_update_metadata_server_reports_not_found(monkeypatch, mock_indexer):
    index = _make_index(monkeypatch, mock_indexer)
    # Server reports 20 as missing/soft-deleted; it is reported as skipped, not raised.
    mock_indexer.update_metadata.return_value = {"updated_count": 1, "not_found_item_ids": [20]}

    report = index.update_metadata(item_ids=[10, 20], metadata=[{"v": 11}, {"v": 22}])

    assert report["updated"] == [10]
    assert report["skipped"] == [20]
    # Both ids are sent to the server; lenience is decided server-side.
    assert mock_indexer.update_metadata.call_args.args[1] == [10, 20]


def test_update_metadata_validation(monkeypatch, mock_indexer):
    index = _make_index(monkeypatch, mock_indexer)
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[], metadata=[])
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[1, 2], metadata=[{"a": 1}])  # length mismatch
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[1, 1], metadata=[{"a": 1}, {"b": 2}])  # duplicate
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[0], metadata=[{"a": 1}])  # non-positive
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[1], metadata="not-a-list")  # metadata not a list
    with pytest.raises(EnvectorValidationError):
        index.update_metadata(item_ids=[1], metadata=[None])  # None entry rejected
