from unittest.mock import MagicMock, patch

import pytest

from pyenvector.api.connection import Connection
from pyenvector.api.grpc import Indexer


@pytest.fixture
def mock_connection():
    mock_conn = MagicMock(spec=Connection)
    mock_conn.is_connected.return_value = True
    return mock_conn


@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_indexer_initialization(mock_stub, mock_connection):
    indexer = Indexer(mock_connection, access_token="test_token")

    assert indexer.connection == mock_connection
    assert indexer.access_token == "test_token"
    assert indexer.grpc_metadata == [("authorization", "Bearer test_token")]
    mock_stub.assert_called_once_with(mock_connection.get_channel())


def test_indexer_is_connected(mock_connection):
    indexer = Indexer(mock_connection)
    assert indexer.is_connected() is True
    mock_connection.is_connected.assert_called_once()


def test_indexer_disconnect(mock_connection):
    indexer = Indexer(mock_connection)
    indexer.disconnect()
    mock_connection.close.assert_called_once()


@patch("builtins.open", create=True)
@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_register_key(mock_stub, mock_open, mock_connection):
    mock_file = MagicMock()
    mock_open.return_value.__enter__.return_value = mock_file
    mock_file.read.side_effect = [b"chunk1", b"chunk2", b""]

    indexer = Indexer(mock_connection)
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success
    indexer.stub.register_key = MagicMock(return_value=mock_response)

    indexer.register_key("key_id", "key_path")

    indexer.stub.register_key.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_get_key_list(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success
    mock_response.key_id = ["key1", "key2"]

    indexer = Indexer(mock_connection)
    indexer.stub.get_key_list = MagicMock(return_value=mock_response)

    key_list = indexer.get_key_list()

    assert key_list == ["key1", "key2"]
    indexer.stub.get_key_list.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_get_key_info(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success

    test_key_info = {
        "key_id": "test_key_id",
        "type": "EvalKey",
        "preset": "IP",
        "eval_mode": "NONE",
        "sha256sum": "test_sha256sum",
    }

    mock_response.key_info = MagicMock()
    for key, value in test_key_info.items():
        setattr(mock_response.key_info, key, value)

    indexer = Indexer(mock_connection)
    indexer.stub.get_key_info = MagicMock(return_value=mock_response)

    key_info = indexer.get_key_info("test_key_id")

    for key, value in test_key_info.items():
        if key == "type":
            key = "key_type"
        assert key_info[key] == value

    indexer.stub.get_key_info.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.ES2EServiceStub")
def test_delete_key(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success

    indexer = Indexer(mock_connection)
    indexer.stub.delete_key = MagicMock(return_value=mock_response)

    indexer.delete_key("key_id")

    indexer.stub.delete_key.assert_called_once()
