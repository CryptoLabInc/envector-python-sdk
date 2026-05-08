from unittest.mock import ANY, MagicMock, patch

import grpc

from pyenvector.api.connection import MAX_MESSAGE_LENGTH, Connection

GRPC_OPTIONS = [
    ("grpc.max_receive_message_length", MAX_MESSAGE_LENGTH),
    ("grpc.max_send_message_length", MAX_MESSAGE_LENGTH),
]


@patch("pyenvector.api.connection.grpc.channel_ready_future")
@patch("pyenvector.api.connection.grpc.insecure_channel")
def test_connection_success(mock_insecure_channel, mock_channel_ready_future):
    # Mock successful connection
    mock_channel_ready_future.return_value.result.return_value = None

    conn = Connection("localhost:50050")

    assert conn.is_connected() is True
    mock_insecure_channel.assert_called_once_with("localhost:50050", options=GRPC_OPTIONS)
    mock_channel_ready_future.assert_called_once()


@patch("pyenvector.api.connection.grpc.channel_ready_future")
@patch("pyenvector.api.connection.grpc.insecure_channel")
def test_connection_failure(mock_insecure_channel, mock_channel_ready_future):
    # Mock connection failure
    mock_channel_ready_future.return_value.result.side_effect = grpc.FutureTimeoutError

    conn = Connection("localhost:50050")

    assert conn.is_connected() is False
    mock_insecure_channel.assert_called_once_with("localhost:50050", options=GRPC_OPTIONS)
    mock_channel_ready_future.assert_called_once()


@patch("pyenvector.api.connection.grpc.insecure_channel")
def test_get_channel(mock_insecure_channel):
    mock_channel = MagicMock()
    mock_insecure_channel.return_value = mock_channel

    conn = Connection("localhost:50050")

    assert conn.get_channel() == mock_channel


@patch("pyenvector.api.connection.grpc.insecure_channel")
def test_close(mock_insecure_channel):
    mock_channel = MagicMock()
    mock_insecure_channel.return_value = mock_channel

    conn = Connection("localhost:50050")
    conn.close()

    assert mock_channel.close.call_count >= 1


@patch("pyenvector.api.connection.grpc.channel_ready_future")
@patch("pyenvector.api.connection.grpc.secure_channel")
def test_secure_connection_success(mock_secure_channel, mock_channel_ready_future):
    # Mock successful secure connection
    mock_channel_ready_future.return_value.result.return_value = None
    mock_secure_channel.return_value = MagicMock()

    conn = Connection("localhost:50050", secure=True)

    assert conn.is_connected() is True
    mock_secure_channel.assert_called_once_with("localhost:50050", ANY, options=GRPC_OPTIONS)
    mock_channel_ready_future.assert_called_once()


@patch("pyenvector.api.connection.grpc.channel_ready_future")
@patch("pyenvector.api.connection.grpc.secure_channel")
def test_secure_connection_failure(mock_secure_channel, mock_channel_ready_future):
    # Mock secure connection failure
    mock_channel_ready_future.return_value.result.side_effect = grpc.FutureTimeoutError
    mock_secure_channel.return_value = MagicMock()

    conn = Connection("localhost:50050", secure=True)

    assert conn.is_connected() is False
    mock_secure_channel.assert_called_once_with("localhost:50050", ANY, options=GRPC_OPTIONS)
    mock_channel_ready_future.assert_called_once()
