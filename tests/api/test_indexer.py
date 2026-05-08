import threading
import time
from unittest.mock import MagicMock, patch

import grpc
import pytest

from pyenvector.api.connection import Connection
from pyenvector.api.grpc import Indexer, _AuthSession
from pyenvector.errors import (
    EnvectorTimeoutError,
    EnvectorTransportError,
    EnvectorValidationError,
    InternalError,
)
from pyenvector.proto_gen.v2.common import index_operation_message_pb2 as envector_op_pb2
from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb


class FakeRpcError(grpc.RpcError):
    def __init__(self, code, details="auth failed"):
        super().__init__()
        self._code = code
        self._details = details

    def code(self):
        return self._code

    def details(self):
        return self._details


@pytest.fixture
def mock_connection():
    mock_conn = MagicMock(spec=Connection)
    mock_conn.is_connected.return_value = True
    return mock_conn


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_initialization(mock_stub, mock_connection):
    indexer = Indexer(mock_connection, access_token="test_token")

    assert indexer.connection == mock_connection
    assert indexer.access_token == "test_token"
    assert indexer.grpc_metadata == [("authorization", "Bearer test_token")]
    mock_stub.assert_called_once_with(mock_connection.get_channel())


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_access_token_provider_refreshes_metadata(mock_stub, mock_connection):
    provider = MagicMock(side_effect=["token-1", "token-2"])

    indexer = Indexer(mock_connection, access_token=provider)

    assert indexer.grpc_metadata == [("authorization", "Bearer token-1")]
    assert indexer.grpc_metadata == [("authorization", "Bearer token-2")]
    assert provider.call_count == 2
    mock_stub.assert_called_once_with(mock_connection.get_channel())


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_access_token_property_resolves_live_token(mock_stub, mock_connection):
    # `access_token` is a property that returns the live token, not the input
    # form: a callable provider is invoked, and a string returns as-is.
    provider = MagicMock(return_value="live-token")
    indexer = Indexer(mock_connection, access_token=provider)

    assert indexer.access_token == "live-token"
    assert provider.call_count == 1

    indexer_str = Indexer(mock_connection, access_token="static-token")
    assert indexer_str.access_token == "static-token"


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_access_token_provider_failure_raises_validation_error(mock_stub, mock_connection):
    indexer = Indexer(mock_connection, access_token=MagicMock(side_effect=RuntimeError("refresh failed")))

    with pytest.raises(EnvectorValidationError, match="access_token provider failed: refresh failed"):
        _ = indexer.grpc_metadata


@patch("pyenvector.api.grpc.urllib_request.urlopen")
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_refresh_access_token_updates_metadata(mock_stub, mock_urlopen, mock_connection):
    refresh_response = MagicMock()
    refresh_response.read.return_value = b'{"access_token":"new-token","refresh_token":"new-refresh"}'
    mock_urlopen.return_value.__enter__.return_value = refresh_response

    indexer = Indexer(
        mock_connection,
        access_token="old-token",
        refresh_token="refresh-token",
        token_endpoint="https://issuer/token",
        client_id="envector-cli",
        client_secret="secret",
    )

    assert indexer._refresh_access_token() is True
    assert indexer.grpc_metadata == [("authorization", "Bearer new-token")]


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_indexer_rejects_callable_access_token_with_refresh_token(mock_stub, mock_connection):
    with pytest.raises(EnvectorValidationError, match="callable cannot be combined with refresh_token"):
        Indexer(
            mock_connection,
            access_token=lambda: "x",
            refresh_token="r",
            token_endpoint="https://issuer/token",
            client_id="envector-cli",
        )


@patch("pyenvector.api.grpc.urllib_request.urlopen")
def test_auth_session_concurrent_refresh_coalesces_to_single_post(mock_urlopen):
    call_count = {"n": 0}
    inside_urlopen = threading.Event()
    release_urlopen = threading.Event()

    def fake_urlopen(*args, **kwargs):
        call_count["n"] += 1
        inside_urlopen.set()
        release_urlopen.wait(timeout=5)
        response = MagicMock()
        response.read.return_value = b'{"access_token":"refreshed","refresh_token":"rotated"}'
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        return response

    mock_urlopen.side_effect = fake_urlopen

    session = _AuthSession(
        access_token="old",
        refresh_token="r0",
        token_endpoint="https://issuer/token",
        client_id="envector-cli",
    )

    results = {}

    def worker(key):
        results[key] = session.refresh_access_token()

    t1 = threading.Thread(target=worker, args=("t1",))
    t2 = threading.Thread(target=worker, args=("t2",))
    t1.start()
    assert inside_urlopen.wait(timeout=5)
    t2.start()
    # Wait until t2 is parked on the lock (has snapshotted, now blocked).
    time.sleep(0.1)
    release_urlopen.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert call_count["n"] == 1
    assert results["t1"] == "refreshed"
    assert results["t2"] == "refreshed"
    assert session._refresh_token == "rotated"


@patch.dict("os.environ", {"ES2_GRPC_HEALTH_CHECK": "0"})
@patch("pyenvector.api.grpc.Connection")
@patch("pyenvector.api.grpc.urllib_request.urlopen")
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_connect_bootstrap_propagates_rotated_refresh_token(
    mock_stub, mock_urlopen, mock_connection_cls
):
    mock_conn = MagicMock()
    mock_conn.is_connected.return_value = True
    mock_connection_cls.return_value = mock_conn

    refresh_response = MagicMock()
    refresh_response.read.return_value = (
        b'{"access_token":"bootstrap-access","refresh_token":"rotated-refresh"}'
    )
    mock_urlopen.return_value.__enter__.return_value = refresh_response

    indexer = Indexer.connect(
        address="localhost:1",
        refresh_token="original-refresh",
        client_id="envector-cli",
        token_endpoint="https://issuer/token",
    )

    assert indexer._auth_session._refresh_token == "rotated-refresh"
    assert indexer.grpc_metadata == [("authorization", "Bearer bootstrap-access")]


def test_indexer_is_connected(mock_connection):
    indexer = Indexer(mock_connection)
    assert indexer.is_connected() is True
    mock_connection.is_connected.assert_called_once()


def test_indexer_disconnect(mock_connection):
    indexer = Indexer(mock_connection)
    indexer.disconnect()
    mock_connection.close.assert_called_once()


@patch("builtins.open", create=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_register_key(mock_stub, mock_open, mock_connection):
    mock_file = MagicMock()
    mock_open.return_value.__enter__.return_value = mock_file
    mock_file.read.side_effect = [b"chunk1", b"chunk2", b""]

    indexer = Indexer(mock_connection)
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success
    indexer.stub.register_key = MagicMock(return_value=mock_response)

    key_payload = b"chunk1chunk2"
    indexer.register_key("key_id", key_payload)

    indexer.stub.register_key.assert_called_once()
    request_iter = indexer.stub.register_key.call_args.args[0]
    requests = list(request_iter)
    assert requests
    assert sum(len(req.key.value) for req in requests) == len(key_payload)
    assert all(req.total_size == len(key_payload) for req in requests)


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_key_list(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success
    mock_response.key_id = ["key1", "key2"]

    indexer = Indexer(mock_connection)
    indexer.stub.get_key_list = MagicMock(return_value=mock_response)

    key_list = indexer.get_key_list()

    assert key_list == ["key1", "key2"]
    indexer.stub.get_key_list.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
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


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_summary(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.index_summary = MagicMock()
    mock_response.index_summary.index_name = "test_index"
    mock_response.index_summary.dim = 128
    mock_response.index_summary.row_count = 42
    mock_response.index_summary.saved_row_count = 42
    mock_response.index_summary.search_type = envector_type_pb.SearchType.IPOnly
    mock_response.index_summary.key_id = "test_key_id"
    mock_response.index_summary.index_encryption = "cipher"
    mock_response.index_summary.query_encryption = "plain"
    mock_response.index_summary.metadata_encryption = True
    mock_response.index_summary.description = "summary description"
    mock_response.index_summary.created_time = "2026-03-24T00:00:00Z"
    mock_response.index_summary.is_loaded = True
    mock_response.index_summary.is_key_loaded = False
    mock_response.index_summary.index_type = envector_type_pb.IndexType.FLAT
    mock_response.index_summary.can_load_now = True
    mock_response.index_summary.remaining_insertable_shards = 3
    mock_response.index_summary.remaining_insertable_vectors_guaranteed = 1200
    mock_response.index_summary.remaining_insertable_vectors_best_effort = 1800

    indexer = Indexer(mock_connection)
    indexer.stub.get_index_summary = MagicMock(return_value=mock_response)

    summary = indexer.get_index_summary("test_index")

    assert summary == {
        "index_name": "test_index",
        "dim": 128,
        "row_count": 42,
        "saved_row_count": 42,
        "search_type": "IPOnly",
        "key_id": "test_key_id",
        "index_encryption": "cipher",
        "query_encryption": "plain",
        "metadata_encryption": True,
        "description": "summary description",
        "created_time": "2026-03-24T00:00:00Z",
        "is_loaded": True,
        "is_key_loaded": False,
        "index_type": "FLAT",
        "state": "unavailable (load key)",
        "can_load_now": True,
        "remaining_insertable_shards": 3,
        "remaining_insertable_vectors_guaranteed": 1200,
        "remaining_insertable_vectors_best_effort": 1800,
    }

    indexer.stub.get_index_summary.assert_called_once()
    req = indexer.stub.get_index_summary.call_args[0][0]
    assert req.header.type == envector_type_pb.MessageType.GetIndexSummary
    assert req.index_name == "test_index"


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_clone_index(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.target_index_name = "target-index"

    indexer = Indexer(mock_connection)
    indexer.stub.clone_index = MagicMock(return_value=mock_response)

    result = indexer.clone_index("source-index", "target-index")

    assert result == {
        "source_index_name": "source-index",
        "target_index_name": "target-index",
    }
    indexer.stub.clone_index.assert_called_once()
    req = indexer.stub.clone_index.call_args[0][0]
    assert req.header.type == envector_type_pb.MessageType.CloneIndex
    assert req.source_index_name == "source-index"
    assert req.target_index_name == "target-index"


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_key(mock_stub, mock_connection):
    mock_response = MagicMock()
    mock_response.header.return_code = 1  # Success

    indexer = Indexer(mock_connection)
    indexer.stub.delete_key = MagicMock(return_value=mock_response)

    indexer.delete_key("key_id")

    indexer.stub.delete_key.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status(mock_stub, mock_connection):
    mock_response = envector_op_pb2.GetIndexOperationStatusResponse()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.request_id = "op-1"
    mock_response.operation_type = envector_type_pb.IndexOperationType.INSERT
    mock_response.total_row_count = 10
    mock_response.searchable_row_count = 10
    mock_response.done = True

    indexer = Indexer(mock_connection)
    indexer.stub.get_index_operation_status = MagicMock(return_value=mock_response)

    res = indexer.get_index_operation_status(index_name="idx", request_id="op-1")
    assert res.done is True

    indexer.stub.get_index_operation_status.assert_called_once()
    req = indexer.stub.get_index_operation_status.call_args[0][0]
    assert req.header.type == envector_type_pb.MessageType.GetIndexOperationStatus
    assert req.index_name == "idx"
    assert req.request_id == "op-1"
    assert req.operation_type == envector_type_pb.IndexOperationType.INSERT


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status_uses_latest_provider_token(mock_stub, mock_connection):
    mock_response = envector_op_pb2.GetIndexOperationStatusResponse()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.request_id = "op-1"
    mock_response.operation_type = envector_type_pb.IndexOperationType.INSERT
    mock_response.total_row_count = 10
    mock_response.searchable_row_count = 10
    mock_response.done = True

    provider = MagicMock(return_value="renewed-token")
    indexer = Indexer(mock_connection, access_token=provider)
    indexer.stub.get_index_operation_status = MagicMock(return_value=mock_response)

    res = indexer.get_index_operation_status(index_name="idx", request_id="op-1")
    assert res.done is True
    assert provider.call_count == 1
    assert indexer.stub.get_index_operation_status.call_args.kwargs["metadata"] == [
        ("authorization", "Bearer renewed-token")
    ]


@patch("pyenvector.api.grpc.urllib_request.urlopen")
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status_refreshes_after_unauthenticated(mock_stub, mock_urlopen, mock_connection):
    refresh_response = MagicMock()
    refresh_response.read.return_value = b'{"access_token":"refreshed-token","refresh_token":"refreshed-refresh"}'
    mock_urlopen.return_value.__enter__.return_value = refresh_response

    mock_response = envector_op_pb2.GetIndexOperationStatusResponse()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.request_id = "op-1"
    mock_response.operation_type = envector_type_pb.IndexOperationType.INSERT
    mock_response.total_row_count = 10
    mock_response.searchable_row_count = 10
    mock_response.done = True

    indexer = Indexer(
        mock_connection,
        access_token="expired-token",
        refresh_token="refresh-token",
        token_endpoint="https://issuer/token",
        client_id="envector-cli",
    )
    indexer.stub.get_index_operation_status = MagicMock(
        side_effect=[FakeRpcError(grpc.StatusCode.UNAUTHENTICATED), mock_response]
    )

    res = indexer.get_index_operation_status(index_name="idx", request_id="op-1")

    assert res.done is True
    assert indexer.stub.get_index_operation_status.call_count == 2
    first_call = indexer.stub.get_index_operation_status.call_args_list[0]
    second_call = indexer.stub.get_index_operation_status.call_args_list[1]
    assert first_call.kwargs["metadata"] == [("authorization", "Bearer expired-token")]
    assert second_call.kwargs["metadata"] == [("authorization", "Bearer refreshed-token")]


@patch("pyenvector.api.grpc.urllib_request.urlopen")
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status_raises_when_unauth_persists_after_refresh(
    mock_stub, mock_urlopen, mock_connection
):
    # Regression guard for the `attempt == 0` retry cap: a successful refresh
    # followed by another UNAUTHENTICATED must surface as EnvectorTransportError,
    # not loop forever.
    refresh_response = MagicMock()
    refresh_response.read.return_value = b'{"access_token":"refreshed-token","refresh_token":"refreshed-refresh"}'
    mock_urlopen.return_value.__enter__.return_value = refresh_response

    indexer = Indexer(
        mock_connection,
        access_token="expired-token",
        refresh_token="refresh-token",
        token_endpoint="https://issuer/token",
        client_id="envector-cli",
    )
    indexer.stub.get_index_operation_status = MagicMock(
        side_effect=[
            FakeRpcError(grpc.StatusCode.UNAUTHENTICATED),
            FakeRpcError(grpc.StatusCode.UNAUTHENTICATED),
        ]
    )

    with pytest.raises(EnvectorTransportError):
        indexer.get_index_operation_status(index_name="idx", request_id="op-1")

    assert indexer.stub.get_index_operation_status.call_count == 2


@patch("pyenvector.api.grpc.urllib_request.urlopen")
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_unary_with_refresh_chains_refresh_failure_to_original_rpc_error(
    mock_stub, mock_urlopen, mock_connection
):
    # When the refresh I/O itself fails, the surfaced EnvectorTransportError
    # must keep the originating UNAUTHENTICATED RpcError as its __cause__ so
    # operators can still see the trace that triggered the refresh.
    import urllib.error as urllib_error

    mock_urlopen.side_effect = urllib_error.URLError("idp down")

    indexer = Indexer(
        mock_connection,
        access_token="expired-token",
        refresh_token="refresh-token",
        token_endpoint="https://issuer/token",
        client_id="envector-cli",
    )
    rpc_err = FakeRpcError(grpc.StatusCode.UNAUTHENTICATED)
    indexer.stub.get_index_operation_status = MagicMock(side_effect=rpc_err)

    with pytest.raises(EnvectorTransportError) as excinfo:
        indexer.get_index_operation_status(index_name="idx", request_id="op-1")

    assert excinfo.value.__cause__ is rpc_err
    assert indexer.stub.get_index_operation_status.call_count == 1


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_insert_searchable(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.return_value = 0.0

    indexer = Indexer(mock_connection)
    resp1 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGE_PENDING,
    )
    resp2 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=10,
        done=True,
        state=envector_op_pb2.SEARCHABLE,
    )
    indexer.get_index_operation_status = MagicMock(side_effect=[resp1, resp2])

    out = indexer.wait_for_insert_searchable(
        index_name="idx",
        request_id="op-1",
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out is resp2
    assert indexer.get_index_operation_status.call_count == 2
    mock_sleep.assert_called_once()


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_insert_searchable_timeout(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    # deadline = 0.0 + 1.0
    # first check returns 0.5 (keep waiting), second check returns 2.0 (timeout)
    mock_monotonic.side_effect = [0.0, 0.5, 2.0]

    indexer = Indexer(mock_connection)
    resp = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGE_PENDING,
    )
    indexer.get_index_operation_status = MagicMock(return_value=resp)

    with pytest.raises(TimeoutError, match="Timed out waiting for index operation state SEARCHABLE"):
        indexer.wait_for_insert_searchable(
            index_name="idx",
            request_id="op-1",
            timeout_s=1.0,
            poll_interval_s=0.01,
        )

    assert indexer.get_index_operation_status.call_count == 2
    mock_sleep.assert_called_once()


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_insert_persist_completed(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.return_value = 0.0

    indexer = Indexer(mock_connection)
    resp1 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.SPLITTING,
    )
    resp2 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.SPLIT_COMPLETED,
    )
    indexer.get_index_operation_status = MagicMock(side_effect=[resp1, resp2])

    out = indexer.wait_for_insert_persist_completed(
        index_name="idx",
        request_id="op-1",
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out == resp2
    assert indexer.get_index_operation_status.call_count == 2
    mock_sleep.assert_called_once()


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_merge_complete_merged_saved(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.return_value = 0.0

    indexer = Indexer(mock_connection)
    resp1 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGING,
    )
    resp2 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGED_SAVED,
    )
    indexer.get_index_operation_status = MagicMock(side_effect=[resp1, resp2])

    out = indexer.wait_for_merge_complete(
        index_name="idx",
        request_id="op-1",
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out == resp2
    assert indexer.get_index_operation_status.call_count == 2
    mock_sleep.assert_called_once()


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_index_operations_state_accepts_later_stage(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.return_value = 0.0

    indexer = Indexer(mock_connection)
    resp = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGE_PENDING,
    )
    indexer.get_index_operation_status = MagicMock(return_value=resp)

    out = indexer.wait_for_index_operations_state(
        index_name="idx",
        request_ids=["op-1"],
        target_state=envector_op_pb2.SPLIT_COMPLETED,
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out == [resp]
    indexer.get_index_operation_status.assert_called_once()
    mock_sleep.assert_not_called()


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_index_operations_state_waits_request_ids_sequentially(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.side_effect = [0.0, 0.0, 0.0, 0.1, 0.1, 0.2]

    indexer = Indexer(mock_connection)
    resp1_pending = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.SPLITTING,
    )
    resp1_done = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.SPLIT_COMPLETED,
    )
    resp2_done = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.SPLIT_COMPLETED,
    )
    indexer.get_index_operation_status = MagicMock(side_effect=[resp1_pending, resp1_done, resp2_done])

    out = indexer.wait_for_index_operations_state(
        index_name="idx",
        request_ids=["op-1", "op-2"],
        target_state=envector_op_pb2.SPLIT_COMPLETED,
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out == [resp1_done, resp2_done]
    assert [call.kwargs["request_id"] for call in indexer.get_index_operation_status.call_args_list] == [
        "op-1",
        "op-1",
        "op-2",
    ]
    mock_sleep.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_index_operation_state_failed_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)
    resp = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=10,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.FAILED,
    )
    indexer.get_index_operation_status = MagicMock(return_value=resp)

    with pytest.raises(InternalError, match="Index operation failed"):
        indexer.wait_for_index_operation_state(
            index_name="idx",
            request_id="op-1",
            target_state=envector_op_pb2.SEARCHABLE,
            timeout_s=10,
            poll_interval_s=0.01,
        )


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_index_operation_state_invalid_target_state_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="target_state must be a valid IndexOperationState value"):
        indexer.wait_for_index_operation_state(
            index_name="idx",
            request_id="op-1",
            target_state=9999,
            timeout_s=10,
            poll_interval_s=0.01,
        )


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_insert_data_rows_batch_out_request_id_captured(mock_stub, mock_connection):
    """Test that server-generated request_id from response.header.id is captured in out_request_id."""
    indexer = Indexer(mock_connection)
    server_generated_request_id = "server-gen-req-123"

    def fake_persist_rows(request_iterator, grpc_metadata=None, **kwargs):
        # Consume the request iterator
        for _ in request_iterator:
            pass

        resp = MagicMock()
        resp.header.return_code = envector_type_pb.ReturnCode.Success
        resp.header.id = server_generated_request_id
        resp.item_ids = [1, 2]
        return resp

    indexer.stub.persist_rows = MagicMock(side_effect=fake_persist_rows)

    out_request_ids = []
    out = indexer.insert_data_rows_batch(
        index_name="idx",
        enc_vecs=[b"abc", b"def"],
        metadata_list=["m1", "m2"],
        out_request_id=out_request_ids,
    )
    assert out == [1, 2]
    assert out_request_ids == [server_generated_request_id]
    indexer.stub.persist_rows.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_insert_data_rows_batch_length_mismatch_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="metadata_list length must match enc_vecs length"):
        indexer.insert_data_rows_batch(
            index_name="idx",
            enc_vecs=[b"abc", b"def"],
            metadata_list=["m1"],
        )

    with pytest.raises(EnvectorValidationError, match="cluster_ids length must match enc_vecs length"):
        indexer.insert_data_rows_batch(
            index_name="idx",
            enc_vecs=[b"abc", b"def"],
            metadata_list=["m1", "m2"],
            cluster_ids=[1],
        )


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_insert_data_bulk_uses_persist_batch(mock_stub, mock_connection, monkeypatch):
    indexer = Indexer(mock_connection)
    server_generated_request_id = "split-batch-req-123"
    monkeypatch.setattr("pyenvector.api.grpc.evi.Query.serializeTo", MagicMock(return_value=b"serialized-query"))

    def fake_persist_batch(request_iterator, grpc_metadata=None, **kwargs):
        for _ in request_iterator:
            pass

        resp = MagicMock()
        resp.header.return_code = envector_type_pb.ReturnCode.Success
        resp.header.id = server_generated_request_id
        resp.item_ids = [101, 202]
        return resp

    indexer.stub.persist_batch = MagicMock(side_effect=fake_persist_batch)

    out_request_ids = []
    out = indexer.insert_data_bulk(
        index_name="idx",
        enc_vec=[MagicMock(), MagicMock()],
        numitems=[1, 1],
        metadata=[["m1"], ["m2"]],
        out_request_id=out_request_ids,
    )

    assert out == [101, 202]
    assert out_request_ids == [server_generated_request_id]
    indexer.stub.persist_batch.assert_called_once()


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_async_persist_data_bulk_accepts_scalar_centroid_idx(mock_stub, mock_connection, monkeypatch):
    indexer = Indexer(mock_connection)
    monkeypatch.setenv("ENVECTOR_SAFE_MEMORY", "0")
    monkeypatch.setattr("pyenvector.api.grpc.evi.Query.serializeTo", MagicMock(return_value=b"serialized-query"))

    def fake_persist_batch(request_iterator, grpc_metadata=None, **kwargs):
        request = next(iter(request_iterator))
        assert list(request.cluster_ids) == [7]

        resp = MagicMock()
        resp.header.return_code = envector_type_pb.ReturnCode.Success
        resp.header.id = "split-batch-req-123"
        resp.item_ids = [101]
        return resp

    indexer.stub.persist_batch = MagicMock(side_effect=fake_persist_batch)

    out = indexer.async_persist_data_bulk(
        index_name="idx",
        enc_vec=[MagicMock()],
        numitems=[1],
        metadata=[["m1"]],
        centroid_idx=7,
    )

    assert out == [101]


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_async_persist_data_bulk_sends_cluster_ids_only_once_across_chunks(mock_stub, mock_connection, monkeypatch):
    indexer = Indexer(mock_connection)
    monkeypatch.setenv("ENVECTOR_SAFE_MEMORY", "0")
    monkeypatch.setattr("pyenvector.api.grpc.evi.Query.serializeTo", MagicMock(return_value=b"abcd"))
    monkeypatch.setattr("pyenvector.api.grpc.CHUNK_SIZE_257MB", 2)

    def fake_persist_batch(request_iterator, grpc_metadata=None, **kwargs):
        requests = list(request_iterator)
        assert len(requests) == 2
        assert list(requests[0].cluster_ids) == [7]
        assert list(requests[1].cluster_ids) == []

        resp = MagicMock()
        resp.header.return_code = envector_type_pb.ReturnCode.Success
        resp.header.id = "split-batch-req-123"
        resp.item_ids = [101]
        return resp

    indexer.stub.persist_batch = MagicMock(side_effect=fake_persist_batch)

    out = indexer.async_persist_data_bulk(
        index_name="idx",
        enc_vec=[MagicMock()],
        numitems=[1],
        metadata=[["m1"]],
        centroid_idx=7,
    )

    assert out == [101]


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_async_merge_by_request_ids_returns_merge_request_id(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)
    merge_request_id = "merge-req-123"

    response = MagicMock()
    response.header.return_code = envector_type_pb.ReturnCode.Success
    response.header.id = merge_request_id
    indexer.stub.merge_by_request_ids = MagicMock(return_value=response)

    out = indexer.async_merge_by_request_ids("idx", ["split-1", "split-2"])

    assert out == merge_request_id
    indexer.stub.merge_by_request_ids.assert_called_once()
    req = indexer.stub.merge_by_request_ids.call_args[0][0]
    assert req.header.type == envector_type_pb.MessageType.MergeByRequestIds
    assert req.index_name == "idx"
    assert list(req.request_ids) == ["split-1", "split-2"]


###################################
# DeleteData Tests
###################################


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_sends_correct_request(mock_stub, mock_connection):
    """Test that delete_data constructs the correct proto request and returns request_id."""
    indexer = Indexer(mock_connection)
    server_request_id = "delete-req-123"

    response = MagicMock()
    response.header.return_code = envector_type_pb.ReturnCode.Success
    response.header.id = server_request_id
    indexer.stub.delete_data = MagicMock(return_value=response)

    out = indexer.delete_data(index_name="idx", item_ids=[10, 20, 30])

    assert out == server_request_id
    indexer.stub.delete_data.assert_called_once()
    req = indexer.stub.delete_data.call_args[0][0]
    assert req.header.type == envector_type_pb.MessageType.DeleteData
    assert req.index_name == "idx"
    assert list(req.item_ids) == [10, 20, 30]


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_empty_item_ids_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="item_ids must be non-empty"):
        indexer.delete_data(index_name="idx", item_ids=[])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_empty_index_name_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="index_name must be non-empty"):
        indexer.delete_data(index_name="", item_ids=[1])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_non_positive_item_ids_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="positive integers"):
        indexer.delete_data(index_name="idx", item_ids=[0, 1])

    with pytest.raises(EnvectorValidationError, match="positive integers"):
        indexer.delete_data(index_name="idx", item_ids=[-1, 2])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_duplicate_item_ids_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="duplicates"):
        indexer.delete_data(index_name="idx", item_ids=[1, 2, 1])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_non_int_item_ids_raises(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="int values"):
        indexer.delete_data(index_name="idx", item_ids=[1.0, 2.0])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_grpc_error_raises_transport_error(mock_stub, mock_connection):
    import grpc

    indexer = Indexer(mock_connection)
    rpc_error = grpc.RpcError()
    rpc_error.code = MagicMock(return_value=grpc.StatusCode.UNAVAILABLE)
    rpc_error.details = MagicMock(return_value="server down")
    indexer.stub.delete_data = MagicMock(side_effect=rpc_error)

    with pytest.raises(Exception):
        indexer.delete_data(index_name="idx", item_ids=[1, 2])


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_delete_data_server_error_raises_application_error(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    response = MagicMock()
    response.header.return_code = envector_type_pb.ReturnCode.Fail
    response.header.error_message = "item not found"
    response.header.id = "req-1"
    indexer.stub.delete_data = MagicMock(return_value=response)

    with pytest.raises(Exception):
        indexer.delete_data(index_name="idx", item_ids=[1])


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_delete_completion_polls_with_delete_type(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    """Test that wait_for_delete_completion polls with operation_type=DELETE."""
    mock_monotonic.return_value = 0.0

    indexer = Indexer(mock_connection)
    resp1 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=0,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGE_PENDING,
    )
    resp2 = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=0,
        searchable_row_count=0,
        done=True,
        state=envector_op_pb2.SEARCHABLE,
    )
    indexer.get_index_operation_status = MagicMock(side_effect=[resp1, resp2])

    out = indexer.wait_for_delete_completion(
        index_name="idx",
        request_id="del-1",
        timeout_s=10,
        poll_interval_s=0.01,
    )

    assert out is resp2
    assert indexer.get_index_operation_status.call_count == 2
    # Verify operation_type=DELETE is passed
    for call_args in indexer.get_index_operation_status.call_args_list:
        assert call_args.kwargs.get("operation_type") == "DELETE" or call_args[1].get("operation_type") == "DELETE"


@patch("pyenvector.api.grpc.time.sleep", autospec=True)
@patch("pyenvector.api.grpc.time.monotonic", autospec=True)
@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_wait_for_delete_completion_timeout(mock_stub, mock_monotonic, mock_sleep, mock_connection):
    mock_monotonic.side_effect = [0.0, 0.5, 2.0]

    indexer = Indexer(mock_connection)
    resp = envector_op_pb2.GetIndexOperationStatusResponse(
        total_row_count=0,
        searchable_row_count=0,
        done=False,
        state=envector_op_pb2.MERGING,
    )
    indexer.get_index_operation_status = MagicMock(return_value=resp)

    with pytest.raises(EnvectorTimeoutError, match="Timed out waiting for index operation state SEARCHABLE"):
        indexer.wait_for_delete_completion(
            index_name="idx",
            request_id="del-1",
            timeout_s=1.0,
            poll_interval_s=0.01,
        )


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status_accepts_delete_type(mock_stub, mock_connection):
    """Test that get_index_operation_status accepts operation_type=DELETE."""
    mock_response = envector_op_pb2.GetIndexOperationStatusResponse()
    mock_response.header.return_code = envector_type_pb.ReturnCode.Success
    mock_response.done = False
    mock_response.state = envector_op_pb2.MERGE_PENDING

    indexer = Indexer(mock_connection)
    indexer.stub.get_index_operation_status = MagicMock(return_value=mock_response)

    res = indexer.get_index_operation_status(index_name="idx", request_id="del-1", operation_type="DELETE")

    req = indexer.stub.get_index_operation_status.call_args[0][0]
    assert req.operation_type == envector_type_pb.IndexOperationType.DELETE


@patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub")
def test_get_index_operation_status_rejects_unsupported_type(mock_stub, mock_connection):
    indexer = Indexer(mock_connection)

    with pytest.raises(EnvectorValidationError, match="operation_type must be a valid IndexOperationType name"):
        indexer.get_index_operation_status(index_name="idx", request_id="op-1", operation_type="SCAN")
