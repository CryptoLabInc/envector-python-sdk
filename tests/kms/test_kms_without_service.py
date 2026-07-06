# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
# ========================================================================================

"""KMS tests that run without an external KMS service.

This file covers:
- pure unit tests with mocked gRPC stubs
- EnvectorClient KMS-mode coordination logic
- in-process gRPC smoke tests with stub services
"""

import importlib
from concurrent import futures
from unittest.mock import MagicMock, mock_open, patch

import grpc
import pytest

from pyenvector.client.client import EnvectorClient
from pyenvector.errors import EnvectorTransportError, KeyManagementError
from pyenvector.index.index import Index, IndexConfig
from pyenvector.api.connection import Connection
from pyenvector.kms.client import KMSClient, _check_response, _make_request_header
from pyenvector.proto_gen.v2.common import common_message_pb2 as common_pb2
from pyenvector.proto_gen.v2.common import type_pb2
from pyenvector.proto_gen.v2.kms import kms_api_pb2 as kms_pb2
from pyenvector.proto_gen.v2.kms import kms_api_pb2_grpc as kms_grpc
from pyenvector.proto_gen.v2.kms import kms_message_pb2 as kms_msg_pb2

client_module = importlib.import_module("pyenvector.client.client")


def _success_header():
    return common_pb2.ResponseHeader(return_code=type_pb2.Success)


def _fail_header(msg="something went wrong"):
    return common_pb2.ResponseHeader(return_code=type_pb2.Fail, error_message=msg)


class _FakeRpcError(grpc.RpcError):
    pass


@pytest.fixture(autouse=True)
def reset_index_defaults():
    original_key_path = Index._default_key_path
    original_index_config = Index._default_index_config
    original_kms_client = getattr(Index, "_default_kms_client", None)
    Index._default_key_path = None
    Index._default_index_config = None
    Index._default_kms_client = None
    yield
    Index._default_key_path = original_key_path
    Index._default_index_config = original_index_config
    Index._default_kms_client = original_kms_client


@pytest.fixture
def mock_connections():
    with patch("pyenvector.kms.client.Connection") as mock_conn:
        instance = mock_conn.return_value
        instance.is_connected.return_value = True
        instance.get_channel.return_value = MagicMock()
        yield mock_conn


@pytest.fixture
def kms_client(mock_connections):
    client = KMSClient(address="localhost:50061", secure=False)
    client._conn = mock_connections.return_value
    return client


class TestMakeRequestHeader:
    def test_returns_request_header(self):
        header = _make_request_header()
        assert isinstance(header, common_pb2.RequestHeader)
        assert len(header.id) > 0
        assert header.timestamp > 0


class TestCheckResponse:
    def test_success_does_not_raise(self):
        resp = MagicMock()
        resp.header = _success_header()
        _check_response(resp, "TestRPC")

    def test_failure_raises_key_management_error(self):
        resp = MagicMock()
        resp.header = _fail_header("bad key")
        with pytest.raises(KeyManagementError, match="bad key"):
            _check_response(resp, "TestRPC")


class TestKMSClientConnection:
    def test_default_connection_uses_secure_channel(self, mock_connections):
        client = KMSClient(address="localhost:50061")
        client._ensure_connected()
        mock_connections.assert_called_once_with(
            "localhost:50061",
            secure=True,
            ca_cert=None,
        )

    def test_secure_connection_uses_secure_channel(self, mock_connections):
        client = KMSClient(address="localhost:50061", secure=True)
        client._ensure_connected()
        mock_connections.assert_called_once_with(
            "localhost:50061",
            secure=True,
            ca_cert=None,
        )

    def test_secure_connection_uses_ca_cert_str(self, mock_connections):
        client = KMSClient(address="localhost:50061", secure=True, ca_cert="/tmp/ca.crt")
        client._ensure_connected()
        mock_connections.assert_called_once_with(
            "localhost:50061",
            secure=True,
            ca_cert="/tmp/ca.crt",
        )

    def test_secure_connection_uses_ca_cert_bytes(self, mock_connections):
        client = KMSClient(address="localhost:50061", secure=True, ca_cert=b"pem")
        client._ensure_connected()
        mock_connections.assert_called_once_with(
            "localhost:50061",
            secure=True,
            ca_cert=b"pem",
        )

    @patch("pyenvector.api.connection.grpc.channel_ready_future")
    @patch("pyenvector.api.connection.grpc.ssl_channel_credentials")
    @patch("pyenvector.api.connection.grpc.secure_channel")
    def test_kms_connection_uses_ca_cert_bytes(
        self,
        mock_secure_channel,
        mock_ssl_channel_credentials,
        mock_channel_ready_future,
    ):
        mock_channel_ready_future.return_value.result.return_value = None
        mock_ssl_channel_credentials.return_value = "creds"

        conn = Connection("localhost:50061", secure=True, ca_cert=b"pem")

        assert conn.is_connected() is True
        mock_ssl_channel_credentials.assert_called_once_with(root_certificates=b"pem")
        mock_secure_channel.assert_called_once()

    @patch("builtins.open", new_callable=mock_open, read_data=b"pem-file")
    @patch("pyenvector.api.connection.grpc.channel_ready_future")
    @patch("pyenvector.api.connection.grpc.ssl_channel_credentials")
    @patch("pyenvector.api.connection.grpc.secure_channel")
    def test_kms_connection_reads_ca_cert_str(
        self,
        mock_secure_channel,
        mock_ssl_channel_credentials,
        mock_channel_ready_future,
        mock_file,
    ):
        mock_channel_ready_future.return_value.result.return_value = None
        mock_ssl_channel_credentials.return_value = "creds"

        conn = Connection("localhost:50061", secure=True, ca_cert="/tmp/kms-ca.crt")

        assert conn.is_connected() is True
        mock_file.assert_called_once_with("/tmp/kms-ca.crt", "rb")
        mock_ssl_channel_credentials.assert_called_once_with(root_certificates=b"pem-file")
        mock_secure_channel.assert_called_once()

    def test_access_token_is_exposed_as_grpc_metadata(self, mock_connections):
        client = KMSClient(address="localhost:50061", access_token="kms-token")
        assert client._grpc_metadata == [("authorization", "Bearer kms-token")]

    def test_connect_failure_raises_transport_error(self, mock_connections):
        mock_connections.return_value.is_connected.return_value = False
        client = KMSClient(address="localhost:50061", secure=False)
        with pytest.raises(EnvectorTransportError, match="Cannot connect to KMS"):
            client._ensure_connected()


class TestKMSClientGenerateKey:
    def test_success(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GenerateKey.return_value = kms_pb2.GenerateKeyResponse(
                header=_success_header(),
                key_id="test-collection",
                version=1,
                status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
            )
            result = kms_client.generate_key(key_id="test-collection", metadata_encryption=False)
            request = stub.GenerateKey.call_args.args[0]
            assert request.metadata_encryption_enabled is False
            assert result == {
                "key_id": "test-collection",
                "version": 1,
                "status": "KEY_GEN_STATUS_PENDING",
            }

    def test_success_forwards_auth_metadata(self, mock_connections):
        client = KMSClient(address="localhost:50061", access_token="kms-token")
        client._conn = mock_connections.return_value
        client._keygen_stub = MagicMock()
        client._keygen_stub.GenerateKey.return_value = kms_pb2.GenerateKeyResponse(
            header=_success_header(),
            key_id="test-collection",
            version=1,
            status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
        )

        client.generate_key(key_id="test-collection")

        assert client._keygen_stub.GenerateKey.call_args.kwargs["metadata"] == [
            ("authorization", "Bearer kms-token")
        ]

    def test_forwards_preset_and_eval_mode(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GenerateKey.return_value = kms_pb2.GenerateKeyResponse(
                header=_success_header(),
                key_id="test-collection",
                version=1,
                status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
            )
            kms_client.generate_key(key_id="test-collection", preset="IP3", eval_mode="MMS32")
            request = stub.GenerateKey.call_args.args[0]
            assert request.preset == "IP3"
            assert request.eval_mode == "MMS32"

    def test_forwards_seed(self, kms_client):
        seed = bytes(range(64))
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GenerateKey.return_value = kms_pb2.GenerateKeyResponse(
                header=_success_header(),
                key_id="test-collection",
                version=1,
                status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
            )
            kms_client.generate_key(key_id="test-collection", seed=seed)
            request = stub.GenerateKey.call_args.args[0]
            assert request.seed == seed

    def test_omits_preset_and_eval_mode_when_not_provided(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GenerateKey.return_value = kms_pb2.GenerateKeyResponse(
                header=_success_header(),
                key_id="test-collection",
                version=1,
                status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
            )
            kms_client.generate_key(key_id="test-collection")
            request = stub.GenerateKey.call_args.args[0]
            assert not request.HasField("preset")
            assert not request.HasField("eval_mode")

    def test_rpc_error_raises_transport_error(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GenerateKey.side_effect = _FakeRpcError()
            with pytest.raises(EnvectorTransportError, match="GenerateKey RPC failed"):
                kms_client.generate_key(key_id="test-collection")


class TestKMSClientStatus:
    def test_get_key_status(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GetKeyStatus.return_value = kms_pb2.GetKeyStatusResponse(
                header=_success_header(),
                key_id="test-collection",
                status=kms_msg_pb2.KEY_GEN_STATUS_READY,
            )
            result = kms_client.get_key_status("test-collection")
            assert result == {"key_id": "test-collection", "status": "KEY_GEN_STATUS_READY"}

    def test_get_key_details(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.GetKeyDetails.return_value = kms_pb2.GetKeyDetailsResponse(
                header=_success_header(),
                key_id="test-collection",
                versions=[
                    kms_msg_pb2.KeyVersionRecord(
                        version=1,
                        state=kms_msg_pb2.KEY_STATE_ACTIVE,
                        key_type=kms_msg_pb2.KEY_TYPE_SECRET_KEY,
                        created_at="2026-03-29T00:00:00Z",
                        updated_at="2026-03-29T00:00:00Z",
                        actor="tester",
                    )
                ],
            )
            result = kms_client.get_key_details("test-collection")
            assert result["key_id"] == "test-collection"
            assert result["versions"] == [
                {
                    "version": 1,
                    "state": "KEY_STATE_ACTIVE",
                    "key_type": "KEY_TYPE_SECRET_KEY",
                    "created_at": "2026-03-29T00:00:00Z",
                    "updated_at": "2026-03-29T00:00:00Z",
                    "actor": "tester",
                }
            ]

    def test_wait_for_key_returns_ready(self, kms_client):
        with patch.object(
            kms_client,
            "get_key_status",
            side_effect=[
                {"key_id": "x", "status": "KEY_GEN_STATUS_PENDING"},
                {"key_id": "x", "status": "KEY_GEN_STATUS_READY"},
            ],
        ):
            result = kms_client.wait_for_key("x", timeout=1, poll_interval=0.001)
            assert result["status"] == "KEY_GEN_STATUS_READY"

    def test_wait_for_key_failed_raises(self, kms_client):
        with patch.object(
            kms_client, "get_key_status", return_value={"key_id": "x", "status": "KEY_GEN_STATUS_FAILED"}
        ):
            with pytest.raises(KeyManagementError, match="Key generation failed"):
                kms_client.wait_for_key("x", timeout=1, poll_interval=0.001)

    def test_wait_for_key_timeout(self, kms_client):
        with patch.object(
            kms_client, "get_key_status", return_value={"key_id": "x", "status": "KEY_GEN_STATUS_PENDING"}
        ):
            with pytest.raises(TimeoutError):
                kms_client.wait_for_key("x", timeout=0.01, poll_interval=0.001)


class TestKMSClientDownloads:
    def test_download_enc_key(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.DownloadKey.return_value = iter(
                [
                    kms_pb2.DownloadKeyResponse(
                        header=_success_header(),
                        key_id="key-1",
                        file_type=kms_pb2.KEY_FILE_TYPE_ENC_KEY,
                        file_name="EncKey.json",
                        content=b"enc-",
                        chunk_index=0,
                    ),
                    kms_pb2.DownloadKeyResponse(
                        header=_success_header(),
                        key_id="key-1",
                        file_type=kms_pb2.KEY_FILE_TYPE_ENC_KEY,
                        file_name="EncKey.json",
                        content=b"key",
                        chunk_index=1,
                        eof=True,
                    ),
                ]
            )
            assert kms_client.download_enc_key("key-1") == b"enc-key"

    def test_download_eval_key(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.DownloadKey.return_value = iter(
                [
                    kms_pb2.DownloadKeyResponse(
                        header=_success_header(),
                        key_id="key-1",
                        file_type=kms_pb2.KEY_FILE_TYPE_EVAL_KEY,
                        file_name="EvalKey.json",
                        content=b"eval-",
                        chunk_index=0,
                    ),
                    kms_pb2.DownloadKeyResponse(
                        header=_success_header(),
                        key_id="key-1",
                        file_type=kms_pb2.KEY_FILE_TYPE_EVAL_KEY,
                        file_name="EvalKey.json",
                        content=b"key",
                        chunk_index=1,
                        eof=True,
                    ),
                ]
            )
            assert kms_client.download_eval_key("key-1") == b"eval-key"

    def test_download_key_empty_stream_returns_empty_bytes(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.DownloadKey.return_value = iter([])
            assert kms_client.download_enc_key("key-1") == b""


class TestKMSClientTopKAndMetadata:
    def test_topk_passes_threshold_and_shard_indices(self, kms_client):
        with patch.object(kms_client, "_topk_stub") as stub:
            stub.TopK.return_value = kms_pb2.TopKResponse(
                header=_success_header(),
                results=[
                    kms_msg_pb2.TopKResult(
                        item_id="item-1",
                        score=0.95,
                        metadata_idx=type_pb2.MetadataIdx(shard_idx=10, row_idx=3),
                    )
                ],
            )
            ct = type_pb2.EVCiphertext(degree=65536, data=b"\x00" * 16)
            top_results = kms_client.topk(
                key_id="test-key-uuid",
                encrypted_scores=[ct],
                k=2,
                score_threshold=0.5,
                shard_indices=[10],
            )
            assert len(top_results) == 1
            assert top_results[0].metadata_idx.shard_idx == 10
            request = stub.TopK.call_args[0][0]
            assert request.score_threshold == pytest.approx(0.5)
            assert list(request.shard_indices) == [10]

    def test_encrypt_metadata(self, kms_client):
        with patch.object(kms_client, "_topk_stub") as stub:
            stub.EncryptMetadata.return_value = kms_pb2.EncryptMetadataResponse(
                header=_success_header(),
                encrypted_metadata=[b"a", b"b"],
            )
            assert kms_client.encrypt_metadata("key-1", ["x", "y"]) == [b"a", b"b"]

    def test_decrypt_metadata(self, kms_client):
        with patch.object(kms_client, "_topk_stub") as stub:
            stub.DecryptMetadata.return_value = kms_pb2.DecryptMetadataResponse(
                header=_success_header(),
                plaintext_metadata=["x", '{"y": 1}'],
            )
            assert kms_client.decrypt_metadata("key-1", [b"a", b"b"]) == ["x", '{"y": 1}']


class TestKMSClientAdminAndHealth:
    def test_transition_state_without_version(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.TransitionState.return_value = kms_pb2.TransitionStateResponse(header=_success_header())
            assert (
                kms_client.transition_state("key-1", new_state=kms_msg_pb2.KEY_STATE_SUSPENDED, reason="pause") is True
            )
            request = stub.TransitionState.call_args[0][0]
            assert request.key_id == "key-1"
            assert request.new_state == kms_msg_pb2.KEY_STATE_SUSPENDED
            assert request.reason == "pause"

    def test_rotate_key_uses_transition_state(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.TransitionState.return_value = kms_pb2.TransitionStateResponse(header=_success_header())
            assert kms_client.rotate_key("key-1", reason="scheduled rotation") is True
            request = stub.TransitionState.call_args[0][0]
            assert request.key_id == "key-1"
            assert request.new_state == kms_msg_pb2.KEY_STATE_ROTATING
            assert request.reason == "scheduled rotation"

    def test_suspend_key_uses_transition_state(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.TransitionState.return_value = kms_pb2.TransitionStateResponse(header=_success_header())
            assert kms_client.suspend_key("key-1", reason="pause") is True
            request = stub.TransitionState.call_args[0][0]
            assert request.new_state == kms_msg_pb2.KEY_STATE_SUSPENDED

    def test_destroy_key_uses_transition_state(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.TransitionState.return_value = kms_pb2.TransitionStateResponse(header=_success_header())
            assert kms_client.destroy_key("key-1", reason="destroy") is True
            request = stub.TransitionState.call_args[0][0]
            assert request.new_state == kms_msg_pb2.KEY_STATE_DESTROYED

    def test_transition_state_raises_if_version_specified(self, kms_client):
        with pytest.raises(NotImplementedError, match="not yet supported"):
            kms_client.transition_state(key_id="key-1", version=1, new_state=1, reason="x")

    def test_transition_state_rejects_unknown_kwargs(self, kms_client):
        with pytest.raises(TypeError, match="got an unexpected keyword argument"):
            kms_client.transition_state(key_id="key-1", new_state=1, reason="x", extra=True)

    def test_delete_key_supports_keyword_args(self, kms_client):
        with patch.object(kms_client, "_keygen_stub") as stub:
            stub.Delete.return_value = kms_pb2.DeleteResponse(header=_success_header())
            assert kms_client.delete_key(key_id="key-1", reason="cleanup") is True

    def test_delete_key_rejects_unknown_kwargs(self, kms_client):
        with pytest.raises(TypeError, match="got an unexpected keyword argument"):
            kms_client.delete_key(key_id="key-1", reason="cleanup", extra=True)

    def test_health_checks(self, kms_client):
        with (
            patch.object(kms_client, "_keygen_stub") as keygen_stub,
            patch.object(kms_client, "_topk_stub") as topk_stub,
        ):
            keygen_stub.Health.return_value = common_pb2.HeartbeatResponse(header=_success_header())
            topk_stub.Health.return_value = common_pb2.HeartbeatResponse(header=_success_header())
            assert kms_client.health_check_keygen() is True
            assert kms_client.health_check_topk() is True

    def test_health_check_topk_returns_false_on_rpc_error(self, kms_client):
        with patch.object(kms_client, "_topk_stub") as topk_stub:
            topk_stub.Health.side_effect = _FakeRpcError()
            assert kms_client.health_check_topk() is False


class _AuthFakeRpcError(grpc.RpcError):
    """RpcError with a controllable code, for exercising refresh-on-401 paths."""

    def __init__(self, code=grpc.StatusCode.UNAUTHENTICATED, details="auth failed"):
        super().__init__()
        self._code = code
        self._details = details

    def code(self):
        return self._code

    def details(self):
        return self._details


class TestKMSClientRefresh:
    def test_refreshes_token_once_on_unauthenticated(self, mock_connections):
        """Mirrors Indexer behavior: a single UNAUTHENTICATED triggers an OIDC
        refresh and a retry with the new bearer token."""
        client = KMSClient(
            address="localhost:50061",
            access_token="old",
            refresh_token="r0",
            token_endpoint="https://issuer/token",
            client_id="envector-cli",
        )
        client._conn = mock_connections.return_value
        client._keygen_stub = MagicMock()

        success_response = kms_pb2.GenerateKeyResponse(
            header=_success_header(),
            key_id="k1",
            version=1,
            status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
        )
        client._keygen_stub.GenerateKey.side_effect = [
            _AuthFakeRpcError(),
            success_response,
        ]

        refresh_response = MagicMock()
        refresh_response.read.return_value = (
            b'{"access_token":"new-token","refresh_token":"r1"}'
        )
        with patch("pyenvector.api.auth_session.urllib_request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = refresh_response
            result = client.generate_key(key_id="k1")

        assert result["key_id"] == "k1"
        assert client._keygen_stub.GenerateKey.call_count == 2
        # First call carries the original token, second call carries the refreshed one.
        first_md = client._keygen_stub.GenerateKey.call_args_list[0].kwargs["metadata"]
        second_md = client._keygen_stub.GenerateKey.call_args_list[1].kwargs["metadata"]
        assert first_md == [("authorization", "Bearer old")]
        assert second_md == [("authorization", "Bearer new-token")]
        assert client._access_token == "new-token"
        assert client._auth_session._refresh_token == "r1"

    def test_does_not_refresh_without_refresh_token(self, mock_connections):
        """Without refresh credentials, an UNAUTHENTICATED bubbles up unchanged."""
        client = KMSClient(address="localhost:50061", access_token="only-access")
        client._conn = mock_connections.return_value
        client._keygen_stub = MagicMock()
        client._keygen_stub.GenerateKey.side_effect = _AuthFakeRpcError()

        with pytest.raises(EnvectorTransportError, match="GenerateKey RPC failed"):
            client.generate_key(key_id="k1")
        assert client._keygen_stub.GenerateKey.call_count == 1


class TestSharedAuthSession:
    def test_envector_client_shares_session_with_kms_client(self):
        """EnvectorClient.init should bind the KMSClient to the indexer's
        _AuthSession instance so one refresh updates both clients."""
        from pyenvector.api.auth_session import _AuthSession
        from pyenvector.api.grpc import Indexer

        client = EnvectorClient()
        shared_session = _AuthSession(access_token="bootstrap")
        # MagicMock with spec=Indexer satisfies the EnvectorClient.indexer
        # setter's isinstance check without dragging in real gRPC channels.
        fake_indexer = MagicMock(spec=Indexer)
        fake_indexer._auth_session = shared_session
        fake_indexer.check_version_compat.return_value = None

        with patch.object(client, "init_index_config"), patch(
            "pyenvector.client.client.Index.init_connect",
            return_value=fake_indexer,
        ), patch("pyenvector.kms.client.Connection") as mock_conn:
            mock_conn.return_value.is_connected.return_value = True
            mock_conn.return_value.get_channel.return_value = MagicMock()

            client.init(
                address="localhost:50050",
                access_token="bootstrap",
                secure=False,
                key_path=None,
                key_id="key-1",
                preset="ip1",
                eval_mode="mm",
                kms_address="localhost:50061",
            )

            assert client.kms_client is not None
            assert client.kms_client._secure is True
            # Identity, not equality — sharing the same object is the only
            # coordination point so a refresh visible to one is visible to both.
            assert client.kms_client._auth_session is shared_session
            assert client.indexer._auth_session is shared_session

    def test_single_refresh_updates_both_clients(self):
        """A refresh on the shared session changes the access token observed
        by both an Indexer and a KMSClient pointed at the same session."""
        from pyenvector.api.auth_session import _AuthSession
        from pyenvector.api.grpc import Indexer

        session = _AuthSession(
            access_token="old",
            refresh_token="r0",
            token_endpoint="https://issuer/token",
            client_id="envector-cli",
        )
        mock_connection = MagicMock()
        mock_connection.is_connected.return_value = True

        with patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub"), patch(
            "pyenvector.kms.client.Connection"
        ) as mock_kms_conn:
            mock_kms_conn.return_value.is_connected.return_value = True
            indexer = Indexer.__new__(Indexer)
            indexer.connection = mock_connection
            indexer._auth_session = session

            kms_client = KMSClient(address="localhost:50061", auth_session=session)
            # Pre-refresh: both see the bootstrap token.
            assert indexer.grpc_metadata == [("authorization", "Bearer old")]
            assert kms_client._grpc_metadata == [("authorization", "Bearer old")]

            refresh_response = MagicMock()
            refresh_response.read.return_value = (
                b'{"access_token":"rotated","refresh_token":"r1"}'
            )
            with patch("pyenvector.api.auth_session.urllib_request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__.return_value = refresh_response
                # Refreshing through either client mutates the shared session.
                kms_client._refresh_access_token()
                assert mock_urlopen.call_count == 1  # single network exchange

            # Post-refresh: both clients observe the new token without a second refresh.
            assert indexer.grpc_metadata == [("authorization", "Bearer rotated")]
            assert kms_client._grpc_metadata == [("authorization", "Bearer rotated")]


class TestKMSClientLifecycle:
    def test_close_cleans_up(self, kms_client):
        kms_client._keygen_stub = MagicMock()
        kms_client._topk_stub = MagicMock()
        kms_client.close()
        assert kms_client._conn is None
        assert kms_client._keygen_stub is None
        assert kms_client._topk_stub is None

    def test_context_manager_closes_connection(self, mock_connections):
        client = KMSClient(address="localhost:50061")
        with client as ctx:
            assert ctx is client
        assert client._conn is None


class TestEnvectorClientKMSMode:
    def test_init_reuses_endpoint_access_token_for_kms_by_default(self):
        client = EnvectorClient()
        with patch.object(client, "init_connect"), patch.object(client, "init_index_config"), patch(
            "pyenvector.kms.client.Connection"
        ) as mock_conn:
            mock_conn.return_value.is_connected.return_value = True
            mock_conn.return_value.get_channel.return_value = MagicMock()

            client.init(
                address="localhost:50050",
                access_token="shared-token",
                secure=False,
                key_path=None,
                key_id="key-1",
                preset="ip1",
                eval_mode="mm",
                kms_address="localhost:50061",
            )

            assert client.kms_client is not None
            assert client.kms_client._secure is True
            assert client.kms_client._access_token == "shared-token"

    def test_init_passes_kms_ca_cert(self):
        client = EnvectorClient()
        with patch.object(client, "init_connect"), patch.object(client, "init_index_config"), patch(
            "pyenvector.kms.client.Connection"
        ) as mock_conn:
            mock_conn.return_value.is_connected.return_value = True
            mock_conn.return_value.get_channel.return_value = MagicMock()

            client.init(
                address="localhost:50050",
                access_token="shared-token",
                secure=False,
                key_path=None,
                key_id="key-1",
                preset="ip1",
                eval_mode="mm",
                kms_address="localhost:50061",
                kms_ca_cert="/tmp/kms-ca.crt",
            )

            assert client.kms_client is not None
            assert client.kms_client._ca_cert == "/tmp/kms-ca.crt"

    def test_init_allows_plaintext_kms_independent_from_endpoint_secure(self):
        client = EnvectorClient()
        with patch.object(client, "init_connect"), patch.object(client, "init_index_config"), patch(
            "pyenvector.kms.client.Connection"
        ) as mock_conn:
            mock_conn.return_value.is_connected.return_value = True
            mock_conn.return_value.get_channel.return_value = MagicMock()

            client.init(
                address="localhost:50050",
                access_token="shared-token",
                secure=True,
                key_path=None,
                key_id="key-1",
                preset="ip1",
                eval_mode="mm",
                kms_address="localhost:50061",
                kms_secure=False,
            )

            assert client.kms_client is not None
            assert client.kms_client._secure is False

    def test_duplicate_key_warns_and_reuses_existing_material(self):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._index_config = MagicMock()
        client._index_config.key_id = "dup-key"
        client._kms_client.generate_key.side_effect = KeyManagementError(
            'key "dup-key" already exists', return_code=type_pb2.Fail
        )
        client._kms_client.get_key_status.return_value = {
            "key_id": "dup-key",
            "status": "KEY_GEN_STATUS_READY",
        }
        client._sync_kms_public_keys = MagicMock()

        with pytest.warns(UserWarning, match="already exists"):
            client.generate_key()

        client._sync_kms_public_keys.assert_called_once_with("dup-key")

    def test_generate_key_forwards_seed_in_managed_mode(self):
        seed = bytes(range(64))
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._index_config = MagicMock()
        client._index_config.key_id = "seeded-key"
        client._index_config.metadata_encryption = True
        client._index_config.context_param.preset_name = "IP2"
        client._index_config.context_param.eval_mode_name = "MM32"
        client._kms_client.generate_key.return_value = {
            "key_id": "seeded-key",
            "status": "KEY_GEN_STATUS_READY",
        }
        client._sync_kms_public_keys = MagicMock()

        client.generate_key(seed=seed)

        client._kms_client.generate_key.assert_called_once_with(
            "seeded-key",
            metadata_encryption=True,
            preset="IP2",
            eval_mode="MM32",
            seed=seed,
        )
        client._sync_kms_public_keys.assert_called_once_with("seeded-key")

    def test_generate_key_raises_on_generic_fail(self):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._index_config = MagicMock()
        client._index_config.key_id = "broken-key"
        client._index_config.metadata_encryption = False
        client._kms_client.generate_key.side_effect = KeyManagementError(
            "internal kms failure", return_code=type_pb2.Fail
        )

        with pytest.raises(KeyManagementError, match="internal kms failure"):
            client.generate_key()

        client._kms_client.get_key_status.assert_not_called()

    def test_sync_kms_public_keys_redownloads_when_key_id_changes(self, monkeypatch):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        original_config = IndexConfig(
            key_id="old-key",
            use_key_stream=True,
            enc_key=b"stale-enc",
            eval_key=b"stale-eval",
        )
        original_config.deepcopy = MagicMock(wraps=original_config.deepcopy)
        client._index_config = original_config

        client._kms_client.download_enc_key.return_value = b"wrapped-enc"
        client._kms_client.download_eval_key.return_value = b"wrapped-eval"

        key_manager = MagicMock()
        key_manager.unwrap_enc_key_bytes.return_value = b"fresh-enc"
        key_manager.unwrap_eval_key_bytes.return_value = b"fresh-eval"
        monkeypatch.setattr(client_module, "KeyManager", MagicMock(return_value=key_manager))

        client._sync_kms_public_keys("new-key")

        client._kms_client.download_enc_key.assert_called_once_with("new-key")
        client._kms_client.download_eval_key.assert_called_once_with("new-key")
        original_config.deepcopy.assert_called_once_with(
            key_id="new-key",
            use_key_stream=True,
            enc_key=b"fresh-enc",
            eval_key=b"fresh-eval",
            sec_key=None,
            metadata_key=None,
        )

    def test_register_key_clears_path_mode_eval_key_cache(self):
        client = EnvectorClient()
        client._indexer = MagicMock()
        client._indexer.get_key_list.return_value = []
        client._indexer.register_key.return_value = None
        client._index_config = IndexConfig(
            key_path="./keys",
            key_id="path-key",
            preset="ip3",
            eval_mode="mm32",
        )
        client._index_config.key_param._eval_key = b"large-eval-key"

        with patch.object(client._index_config.key_param, "check_key_dir", return_value=True):
            client.register_key()

        client._indexer.register_key.assert_called_once()
        assert client._index_config.key_param._eval_key is None

    def test_ensure_kms_key_ready_downloads_when_ready(self, monkeypatch):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._kms_client.get_key_details.return_value = {"key_id": "k1", "versions": [{"version": 1}]}
        client._kms_client.get_key_status.return_value = {"key_id": "k1", "status": "KEY_GEN_STATUS_READY"}

        sync_mock = MagicMock()
        generate_mock = MagicMock()
        monkeypatch.setattr(client, "_sync_kms_public_keys", sync_mock)
        monkeypatch.setattr(client, "generate_key", generate_mock)

        client._ensure_kms_key_ready("k1")

        sync_mock.assert_called_once_with("k1")
        generate_mock.assert_not_called()
        client._kms_client.wait_for_key.assert_not_called()

    def test_ensure_kms_key_ready_waits_when_pending(self, monkeypatch):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._kms_client.get_key_details.return_value = {"key_id": "k1", "versions": [{"version": 1}]}
        client._kms_client.get_key_status.return_value = {"key_id": "k1", "status": "KEY_GEN_STATUS_PENDING"}

        sync_mock = MagicMock()
        monkeypatch.setattr(client, "_sync_kms_public_keys", sync_mock)

        client._ensure_kms_key_ready("k1")

        client._kms_client.wait_for_key.assert_called_once_with("k1")
        sync_mock.assert_called_once_with("k1")

    def test_ensure_kms_key_ready_generates_when_missing(self, monkeypatch):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._kms_client.get_key_details.return_value = {"key_id": "k1", "versions": []}

        generate_mock = MagicMock()
        monkeypatch.setattr(client, "generate_key", generate_mock)

        client._ensure_kms_key_ready("k1")

        generate_mock.assert_called_once_with("k1")
        client._kms_client.get_key_status.assert_not_called()

    def test_ensure_kms_key_ready_raises_when_failed(self):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._kms_client.get_key_details.return_value = {"key_id": "k1", "versions": [{"version": 1}]}
        client._kms_client.get_key_status.return_value = {"key_id": "k1", "status": "KEY_GEN_STATUS_FAILED"}

        with pytest.raises(KeyManagementError, match="KMS key generation failed"):
            client._ensure_kms_key_ready("k1")

    def test_init_index_config_uses_kms_ready_helper(self, monkeypatch):
        client = EnvectorClient()
        client._kms_client = MagicMock()
        client._indexer = MagicMock()
        client._indexer.get_key_list.return_value = []

        ensure_mock = MagicMock()
        register_mock = MagicMock()
        load_mock = MagicMock()
        unload_mock = MagicMock()
        generate_mock = MagicMock()
        monkeypatch.setattr(client, "_ensure_kms_key_ready", ensure_mock)
        monkeypatch.setattr(client, "register_key", register_mock)
        monkeypatch.setattr(client, "load_key", load_mock)
        monkeypatch.setattr(client, "unload_key", unload_mock)
        monkeypatch.setattr(client, "generate_key", generate_mock)

        client.init_index_config(
            index_name="test-index",
            dim=32,
            key_path=None,
            key_id="k1",
            preset="ip1",
            eval_mode="MM",
            query_encryption="plain",
            index_encryption="cipher",
            index_params={"index_type": "flat"},
            metadata_encryption=False,
            auto_key_setup=True,
        )

        ensure_mock.assert_called_once_with("k1")
        register_mock.assert_called_once()
        load_mock.assert_called_once()
        unload_mock.assert_not_called()
        generate_mock.assert_not_called()


class StubKeyManagerServicer(kms_grpc.KeyManagerServiceServicer):
    def __init__(self):
        self._jobs = {}

    def GenerateKey(self, request, context):
        self._jobs[request.key_id] = {
            "status": kms_msg_pb2.KEY_GEN_STATUS_READY,
            "metadata_encryption_enabled": request.metadata_encryption_enabled,
        }
        return kms_pb2.GenerateKeyResponse(
            header=_success_header(),
            key_id=request.key_id,
            version=1,
            status=kms_msg_pb2.KEY_GEN_STATUS_PENDING,
        )

    def GetKeyStatus(self, request, context):
        return kms_pb2.GetKeyStatusResponse(
            header=_success_header(),
            key_id=request.key_id,
            status=self._jobs.get(request.key_id, {}).get("status", kms_msg_pb2.KEY_GEN_STATUS_UNSPECIFIED),
        )

    def GetKeyDetails(self, request, context):
        if request.key_id not in self._jobs:
            return kms_pb2.GetKeyDetailsResponse(header=_fail_header("missing key"), key_id=request.key_id)
        return kms_pb2.GetKeyDetailsResponse(
            header=_success_header(),
            key_id=request.key_id,
            versions=[
                kms_msg_pb2.KeyVersionRecord(
                    version=1,
                    state=kms_msg_pb2.KEY_STATE_ACTIVE,
                    key_type=kms_msg_pb2.KEY_TYPE_SECRET_KEY,
                    created_at="2026-03-30T00:00:00Z",
                    updated_at="2026-03-30T00:00:00Z",
                )
            ],
        )

    def DownloadKey(self, request, context):
        content = b"enc-key" if request.file_type == kms_pb2.KEY_FILE_TYPE_ENC_KEY else b"eval-key"
        yield kms_pb2.DownloadKeyResponse(
            header=_success_header(),
            key_id=request.key_id,
            file_type=request.file_type,
            file_name="Key.bin",
            content=content,
            chunk_index=0,
            eof=True,
        )

    def TransitionState(self, request, context):
        return kms_pb2.TransitionStateResponse(header=_success_header())

    def Delete(self, request, context):
        self._jobs.pop(request.key_id, None)
        return kms_pb2.DeleteResponse(header=_success_header())

    def Health(self, request, context):
        return common_pb2.HeartbeatResponse(header=_success_header())


class StubTopKServicer(kms_grpc.TopKServiceServicer):
    def TopK(self, request, context):
        if request.key_id == "nonexistent-key":
            context.abort(grpc.StatusCode.NOT_FOUND, "missing key")
        shard_idx = request.shard_indices[0] if request.shard_indices else 0
        return kms_pb2.TopKResponse(
            header=_success_header(),
            results=[
                kms_msg_pb2.TopKResult(
                    item_id="item-0",
                    score=0.99,
                    metadata_idx=type_pb2.MetadataIdx(shard_idx=shard_idx, row_idx=1),
                )
            ],
        )

    def EncryptMetadata(self, request, context):
        payload = [item.encode("utf-8") for item in request.plaintext_metadata]
        return kms_pb2.EncryptMetadataResponse(header=_success_header(), encrypted_metadata=payload)

    def DecryptMetadata(self, request, context):
        payload = [item.decode("utf-8") for item in request.encrypted_metadata]
        return kms_pb2.DecryptMetadataResponse(header=_success_header(), plaintext_metadata=payload)

    def Health(self, request, context):
        return common_pb2.HeartbeatResponse(header=_success_header())


@pytest.fixture(scope="module")
def kms_stub_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    kms_grpc.add_KeyManagerServiceServicer_to_server(StubKeyManagerServicer(), server)
    kms_grpc.add_TopKServiceServicer_to_server(StubTopKServicer(), server)
    port = server.add_insecure_port("localhost:0")
    server.start()
    yield f"localhost:{port}"
    server.stop(grace=0)


@pytest.fixture
def inprocess_kms_client(kms_stub_server):
    client = KMSClient(address=kms_stub_server, secure=False)
    yield client
    client.close()


class TestKMSInProcessSmoke:
    def test_generate_key_can_disable_metadata_encryption(self, inprocess_kms_client):
        result = inprocess_kms_client.generate_key(key_id="e2e-no-metadata", metadata_encryption=False)
        assert result["key_id"] == "e2e-no-metadata"
        assert inprocess_kms_client._keygen_stub is not None

    def test_generate_wait_details_downloads_and_delete(self, inprocess_kms_client):
        result = inprocess_kms_client.generate_key(key_id="e2e-collection")
        assert result["key_id"] == "e2e-collection"
        status = inprocess_kms_client.wait_for_key("e2e-collection", timeout=1, poll_interval=0.01)
        assert status["status"] == "KEY_GEN_STATUS_READY"

        details = inprocess_kms_client.get_key_details("e2e-collection")
        assert details["versions"][0]["state"] == "KEY_STATE_ACTIVE"
        assert inprocess_kms_client.download_enc_key("e2e-collection") == b"enc-key"
        assert inprocess_kms_client.download_eval_key("e2e-collection") == b"eval-key"
        assert inprocess_kms_client.transition_state(
            "e2e-collection", new_state=kms_msg_pb2.KEY_STATE_ACTIVE, reason="activate"
        )
        assert inprocess_kms_client.delete_key("e2e-collection", "cleanup")

    def test_topk_and_metadata_rpc(self, inprocess_kms_client):
        ct = type_pb2.EVCiphertext(degree=65536, data=b"\x00" * 16)
        top_results = inprocess_kms_client.topk("key-1", [ct], k=1, shard_indices=[77])
        assert len(top_results) == 1
        assert top_results[0].metadata_idx.shard_idx == 77
        assert top_results[0].metadata_idx.row_idx == 1

        encrypted = inprocess_kms_client.encrypt_metadata("key-1", ["m1", "m2"])
        assert encrypted == [b"m1", b"m2"]
        decrypted = inprocess_kms_client.decrypt_metadata("key-1", encrypted)
        assert decrypted == ["m1", "m2"]

    def test_topk_missing_key_raises_transport_error(self, inprocess_kms_client):
        ct = type_pb2.EVCiphertext(degree=65536, data=b"\x00" * 16)
        with pytest.raises(EnvectorTransportError, match="TopK RPC failed"):
            inprocess_kms_client.topk("nonexistent-key", [ct], k=1)
