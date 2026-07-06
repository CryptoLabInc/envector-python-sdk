# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

"""Unit tests for pyenvector.errors exception hierarchy."""

from unittest.mock import MagicMock, patch

import grpc
import pytest

from pyenvector.errors import (
    AuthError,
    DependencyError,
    EnvectorApplicationError,
    EnvectorError,
    EnvectorTimeoutError,
    EnvectorTransportError,
    EnvectorValidationError,
    InternalError,
    InvalidInputError,
    KeyManagementError,
    NotReadyError,
    ResourceLimitError,
)

# ---------------------------------------------------------------------------
# Exception hierarchy (isinstance checks)
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Verify the class hierarchy and isinstance relationships."""

    def test_all_inherit_from_envector_error(self):
        """Every SDK exception must be a subclass of EnvectorError."""
        for cls in (
            EnvectorApplicationError,
            InvalidInputError,
            AuthError,
            KeyManagementError,
            NotReadyError,
            ResourceLimitError,
            DependencyError,
            EnvectorTimeoutError,
            InternalError,
            EnvectorTransportError,
            EnvectorValidationError,
        ):
            assert issubclass(cls, EnvectorError), f"{cls.__name__} must inherit from EnvectorError"

    def test_application_error_subclasses(self):
        """Application-level error leaf classes must inherit from EnvectorApplicationError."""
        for cls in (
            InvalidInputError,
            AuthError,
            KeyManagementError,
            NotReadyError,
            ResourceLimitError,
            DependencyError,
            EnvectorTimeoutError,
            InternalError,
        ):
            assert issubclass(
                cls, EnvectorApplicationError
            ), f"{cls.__name__} must inherit from EnvectorApplicationError"

    def test_transport_error_not_application_error(self):
        assert not issubclass(EnvectorTransportError, EnvectorApplicationError)

    def test_validation_error_not_application_error(self):
        assert not issubclass(EnvectorValidationError, EnvectorApplicationError)

    def test_all_inherit_from_builtin_exception(self):
        """The entire tree ultimately inherits from builtins.Exception."""
        for cls in (
            EnvectorError,
            EnvectorApplicationError,
            EnvectorTransportError,
            EnvectorValidationError,
        ):
            assert issubclass(cls, Exception)


# ---------------------------------------------------------------------------
# B1 — EnvectorTimeoutError dual inheritance
# ---------------------------------------------------------------------------


class TestEnvectorTimeoutErrorInheritance:
    """EnvectorTimeoutError must be catchable as both EnvectorApplicationError AND builtin TimeoutError."""

    def test_subclass_of_builtin_timeout(self):
        assert issubclass(EnvectorTimeoutError, TimeoutError)

    def test_subclass_of_application_error(self):
        assert issubclass(EnvectorTimeoutError, EnvectorApplicationError)

    def test_instance_caught_by_builtin_timeout(self):
        err = EnvectorTimeoutError(message="timed out")
        with pytest.raises(TimeoutError):
            raise err

    def test_instance_caught_by_application_error(self):
        err = EnvectorTimeoutError(message="timed out")
        with pytest.raises(EnvectorApplicationError):
            raise err

    def test_instance_caught_by_envector_error(self):
        err = EnvectorTimeoutError(message="timed out")
        with pytest.raises(EnvectorError):
            raise err


# ---------------------------------------------------------------------------
# __str__() output format
# ---------------------------------------------------------------------------


class TestStrOutput:
    """Verify __str__ for various attribute combinations."""

    def test_message_only(self):
        err = EnvectorError(message="something broke")
        assert str(err) == "something broke"

    def test_message_with_action(self):
        err = EnvectorError(message="something broke", action="retry later")
        assert str(err) == "something broke | Action: retry later"

    def test_message_with_request_id(self):
        err = EnvectorError(message="fail", request_id="req-123")
        assert str(err) == "fail | Request ID: req-123"

    def test_message_with_action_and_request_id(self):
        err = EnvectorError(message="fail", action="retry", request_id="req-123")
        assert str(err) == "fail | Action: retry | Request ID: req-123"

    def test_subclass_str_format(self):
        err = InternalError(
            message="internal server error",
            return_code=2,
            retryable=False,
            action="Contact support",
            request_id="abc",
        )
        result = str(err)
        assert "internal server error" in result
        assert "Action: Contact support" in result
        assert "Request ID: abc" in result

    def test_attributes_stored(self):
        err = EnvectorError(
            message="msg",
            return_code=99,
            retryable=True,
            action="do something",
            request_id="r1",
        )
        assert err.message == "msg"
        assert err.return_code == 99
        assert err.retryable is True
        assert err.action == "do something"
        assert err.request_id == "r1"


# ---------------------------------------------------------------------------
# _to_application_error() mapping from ReturnCode
# ---------------------------------------------------------------------------


class TestToApplicationError:
    """Test Indexer._to_application_error() maps ReturnCode to typed exceptions."""

    @pytest.fixture
    def indexer(self):
        with patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub"):
            from pyenvector.api.grpc import Indexer

            mock_conn = MagicMock()
            mock_conn.is_connected.return_value = True
            return Indexer(mock_conn)

    def _make_header(self, return_code, error_message="test error", header_id="req-1"):
        header = MagicMock()
        header.return_code = return_code
        header.error_message = error_message
        header.id = header_id
        header.retryable = False
        header.action = None
        return header

    def test_invalid_input(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.InvalidInput)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, InvalidInputError)
        assert isinstance(err, EnvectorApplicationError)

    def test_no_such_index(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.NoSuchIndex)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, NotReadyError)

    def test_fail_maps_to_internal(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.Fail)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, InternalError)

    def test_unknown_error_maps_to_internal(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.UnknownError)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, InternalError)

    def test_invalid_key_url(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.InvalidKeyURL)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, KeyManagementError)

    def test_invalid_key_auth_info(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.InvalidKeyAuthInfo)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, AuthError)

    def test_failed_to_unpack_key(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.FailedToUnpackKey)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, KeyManagementError)

    def test_insufficient_disk_space(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.InsufficientDIskSpace)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, ResourceLimitError)

    def test_warning_maps_to_application_error(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.Warning)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, EnvectorApplicationError)

    def test_not_found_error(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(envector_type_pb.ReturnCode.NotFoundError)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, InvalidInputError)

    def test_unmapped_code_defaults_to_internal(self, indexer):
        """An unknown/unmapped return code should fall back to InternalError."""
        header = self._make_header(return_code=9999)
        err = indexer._to_application_error(header, "test op")
        assert isinstance(err, InternalError)

    def test_error_message_preserved(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = self._make_header(
            envector_type_pb.ReturnCode.InvalidInput,
            error_message="bad vector dim",
            header_id="req-42",
        )
        err = indexer._to_application_error(header, "insert")
        assert "bad vector dim" in str(err)
        assert err.request_id == "req-42"


class TestNonFatalWarningHandling:
    @pytest.fixture
    def indexer(self):
        with patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub"):
            from pyenvector.api.grpc import Indexer

            mock_conn = MagicMock()
            mock_conn.is_connected.return_value = True
            mock_conn.server_address = "localhost:50050"
            return Indexer(mock_conn)

    def test_warning_response_does_not_raise_and_logs_warning(self, indexer):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        header = MagicMock()
        header.return_code = envector_type_pb.ReturnCode.Warning
        header.error_message = "index already warm"
        header.id = "req-warning"

        response = MagicMock()
        response.header = header

        indexer.stub.load_index = MagicMock(return_value=response)
        with patch("pyenvector.api.grpc.logger.warning") as mock_warning:
            indexer.load_index("test_index")

        mock_warning.assert_called_once()
        assert "index already warm" in mock_warning.call_args.args[2]


# ---------------------------------------------------------------------------
# _normalize_transport_error() mapping from gRPC status codes
# ---------------------------------------------------------------------------


class TestNormalizeTransportError:
    """Test Indexer._normalize_transport_error() maps gRPC StatusCode to EnvectorTransportError."""

    @pytest.fixture
    def indexer(self):
        with patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub"):
            from pyenvector.api.grpc import Indexer

            mock_conn = MagicMock()
            mock_conn.is_connected.return_value = True
            mock_conn.server_address = "localhost:50050"
            return Indexer(mock_conn)

    def _make_rpc_error(self, code):
        # Don't use spec=grpc.RpcError — the spec blocks .code() and .details()
        # which are added by grpc._channel._InactiveRpcError at runtime.
        err = MagicMock()
        err.code.return_value = code
        err.details.return_value = "test details"
        return err

    def test_unavailable(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.UNAVAILABLE)
        result = indexer._normalize_transport_error(err, "search")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is True
        assert "UNAVAILABLE" in str(result)

    def test_deadline_exceeded(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.DEADLINE_EXCEEDED)
        result = indexer._normalize_transport_error(err, "search")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is True
        assert "DEADLINE_EXCEEDED" in str(result)

    def test_invalid_argument(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.INVALID_ARGUMENT)
        result = indexer._normalize_transport_error(err, "insert")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is False

    def test_not_found(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.NOT_FOUND)
        result = indexer._normalize_transport_error(err, "get index info")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is False

    def test_unauthenticated(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.UNAUTHENTICATED)
        result = indexer._normalize_transport_error(err, "search")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is False

    def test_permission_denied(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.PERMISSION_DENIED)
        result = indexer._normalize_transport_error(err, "search")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is False

    def test_unknown_grpc_code_defaults(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.DATA_LOSS)
        result = indexer._normalize_transport_error(err, "search")
        assert isinstance(result, EnvectorTransportError)
        assert result.retryable is False
        assert result.action == "Contact support with request ID"

    def test_request_id_preserved(self, indexer):
        err = self._make_rpc_error(grpc.StatusCode.UNAVAILABLE)
        result = indexer._normalize_transport_error(err, "search", request_id="req-xyz")
        assert result.request_id == "req-xyz"


# ---------------------------------------------------------------------------
# Log message renders without a custom formatter (no reliance on extra={})
# ---------------------------------------------------------------------------


class TestErrorLogMessageRendersFully:
    """The ERROR log line must include the actionable fields in the message body itself,
    so the default stdlib formatter (which only renders %(message)s) still surfaces them.
    Previously these fields lived only in extra={}, which is silently dropped by default."""

    @pytest.fixture
    def indexer(self):
        with patch("pyenvector.api.grpc.envector_grpc.EndpointServiceStub"):
            from pyenvector.api.grpc import Indexer

            mock_conn = MagicMock()
            mock_conn.is_connected.return_value = True
            mock_conn.server_address = "localhost:50050"
            return Indexer(mock_conn)

    def _capture_pyenvector_log(self, caplog):
        # The SDK uses stdlib logging.getLogger("pyenvector"); caplog needs to attach there.
        import logging

        caplog.set_level(logging.ERROR, logger="pyenvector")
        return caplog

    def test_application_error_log_contains_error_message_and_ids(self, indexer, caplog):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        self._capture_pyenvector_log(caplog)

        header = MagicMock()
        header.return_code = envector_type_pb.ReturnCode.NoSuchIndex
        header.error_message = "shard not loaded for uplus_20260511060525"
        header.id = "req-app-1"
        header.retryable = False
        header.action = None

        indexer._to_application_error(header, "get metadata")

        # The rendered message (post-% formatting) must include the actionable bits.
        records = [r for r in caplog.records if r.name == "pyenvector"]
        assert len(records) == 1
        rendered = records[0].getMessage()
        assert "Application error from server" in rendered
        assert "operation=get metadata" in rendered
        # return_code must render as the human-readable enum name, not the raw int.
        assert "return_code=NoSuchIndex" in rendered
        assert "return_code=3" not in rendered
        assert "shard not loaded for uplus_20260511060525" in rendered
        assert "req-app-1" in rendered

    def test_application_error_log_falls_back_to_int_for_unknown_return_code(self, indexer, caplog):
        """Future-proofing: if the server sends a ReturnCode this SDK doesn't know,
        ReturnCode.Name() raises ValueError. The helper must fall back to str()
        rather than crashing inside the error-logging path."""
        self._capture_pyenvector_log(caplog)

        header = MagicMock()
        header.return_code = 9999  # not a known enum member
        header.error_message = "future server error"
        header.id = "req-future-1"
        header.retryable = False
        header.action = None

        indexer._to_application_error(header, "get metadata")

        records = [r for r in caplog.records if r.name == "pyenvector"]
        assert len(records) == 1
        rendered = records[0].getMessage()
        assert "return_code=9999" in rendered

    def test_application_error_extra_matches_message_body(self, indexer, caplog):
        """extra={} payload must use the same return_code formatting as the message body
        (enum name), and expose the raw int separately as `return_code_value`. This keeps
        structured/JSON consumers consistent with the rendered text."""
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        self._capture_pyenvector_log(caplog)

        header = MagicMock()
        header.return_code = envector_type_pb.ReturnCode.NoSuchIndex
        header.error_message = "shard not loaded"
        header.id = "req-extra-1"
        header.retryable = False
        header.action = None

        indexer._to_application_error(header, "get metadata")

        records = [r for r in caplog.records if r.name == "pyenvector"]
        assert len(records) == 1
        record = records[0]
        assert record.return_code == "NoSuchIndex"
        assert record.return_code_value == int(envector_type_pb.ReturnCode.NoSuchIndex)
        # Message body and extra agree on the human-readable name.
        assert f"return_code={record.return_code}" in record.getMessage()

    def test_transport_error_extra_matches_message_body(self, indexer, caplog):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        self._capture_pyenvector_log(caplog)

        err = MagicMock()
        err.code.return_value = grpc.StatusCode.UNAVAILABLE
        err.details.return_value = "connection refused"

        indexer._normalize_transport_error(err, "search", request_id="req-extra-2")

        records = [r for r in caplog.records if r.name == "pyenvector"]
        assert len(records) == 1
        record = records[0]
        expected_name = envector_type_pb.ReturnCode.Name(envector_type_pb.ReturnCode.DependencyError)
        assert record.return_code == expected_name
        assert record.return_code_value == int(envector_type_pb.ReturnCode.DependencyError)
        assert f"return_code={record.return_code}" in record.getMessage()

    def test_transport_error_log_contains_grpc_code_and_request_id(self, indexer, caplog):
        from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

        self._capture_pyenvector_log(caplog)

        err = MagicMock()
        err.code.return_value = grpc.StatusCode.UNAVAILABLE
        err.details.return_value = "connection refused"

        indexer._normalize_transport_error(err, "search", request_id="req-xport-2")

        records = [r for r in caplog.records if r.name == "pyenvector"]
        assert len(records) == 1
        rendered = records[0].getMessage()
        assert "gRPC transport error" in rendered
        assert "operation=search" in rendered
        assert "grpc_code=UNAVAILABLE" in rendered
        # UNAVAILABLE maps to ReturnCode.DependencyError per the status map
        # in _get_grpc_status_map(); assert the message renders the enum name.
        expected_name = envector_type_pb.ReturnCode.Name(envector_type_pb.ReturnCode.DependencyError)
        assert f"return_code={expected_name}" in rendered
        assert "connection refused" in rendered
        assert "req-xport-2" in rendered
