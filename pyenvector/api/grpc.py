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

import logging as _stdlib_logging
import os
import secrets
import time
from typing import Any, List, Optional, Sequence, Tuple, Union

import evi
import grpc
import numpy as np

from pyenvector.api.auth_session import (
    AccessTokenInput,
    AccessTokenProvider,
    _AuthSession,
    build_auth_metadata,
    is_auth_return_code,
    is_auth_rpc_error,
    resolve_access_token,
)
from pyenvector.api.connection import Connection
from pyenvector.crypto import CipherBlock
from pyenvector.errors import (
    AuthError,
    DependencyError,
    EnvectorApplicationError,
    EnvectorTimeoutError,
    EnvectorTransportError,
    EnvectorValidationError,
    InternalError,
    InvalidInputError,
    KeyManagementError,
    NotReadyError,
    ResourceLimitError,
)
from pyenvector.helpers import CHUNK_SIZE_1MB, CHUNK_SIZE_257MB
from pyenvector.proto_gen.v2.common import index_operation_message_pb2 as envector_op_pb2
from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb
from pyenvector.proto_gen.v2.endpoint import endpoint_api_pb2_grpc as envector_grpc
from pyenvector.proto_gen.v2.endpoint import endpoint_message_pb2 as envector_msg_pb2
from pyenvector.utils import version as version_utils
from pyenvector.utils.logging_config import logger
from pyenvector.utils.utils import _calculate_file_sha256

_error_logger = _stdlib_logging.getLogger("pyenvector")

###################################
# Indexer Class
###################################

MAX_REQUEST_ID_LENGTH = 30
_INDEX_OPERATION_STATE_RANK = {
    envector_op_pb2.INDEX_OPERATION_STATE_UNSPECIFIED: -1,
    envector_op_pb2.SPLIT_PENDING: 0,
    envector_op_pb2.SPLITTING: 1,
    envector_op_pb2.SPLIT_COMPLETED: 2,
    envector_op_pb2.MERGE_PENDING: 3,
    envector_op_pb2.MERGING: 4,
    envector_op_pb2.MERGED_SAVED: 5,
    envector_op_pb2.SEARCHABLE: 6,
    envector_op_pb2.FAILED: 99,
}

def _validate_index_operation_target_state(target_state: int) -> str:
    if target_state not in _INDEX_OPERATION_STATE_RANK:
        raise EnvectorValidationError(message="target_state must be a valid IndexOperationState value")
    return envector_op_pb2.IndexOperationState.Name(target_state)


def _normalize_cluster_id_sequence(
    cluster_ids: Optional[Union[int, Sequence[int]]],
    field_name: str,
) -> Optional[List[int]]:
    if cluster_ids is None:
        return None
    if isinstance(cluster_ids, int):
        return [cluster_ids]
    if isinstance(cluster_ids, Sequence) and not isinstance(cluster_ids, (str, bytes)):
        normalized = list(cluster_ids)
        if not all(isinstance(cluster_id, int) for cluster_id in normalized):
            raise EnvectorValidationError(message=f"{field_name} must contain only ints")
        return normalized
    raise EnvectorValidationError(message=f"{field_name} must be an int or a sequence of ints")


def _validate_row_insert_lengths(
    enc_vecs: Sequence[bytes],
    metadata_list: Sequence[str],
    cluster_ids: Optional[Sequence[int]] = None,
) -> None:
    if len(metadata_list) != len(enc_vecs):
        raise EnvectorValidationError(message="metadata_list length must match enc_vecs length")
    if cluster_ids is not None and len(cluster_ids) != len(enc_vecs):
        raise EnvectorValidationError(message="cluster_ids length must match enc_vecs length")


class Indexer:
    """
    High-level client for managing encrypted index and performing vector search operations on the enVector server.

    This API provides:

    - Connection to the enVector server (local or remote)
    - Key and context setup for homomorphic encryption at server side
    - Index creation, deletion, and management (encrypted/plain(TBD))
    - Batch or incremental vector insertion (encrypted/plain)
    - Encrypted similarity search
    - Both synchronous and asynchronous search operations

    Notes
    -----
    Instances should be created via the static `connect()` methods.

    Example
    --------

    >>> indexer = Indexer.connect("localhost:50050", access_token="your_access_token")
    >>> if indexer.is_connected():
    >>>     print("Connected to enVector service.")
    >>> else:
    >>>     print("Failed to connect to enVector service.")

    """

    # FIX: Changed from None to set() to enable proper membership checking
    # Previously assigned as string, causing substring match bugs
    _REGISTERED_ADDRS: set = set()

    # ReturnCode to exception class mapping (lazy-init)
    _RETURN_CODE_EXCEPTION_MAP = None

    # gRPC StatusCode to (return_code, retryable, action) mapping (lazy-init)
    _GRPC_STATUS_MAP = None

    @classmethod
    def _get_return_code_map(cls):
        """Lazy-init return code to exception class mapping."""
        if cls._RETURN_CODE_EXCEPTION_MAP is None:
            rc = envector_type_pb.ReturnCode
            cls._RETURN_CODE_EXCEPTION_MAP = {
                rc.InvalidInput: InvalidInputError,
                rc.NoSuchIndex: NotReadyError,
                rc.NotFoundError: InvalidInputError,
                rc.InvalidKeyURL: KeyManagementError,
                rc.InvalidKeyAuthInfo: AuthError,
                rc.FailedToUnpackKey: KeyManagementError,
                rc.InsufficientDIskSpace: ResourceLimitError,
                rc.Fail: InternalError,
                rc.UnknownError: InternalError,
                rc.Warning: EnvectorApplicationError,
            }
            # Add v2.1 codes if available (after T1 proto extension)
            for attr, exc_cls in [
                ("Timeout", EnvectorTimeoutError),
                ("DependencyError", DependencyError),
                ("NotReady", NotReadyError),
                ("AuthenticationError", AuthError),
                ("ResourceLimitError", ResourceLimitError),
            ]:
                code = getattr(rc, attr, None)
                if code is not None:
                    cls._RETURN_CODE_EXCEPTION_MAP[code] = exc_cls
        return cls._RETURN_CODE_EXCEPTION_MAP

    @classmethod
    def _get_grpc_status_map(cls):
        """Lazy-init gRPC StatusCode to (return_code, retryable, action) mapping."""
        if cls._GRPC_STATUS_MAP is None:
            rc = envector_type_pb.ReturnCode
            cls._GRPC_STATUS_MAP = {
                grpc.StatusCode.UNAVAILABLE: (
                    getattr(rc, "DependencyError", rc.Fail),
                    True,
                    "Check server connectivity",
                ),
                grpc.StatusCode.DEADLINE_EXCEEDED: (
                    getattr(rc, "Timeout", rc.Fail),
                    True,
                    "Retry with longer timeout",
                ),
                grpc.StatusCode.INVALID_ARGUMENT: (rc.InvalidInput, False, "Check input parameters"),
                grpc.StatusCode.NOT_FOUND: (rc.NotFoundError, False, "Verify resource exists"),
                grpc.StatusCode.UNAUTHENTICATED: (
                    getattr(rc, "AuthenticationError", rc.Fail),
                    False,
                    "Check credentials",
                ),
                grpc.StatusCode.PERMISSION_DENIED: (
                    getattr(rc, "AuthenticationError", rc.Fail),
                    False,
                    "Check permissions",
                ),
            }
        return cls._GRPC_STATUS_MAP

    @staticmethod
    def _return_code_name(return_code) -> str:
        """Best-effort human-readable name for a ReturnCode enum value.

        Protobuf enum fields are plain `int`, so `str(rc)` would render as a
        number (e.g. "3"). Use ReturnCode.Name() to surface "NoSuchIndex"
        instead, falling back to the raw value if the int isn't a known enum
        member (e.g. a future server emits a code this SDK doesn't know yet).
        """
        try:
            return envector_type_pb.ReturnCode.Name(return_code)
        except (ValueError, TypeError):
            return str(return_code)

    def _to_application_error(self, header, operation):
        """Convert ResponseHeader with error return_code to typed exception."""
        exc_map = self._get_return_code_map()
        exc_class = exc_map.get(header.return_code, InternalError)

        # Parse retryable/action if server provides them (after T1 proto extension)
        retryable = getattr(header, "retryable", False)
        action = getattr(header, "action", None) or None

        error = exc_class(
            message=header.error_message or f"{operation} failed",
            return_code=header.return_code,
            retryable=retryable,
            action=action,
            request_id=header.id if header.id else None,
        )

        _error_logger.error(
            "Application error from server: operation=%s return_code=%s "
            "error_message=%r request_id=%s retryable=%s exception_class=%s",
            operation,
            self._return_code_name(header.return_code),
            header.error_message or "",
            header.id if header.id else None,
            retryable,
            exc_class.__name__,
            extra={
                "operation": operation,
                # Keep `return_code` aligned with the message body (enum name)
                # so structured handlers and the rendered message agree.
                # `return_code_value` preserves the raw int for machine filters.
                "return_code": self._return_code_name(header.return_code),
                "return_code_value": int(header.return_code),
                "error_message": header.error_message,
                "request_id": header.id if header.id else None,
                "trace_id": header.id if header.id else None,
                "target_address": getattr(getattr(self, "connection", None), "server_address", None),
                "exception_class": exc_class.__name__,
                "retryable": retryable,
                "sdk_version": self._get_sdk_version(),
            },
        )

        return error

    def _normalize_transport_error(self, error, operation, request_id=None):
        """Map gRPC status to EnvectorTransportError."""
        code = error.code()
        status_map = self._get_grpc_status_map()
        rc = envector_type_pb.ReturnCode
        return_code, retryable, action = status_map.get(code, (rc.Fail, False, "Contact support with request ID"))

        _error_logger.error(
            "gRPC transport error: operation=%s grpc_code=%s grpc_details=%r "
            "return_code=%s request_id=%s",
            operation,
            code.name,
            str(error.details()) if hasattr(error, "details") else None,
            self._return_code_name(return_code),
            request_id,
            extra={
                "operation": operation,
                "grpc_code": code.name,
                "grpc_details": str(error.details()) if hasattr(error, "details") else None,
                # Aligned with message body (enum name); raw int preserved separately.
                "return_code": self._return_code_name(return_code),
                "return_code_value": int(return_code),
                "request_id": request_id,
                "trace_id": request_id,
                "target_address": getattr(getattr(self, "connection", None), "server_address", None),
                "sdk_version": self._get_sdk_version(),
            },
        )

        return EnvectorTransportError(
            message=f"{operation} failed: {code.name}",
            return_code=return_code,
            retryable=retryable,
            action=action,
            request_id=request_id,
        )

    @staticmethod
    def _get_sdk_version():
        """Return SDK version string for structured logging."""
        try:
            import pyenvector as _pkg

            return getattr(_pkg, "__version__", "unknown")
        except Exception:
            return "unknown"

    # Thin wrappers over shared auth helpers; kept so subclasses/tests that
    # reach for these names on Indexer continue to work.
    _resolve_access_token = staticmethod(resolve_access_token)
    _build_auth_metadata = staticmethod(build_auth_metadata)
    _is_auth_return_code = staticmethod(is_auth_return_code)
    _is_auth_rpc_error = staticmethod(is_auth_rpc_error)

    def _refresh_access_token(self) -> bool:
        if self._auth_session is None or not self._auth_session.can_refresh():
            return False
        refreshed_token = self._auth_session.refresh_access_token()
        logger.info(
            "Refreshed access token for %s",
            getattr(self.connection, "server_address", "<unknown>"),
        )
        return bool(refreshed_token)

    @staticmethod
    def _is_nonfatal_return_code(return_code: Optional[int]) -> bool:
        return return_code in (
            envector_type_pb.ReturnCode.Success,
            getattr(envector_type_pb.ReturnCode, "Warning", None),
        )

    def _normalize_nonfatal_unary_response(self, response, operation: str, request_id: Optional[str] = None):
        if not hasattr(response, "header") or response.header is None:
            return response

        return_code = getattr(response.header, "return_code", None)
        warning_code = getattr(envector_type_pb.ReturnCode, "Warning", None)
        if self._is_nonfatal_return_code(return_code) and return_code == warning_code:
            logger.warning(
                "Server returned non-fatal warning during {}: {} (request_id={})",
                operation,
                getattr(response.header, "error_message", "") or warning_code,
                request_id or getattr(response.header, "id", None) or "-",
            )
            response.header.return_code = envector_type_pb.ReturnCode.Success

        return response

    def _call_unary_with_refresh(self, rpc, request, operation: str, request_id: Optional[str] = None):
        allow_refresh = self._auth_session is not None and self._auth_session.can_refresh()
        attempt = 0
        while True:
            try:
                response = rpc(
                    request,
                    metadata=self.grpc_metadata,
                )
            except grpc.RpcError as e:
                if attempt == 0 and allow_refresh and self._is_auth_rpc_error(e):
                    try:
                        refreshed = self._refresh_access_token()
                    except EnvectorTransportError as refresh_err:
                        # Preserve the originating gRPC error context — without
                        # `from e`, the cause chain would only show the refresh
                        # failure and the originating UNAUTHENTICATED trace would
                        # be lost.
                        raise refresh_err from e
                    if refreshed:
                        attempt += 1
                        continue
                raise self._normalize_transport_error(e, operation, request_id=request_id) from e

            if (
                attempt == 0
                and allow_refresh
                and hasattr(response, "header")
                and self._is_auth_return_code(getattr(response.header, "return_code", None))
                and self._refresh_access_token()
            ):
                attempt += 1
                continue
            return self._normalize_nonfatal_unary_response(response, operation, request_id=request_id)

    def _call_unary_with_call_and_refresh(self, rpc, request, operation: str, request_id: Optional[str] = None):
        allow_refresh = self._auth_session is not None and self._auth_session.can_refresh()
        attempt = 0
        while True:
            try:
                response, call = rpc.with_call(
                    request,
                    metadata=self.grpc_metadata,
                )
            except grpc.RpcError as e:
                if attempt == 0 and allow_refresh and self._is_auth_rpc_error(e):
                    try:
                        refreshed = self._refresh_access_token()
                    except EnvectorTransportError as refresh_err:
                        raise refresh_err from e
                    if refreshed:
                        attempt += 1
                        continue
                raise self._normalize_transport_error(e, operation, request_id=request_id) from e

            if (
                attempt == 0
                and allow_refresh
                and hasattr(response, "header")
                and self._is_auth_return_code(getattr(response.header, "return_code", None))
                and self._refresh_access_token()
            ):
                attempt += 1
                continue
            return self._normalize_nonfatal_unary_response(response, operation, request_id=request_id), call

    def _call_client_stream_with_refresh(self, rpc, request_factory, operation: str, request_id: Optional[str] = None):
        """Invoke a client-streaming RPC with a single auth-refresh retry.

        Unlike the unary helpers, the request payload is a consumable iterator that
        cannot be replayed once streamed to the server. ``request_factory`` must
        therefore be a zero-argument callable returning a *fresh* request iterator
        on each call, so the retry after a token refresh streams from the start.

        Returns the raw response; the caller is responsible for inspecting
        ``response.header.return_code`` and raising an application error as needed.
        """
        allow_refresh = self._auth_session is not None and self._auth_session.can_refresh()
        attempt = 0
        while True:
            try:
                response = rpc(
                    request_factory(),
                    metadata=self.grpc_metadata,
                )
            except grpc.RpcError as e:
                if attempt == 0 and allow_refresh and self._is_auth_rpc_error(e):
                    try:
                        refreshed = self._refresh_access_token()
                    except EnvectorTransportError as refresh_err:
                        raise refresh_err from e
                    if refreshed:
                        attempt += 1
                        continue
                raise self._normalize_transport_error(e, operation, request_id=request_id) from e

            if (
                attempt == 0
                and allow_refresh
                and hasattr(response, "header")
                and self._is_auth_return_code(getattr(response.header, "return_code", None))
                and self._refresh_access_token()
            ):
                attempt += 1
                continue
            return response

    def _is_safe_memory_mode(self):
        """
        Checks if the safe memory enforcement mode is enabled via environment variables.
        Returns True if ENVECTOR_SAFE_MEMORY is set to '1', 'true', or 'yes' (default is '1').
        """
        enabled = str(os.getenv("ENVECTOR_SAFE_MEMORY", "1")).lower()
        return enabled in ("1", "true", "yes")

    def _check_insertable(self, index_name):
        """
        Validates if the index can accept new insertions based on available shards.
        Raises ValueError if memory safety is enabled and no insertable shards remain.
        """
        if not self._is_safe_memory_mode():
            return

        # Check if there is at least one shard available for insertion
        shards = self.get_index_summary(index_name).get("remaining_insertable_shards", 0)
        logger.debug(f"Remaining insertable shards for index '{index_name}': {shards}")
        if shards < 1:
            raise ValueError(
                f"Index '{index_name}' is not insertable: No remaining shards available. "
                "To bypass this check, set ENVECTOR_SAFE_MEMORY=0."
            )

    def _check_loadable(self, index_name):
        """
        Validates if the index can be loaded into memory.
        Raises ValueError if memory safety is enabled and the index cannot be loaded.
        """
        if not self._is_safe_memory_mode():
            return

        # Check the loadable status from the index summary
        if not self.get_index_summary(index_name).get("can_load_now", False):
            raise ValueError(
                f"Index '{index_name}' is not loadable: Memory constraints detected. "
                "To bypass this check, set ENVECTOR_SAFE_MEMORY=0."
            )

    def __init__(
        self,
        connection: Connection,
        access_token: AccessTokenInput = None,
        refresh_token: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ):
        self.connection = connection
        self.stub = envector_grpc.EndpointServiceStub(connection.get_channel())
        self._auth_session = _AuthSession(
            access_token=access_token,
            refresh_token=refresh_token,
            oidc_issuer=oidc_issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )

    @property
    def access_token(self) -> Optional[str]:
        # Resolves to the live access token (post-refresh value if rotated, or the
        # current return of the configured callable provider). Returns the input
        # string when no refresh/provider is configured, or None if unauthenticated.
        if self._auth_session is None:
            return None
        return self._auth_session.get_access_token()

    @property
    def grpc_metadata(self) -> List[Tuple[str, str]]:
        token = self._auth_session.get_access_token() if self._auth_session else None
        metadata = self._build_auth_metadata(token)
        return metadata or []

    ###################################
    # Connection Management
    ###################################

    @classmethod
    def connect(
        cls,
        address: str,
        access_token: AccessTokenInput = None,
        secure: Optional[bool] = None,
        refresh_token: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> "Indexer":
        """
        Establishes a connection to the enVector service.

        Parameters
        ----------
        address : str
            The address of the enVector service endpoint (e.g., "localhost:50050").
        access_token : str or callable, optional
            Access token for authentication. You may provide a string token or a callable returning
            the current token. The callable form is useful when tokens need to be refreshed during
            long-running operations.
        secure : bool, optional
            Whether to use a secure connection (default: True if access_token or refresh_token is provided,
            else False)
        refresh_token : str, optional
            OIDC refresh token. When provided with ``client_id`` and ``token_endpoint`` or
            ``oidc_issuer``, the SDK refreshes the bearer token internally on authentication failures.
        oidc_issuer : str, optional
            OIDC issuer URL used to discover the token endpoint.
        token_endpoint : str, optional
            Explicit OIDC token endpoint used for refresh.
        client_id : str, optional
            OIDC client ID used for refresh token exchange.
        client_secret : str, optional
            OIDC client secret used for refresh token exchange.
        scope : str, optional
            Optional scope value included in refresh requests.

        Returns
        -------
        Indexer
            An instance of the Indexer class connected to the specified address.
        """
        if access_token is None and refresh_token and client_id and (token_endpoint or oidc_issuer):
            bootstrap = _AuthSession(
                refresh_token=refresh_token,
                oidc_issuer=oidc_issuer,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
            )
            access_token = bootstrap.refresh_access_token()
            # IdPs with rotation hand back a new refresh_token on every exchange;
            # propagate it so the Indexer's session does not re-use the consumed one.
            refresh_token = bootstrap._refresh_token
        if secure is None:
            secure = True if (access_token or refresh_token) else False
        logger.info(f"Connecting to enVector service at {address} with secure={secure}")
        conn = Connection(address, secure=secure)
        if not conn.is_connected():
            raise EnvectorTransportError(
                message=f"Failed to connect to {address}",
                retryable=True,
                action="Check server connectivity",
            )

        # Optional gRPC Health Check (enabled by default)
        # Env vars:
        #   ES2_GRPC_HEALTH_CHECK: enable/disable (default: 1)
        #   ES2_GRPC_HEALTH_REQUIRED: fail if health unavailable/unimplemented (default: 1)
        #   ES2_GRPC_HEALTH_SERVICE: target service name (default: "")
        #   ES2_GRPC_HEALTH_TIMEOUT: RPC timeout in seconds (default: 3)
        do_health = os.getenv("ES2_GRPC_HEALTH_CHECK", "1").lower() not in ("0", "false", "no")
        if do_health:
            # Only perform health check the first time per address
            if cls._REGISTERED_ADDRS and address in cls._REGISTERED_ADDRS:
                logger.debug("Skipping gRPC health check; already verified for %s", address)
            else:
                health_required = os.getenv("ES2_GRPC_HEALTH_REQUIRED", "1").lower() not in ("0", "false", "no")
                health_service = os.getenv("ES2_GRPC_HEALTH_SERVICE", "")
                try:
                    timeout_s = float(os.getenv("ES2_GRPC_HEALTH_TIMEOUT", "3"))
                except Exception:
                    timeout_s = 3.0

                try:
                    # Import gRPC health checking stubs
                    from grpc_health.v1 import health_pb2, health_pb2_grpc  # type: ignore

                    health_stub = health_pb2_grpc.HealthStub(conn.get_channel())
                    req = health_pb2.HealthCheckRequest(service=health_service)
                    # Include authorization metadata if an access token is provided
                    auth_md = cls._build_auth_metadata(access_token)
                    resp = health_stub.Check(
                        req,
                        timeout=timeout_s,
                        metadata=auth_md,
                    )
                    if resp.status != health_pb2.HealthCheckResponse.SERVING:
                        # Convert enum to human string if possible
                        try:
                            status_name = health_pb2.HealthCheckResponse.ServingStatus.Name(resp.status)
                        except Exception:
                            status_name = str(resp.status)
                        raise EnvectorTransportError(
                            message=f"gRPC health status for service '{health_service}' is '{status_name}'",
                            action="Ensure enVector server is healthy",
                        )
                    # Mark as checked on success
                    cls._REGISTERED_ADDRS.add(address)
                except ImportError as e:
                    msg = (
                        "grpcio-health-checking is not installed; cannot perform gRPC health check. "
                        "Install 'grpcio-health-checking' or set ES2_GRPC_HEALTH_CHECK=0 to disable."
                    )
                    if health_required:
                        raise EnvectorTransportError(
                            message=msg,
                            action="Install grpcio-health-checking or set ES2_GRPC_HEALTH_CHECK=0",
                        ) from e
                    else:
                        logger.warning(msg)
                        # Consider health waived for this address to avoid repeated attempts
                        cls._REGISTERED_ADDRS.add(address)
                except grpc.RpcError as e:
                    code = e.code()
                    if code == grpc.StatusCode.UNIMPLEMENTED:
                        msg = "Server does not implement gRPC health service"
                        if health_required:
                            raise EnvectorTransportError(
                                message=msg,
                                action="Set ES2_GRPC_HEALTH_REQUIRED=0 or implement gRPC health service",
                            ) from e
                        else:
                            logger.warning(msg + "; proceeding without health validation")
                            # Consider health waived for this address to avoid repeated attempts
                            cls._REGISTERED_ADDRS.add(address)
                    else:
                        raise EnvectorTransportError(
                            message=f"Health check RPC failed: {code.name}",
                            retryable=True,
                            action="Check server connectivity",
                        ) from e

        return cls(
            conn,
            access_token=access_token,
            refresh_token=refresh_token,
            oidc_issuer=oidc_issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )

    def is_connected(self):
        """
        Checks if the enVector connection is active.

        Returns
        -------
        bool
            True if the connection is active, False otherwise.
        """
        return self.connection.is_connected()

    def disconnect(self):
        """
        Closes the enVector connection.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        self.connection.close()

    ###################################
    # Server Info
    ###################################

    def get_server_version(self) -> Optional[str]:
        """
        Retrieve server version via gRPC metadata.

        This method performs a lightweight RPC (get_key_list) and reads
        the server version from response metadata injected by the server.

        Returns
        -------
        Optional[str]
            Version string if available, otherwise None.
        """
        try:
            request = envector_msg_pb2.GetKeyListRequest()
            request.header.type = envector_type_pb.MessageType.GetKeyList
            # use with_call to access metadata
            response, call = self._call_unary_with_call_and_refresh(
                self.stub.get_key_list,
                request,
                "get server version",
            )
            # prefer trailing metadata
            md = dict(call.trailing_metadata()) if hasattr(call, "trailing_metadata") else {}
            server_version = md.get("x-envector-endpoint-version") or md.get("x-es2e-server-version")
            if not server_version and hasattr(call, "initial_metadata"):
                imd = dict(call.initial_metadata())
                server_version = imd.get("x-envector-endpoint-version") or imd.get("x-es2e-server-version")
            return server_version
        except Exception as e:
            logger.warning(f"Failed to retrieve server version from metadata: {e}")
            return None

    def check_version_compat(self) -> None:
        """
        Compare SDK version with server version and enforce compatibility policy.

        Policy:
        - If ES2_VERSION_CHECK is 0/false/no, skip.
        - If server version does not start with 'vX.Y.Z', skip (non-versioned server).
        - Otherwise compare using semantic parsing incl. pre-release tags.
          If mismatch and ES2_VERSION_CHECK_STRICT is on (default), raise; else warn.
        """
        import os

        do_check = os.getenv("ES2_VERSION_CHECK", "1").lower() not in ("0", "false", "no")
        if not do_check:
            return

        try:
            import pyenvector as _pyenvector_pkg  # lazy to avoid circular import on package init

            sdk_version: Optional[str] = getattr(_pyenvector_pkg, "__version__", None)
        except Exception:
            sdk_version = None

        server_version = None
        try:
            server_version = self.get_server_version()
        except Exception as e:
            logger.debug(f"Version check: unable to fetch server version: {e}")

        if sdk_version and server_version:
            if not version_utils.should_check(server_version):
                logger.debug(
                    "Server version '%s' is not a valid semver (X.Y.Z or vX.Y.Z); skipping version check.",
                    server_version,
                )
                return
            strict = os.getenv("ES2_VERSION_CHECK_STRICT", "1").lower() not in ("0", "false", "no")
            compatible = version_utils.is_equal(sdk_version, server_version) or version_utils.is_hotfix_compatible(
                sdk_version, server_version
            )
            if not compatible:
                server_pep440 = version_utils.to_pep440(server_version)
                msg = (
                    f"SDK/Server version mismatch: sdk={sdk_version}, server={server_version}"
                    f" (server_pep440={server_pep440}). "
                    f"Set ES2_VERSION_CHECK=0 to skip, or ES2_VERSION_CHECK_STRICT=0 to warn only."
                )
                if strict:
                    raise EnvectorTransportError(
                        message=msg,
                        action="Set ES2_VERSION_CHECK=0 to skip or ES2_VERSION_CHECK_STRICT=0 to warn only",
                    )
                else:
                    logger.warning(msg)
        else:
            logger.debug(
                "Version check skipped: missing sdk or server version (sdk=%s, server=%s)",
                str(sdk_version),
                str(server_version),
            )

    ###################################
    # Key Management
    ###################################

    def register_key(
        self, key_id: str, key: bytes, key_type: str = "EvalKey", preset: str = "IP3", eval_mode: str = "MM32"
    ):
        """
        Registers a public key from the specified file path to enVector server.

        Parameters
        ----------
        key_id : str
            The unique identifier for the key.
        key_path : str
            The file path to the key to be registered.
        preset : str
            The preset to use for the key. Default is "IP3".
        eval_mode : str
            The evaluation mode to use for the key. Default is "MM32".

        Returns
        -------
        None
        """
        CHUNK_SIZE = CHUNK_SIZE_1MB  # 1MB

        # Use a unique header ID as an API request identifier
        header_id = secrets.token_hex(10)

        try:
            sha256sum = _calculate_file_sha256(key)
        except Exception as exc:
            raise EnvectorValidationError(
                message=f"Failed to compute SHA256 for key '{key_id}': {exc}",
            ) from exc

        def register_key_request_generator():
            try:
                for offset in range(0, len(key), CHUNK_SIZE):
                    chunk = key[offset : offset + CHUNK_SIZE]
                    request = envector_msg_pb2.RegisterKeyRequest()
                    request.header.type = envector_type_pb.MessageType.RegisterKey
                    request.header.id = header_id

                    request.key_info.key_id = key_id
                    request.key_info.type = key_type
                    request.key_info.preset = preset
                    request.key_info.eval_mode = eval_mode
                    request.key_info.sha256sum = sha256sum

                    request.key.value = chunk
                    request.key.size = len(chunk)
                    request.total_size = len(key)
                    yield request

            except Exception as e:
                logger.error(f"Error reading key file : {e}")
                return

        try:
            response = self.stub.register_key(
                register_key_request_generator(),
                metadata=self.grpc_metadata,
            )
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "register key", request_id=header_id) from e

        response = self._normalize_nonfatal_unary_response(response, "register key", request_id=header_id)

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "register key")
        else:
            logger.info(f"Key '{key_id}' registered successfully.")

    def get_key_list(self):
        """
        Get a list of all registered key IDs.

        Returns
        -------
        Optional[List[str]]
            A list of registered key IDs, or None if the request failed.
        """
        request = envector_msg_pb2.GetKeyListRequest()

        request.header.type = envector_type_pb.MessageType.GetKeyList
        request.header.id = secrets.token_hex(10)  # unique header ID

        response = self._call_unary_with_refresh(
            self.stub.get_key_list,
            request,
            "list keys",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "list keys")
        else:
            logger.info("Get key list successfully.")
            key_list = list(response.key_id)
            if len(key_list) == 0:
                logger.info("No keys registered in the enVector server.")
            return key_list

    def get_key_info(self, key_id: str):
        """
        Retrieves key information about a specific key from enVector server.

        Parameters
        ----------
        key_id : str
            The unique identifier for the key.

        Returns
        -------
        Optional[dict]
            A dictionary containing key information (key_id, key_type, dim, url), or None if the request failed.
        """
        request = envector_msg_pb2.GetKeyInfoRequest()

        request.header.type = envector_type_pb.MessageType.GetKeyInfo
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.key_id = key_id

        response = self._call_unary_with_refresh(
            self.stub.get_key_info,
            request,
            "get key info",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "get key info")
        else:
            logger.info(f"Key info for '{key_id}' received successfully.")

            return {
                "key_id": key_id,
                "key_type": response.key_info.type,
                "preset": response.key_info.preset,
                "eval_mode": response.key_info.eval_mode,
                "sha256sum": response.key_info.sha256sum,
                "is_loaded": response.key_info.is_loaded,
            }

    def delete_key(self, key_id: str):
        """
        Deletes a registered key by its ID from enVector server.

        Parameters
        ----------
        key_id : str
            The unique identifier for the key to be deleted.
        """
        request = envector_msg_pb2.DeleteKeyRequest()
        request.header.type = envector_type_pb.MessageType.DeleteKey
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.key_id = key_id

        response = self._call_unary_with_refresh(
            self.stub.delete_key,
            request,
            "delete key",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "delete key")
        else:
            logger.info(f"Key '{key_id}' deleted successfully.")

    def load_key(self, key_id: str):
        """
        Loads a registered key by its ID from enVector server.

        Parameters
        ----------
        key_id : str
            The unique identifier for the key to be loaded.
        """
        request = envector_msg_pb2.LoadKeyRequest()
        request.header.type = envector_type_pb.MessageType.LoadKey
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.key_id = key_id

        response = self._call_unary_with_refresh(
            self.stub.load_key,
            request,
            "load key",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "load key")
        else:
            logger.info(f"Key '{key_id}' loaded successfully.")

    def unload_key(self, key_id: str):
        """
        Unloads a registered key by its ID from enVector server.

        Parameters
        ----------
        key_id : str
            The unique identifier for the key to be loaded.
        """
        request = envector_msg_pb2.UnloadKeyRequest()
        request.header.type = envector_type_pb.MessageType.UnloadKey
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.key_id = key_id

        response = self._call_unary_with_refresh(
            self.stub.unload_key,
            request,
            "unload key",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "unload key")
        else:
            logger.info(f"Key '{key_id}' unloaded successfully.")

    def _describe_index_state(self, index_loaded: Optional[bool], key_loaded: Optional[bool]) -> str:
        if index_loaded and key_loaded:
            return "insert/search"

        needs_index = index_loaded is False
        needs_key = key_loaded is False
        if needs_index and needs_key:
            return "unavailable (load index and key)"
        if needs_index:
            return "unavailable (load index)"
        if needs_key:
            return "unavailable (load key)"
        return "unavailable"

    ###################################
    # Index Management
    ###################################

    def create_index(
        self,
        index_name: str,
        key_id: str,
        dim: int,
        search_type: str = "ip1",
        index_encryption: str = "cipher",
        query_encryption: str = "plain",
        metadata_encryption: bool = True,
        index_params: dict = {"index_type": "flat"},
        description: Optional[str] = None,
    ):
        """
        Creates a new index into enVector server.

        Index includes the following information:
        - Encrypted Vectors to store
        - Metadata for each vector

        Parameters
        ----------
        index_name : str
            The name of the index to be created.
        key_id : str
            The unique identifier for the key associated with the index.
        dim : int
            Vector dimension to be stored in the index.
        search_type : Union[str, envector_type_pb.SearchType], optional
            The type of search to be performed on the index (default: "ip1").
        index_encryption : str, optional
            The type of index to be created (default: "cipher"). Options are "plain" or "cipher".
        query_encryption : str, optional
            The type of query to be performed on the index (default: "plain"). Options are "plain" or "cipher".
        index_type : str, optional
            The type of index to be created (default: "flat"). Options are "flat", "ivf_flat" and "ivf_vct".
        description : str, optional
            A human-readable description for the index.

        Returns
        -------
        Dict
            A dictionary containing index information.
        """
        # Use a unique header ID as an API request identifier
        header_id = secrets.token_hex(10)
        request = envector_msg_pb2.CreateIndexRequest()
        request.header.type = envector_type_pb.MessageType.CreateIndex
        request.header.id = header_id

        logger.debug(
            f"Creating index with name: {index_name}, dim: {dim}, search_type: {search_type}, "
            f"key_id: {key_id}, index_encryption: {index_encryption}, "
            f"query_encryption: {query_encryption}, index_type: {index_params.get('index_type', None)}"
        )
        if isinstance(search_type, str):
            if search_type.lower() == "iponly" or search_type.lower() == "ip1":
                search_type = envector_type_pb.SearchType.IPOnly
            elif search_type.lower() == "ipandqf" or search_type.lower() == "qf":
                search_type = envector_type_pb.SearchType.IPAndQF
            else:
                logger.debug(f"Invalid search type: {search_type}. Defaulting to IPOnly.")
                search_type = envector_type_pb.SearchType.IPOnly

        elif isinstance(search_type, int):
            if search_type not in [envector_type_pb.SearchType.IPOnly, envector_type_pb.SearchType.IPAndQF]:
                logger.debug(f"Invalid search type: {search_type}. Defaulting to IPOnly.")
                search_type = envector_type_pb.SearchType.IPOnly
            else:
                search_type = search_type
        else:
            raise EnvectorValidationError(
                message=f"Invalid type for search_type: {type(search_type)}.",
            )

        if isinstance(index_encryption, str) and index_encryption.lower() in ["plain", "cipher", "hybrid"]:
            index_encryption = index_encryption.lower()
        else:
            raise EnvectorValidationError(
                message=f"Invalid index_encryption: {index_encryption}. Expected 'plain' or 'cipher'.",
            )

        centroids = None
        if isinstance(index_params["index_type"], str):
            if index_params["index_type"].upper() == "FLAT":
                index_type = envector_type_pb.IndexType.FLAT
            elif index_params["index_type"].upper() == "IVF_FLAT" or index_params["index_type"].upper() == "IVF_VCT":
                logger.debug(
                    f"{index_params['index_type']} params with values: "
                    f"nlist: {index_params['nlist']}, default_nprobe: {index_params['default_nprobe']}"
                )
                if index_params["index_type"].upper() == "IVF_FLAT":
                    index_type = envector_type_pb.IndexType.IVF_FLAT
                elif index_params["index_type"].upper() == "IVF_VCT":
                    index_type = envector_type_pb.IndexType.IVF_VCT
                if index_params.get("nlist") is None:
                    raise EnvectorValidationError(
                        message="nlist must be provided for IVF index type.",
                    )
                if index_params.get("default_nprobe") is None:
                    raise EnvectorValidationError(
                        message="default_nprobe must be provided for IVF index type.",
                    )
                centroids = index_params.get("centroids")
                if centroids is None:
                    logger.info("Centroids not provided for IVF index type. Generating random centroids locally.")
                    # FIX: Use seeded RNG for deterministic centroid generation
                    # Previously np.random.rand() without seed caused non-reproducible benchmarks
                    seed = index_params.get("centroid_seed", 42)
                    rng = np.random.default_rng(seed)
                    centroids = rng.random((index_params["nlist"], dim)).astype(np.float32)
                    # FIX: Add epsilon to prevent division by zero on zero-sum rows
                    # Previously zero rows caused NaN which corrupted KNN search
                    centroids /= np.sum(centroids, axis=1, keepdims=True) + 1e-10
                if len(centroids) != index_params["nlist"]:
                    raise EnvectorValidationError(
                        message=f"Centroids size ({len(centroids)}) does not match nlist ({index_params['nlist']})",
                    )

                request.index_info.index_detail.ivf_detail.nlist = index_params["nlist"]
                request.index_info.index_detail.ivf_detail.default_nprobe = index_params["default_nprobe"]

        request.index_info.index_name = index_name
        request.index_info.dim = dim
        request.index_info.search_type = search_type
        request.index_info.key_id = key_id
        request.index_info.index_encryption = index_encryption
        request.index_info.query_encryption = query_encryption
        request.index_info.metadata_encryption = metadata_encryption
        request.index_info.index_type = index_type
        if description is not None:
            request.index_info.description = description

        # Chunk centroids across stream messages so the backend unmarshal buffer + decoded proto
        # do not coexist at full nlist*dim size. Server appends centroids from subsequent messages.
        centroids_per_chunk = max(1, CHUNK_SIZE_1MB // (dim * 4 + 16)) if centroids is not None else 0

        def request_generator():
            if centroids is None or len(centroids) == 0:
                yield request
                return
            msg = request
            for offset in range(0, len(centroids), centroids_per_chunk):
                if offset > 0:
                    msg = envector_msg_pb2.CreateIndexRequest()
                for centroid in centroids[offset : offset + centroids_per_chunk]:
                    dt = envector_type_pb.DataType()
                    dt.plain_vector.data.extend(centroid)
                    msg.index_info.index_detail.ivf_detail.centroids.append(dt)
                yield msg

        try:
            response = self.stub.create_index(
                request_generator(),
                metadata=self.grpc_metadata,
            )
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "create index", request_id=header_id) from e

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "create index")
        else:
            logger.info(f"Index '{index_name}' created successfully.")
            return {
                "index_name": index_name,
                "dim": dim,
                "search_type": search_type,
                "key_id": key_id,
                "index_encryption": index_encryption,
                "query_encryption": query_encryption,
                "index_type": index_type,
                "description": description,
            }

    def get_index_list(self, loaded_only: bool = False):
        """
        Get a list of all index names in enVector server.

        Parameters
        ----------
        loaded_only : bool, optional
            If True, only return names of loaded indexes.

        Returns
        -------
        List[str]
            A list of index names, or None if the request failed.
        """
        request = envector_msg_pb2.GetIndexListRequest()
        request.header.type = envector_type_pb.MessageType.GetIndexList
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.loaded_only = loaded_only

        response = self._call_unary_with_refresh(
            self.stub.get_index_list,
            request,
            "get index list",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "get index list")
        else:
            logger.info("Get Index list received successfully.")
            return list(response.index_names)

    def get_index_info(self, index_name: str):
        """
        Retrieves information about a specific index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index to retrieve information for.

        Returns
        -------
        Dict
            A dictionary containing index information (index_name, dim, row_count, search_type, key_id, created_time),
                or None if the request failed.
        """
        request = envector_msg_pb2.GetIndexInfoRequest()
        request.header.type = envector_type_pb.MessageType.GetIndexInfo
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        try:
            response_iter = self.stub.get_index_info(
                request,
                metadata=self.grpc_metadata,
            )
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "get index info", request_id=request.header.id) from e

        try:
            for stream_idx, response in enumerate(response_iter):
                if response.header.return_code != envector_type_pb.ReturnCode.Success:
                    raise self._to_application_error(response.header, "get index info")

                if stream_idx == 0:
                    assert response.index_info.index_name == index_name, "Index name mismatch in response."

                    res = {
                        "index_name": index_name,
                        "dim": response.index_info.dim,
                        "row_count": response.index_info.row_count,
                        "search_type": envector_type_pb.SearchType.Name(response.index_info.search_type),
                        "key_id": response.index_info.key_id,
                        "index_encryption": response.index_info.index_encryption,
                        "query_encryption": response.index_info.query_encryption,
                        "metadata_encryption": getattr(response.index_info, "metadata_encryption", None),
                        "description": getattr(response.index_info, "description", None),
                        "created_time": response.index_info.created_time,
                        "is_loaded": response.index_info.is_loaded,
                        "is_key_loaded": response.index_info.is_key_loaded,
                        "index_type": envector_type_pb.IndexType.Name(response.index_info.index_type),
                        "state": self._describe_index_state(
                            response.index_info.is_loaded,
                            response.index_info.is_key_loaded,
                        ),
                    }

                    if res["index_type"].upper() == "IVF_FLAT" or res["index_type"].upper() == "IVF_VCT":
                        ivf_detail = response.index_info.index_detail.ivf_detail

                        res["ivf_detail"] = envector_type_pb.IvfDetail()

                        res["ivf_detail"].nlist = ivf_detail.nlist
                        res["ivf_detail"].default_nprobe = ivf_detail.default_nprobe

                        res["ivf_detail"].centroids.extend(ivf_detail.centroids)

                else:
                    if res["index_type"].upper() == "IVF_FLAT" or res["index_type"].upper() == "IVF_VCT":
                        res["ivf_detail"].centroids.extend(response.index_info.index_detail.ivf_detail.centroids)
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "get index info (stream)", request_id=request.header.id) from e

        logger.info(f"Index info for '{index_name}' received successfully.")

        return res

    def get_index_summary(self, index_name: str):
        """
        Retrieves a lightweight summary for a specific index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index to retrieve summary information for.

        Returns
        -------
        Dict
            A dictionary containing summary index information without heavy index detail payloads.
        """
        request = envector_msg_pb2.GetIndexSummaryRequest()
        request.header.type = envector_type_pb.MessageType.GetIndexSummary
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        response = self._call_unary_with_refresh(
            self.stub.get_index_summary,
            request,
            "get index summary",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "get index summary")

        summary = response.index_summary
        logger.info(f"Index summary for '{index_name}' received successfully.")

        return {
            "index_name": summary.index_name or index_name,
            "dim": summary.dim,
            "row_count": summary.row_count,
            "saved_row_count": summary.saved_row_count,
            "search_type": envector_type_pb.SearchType.Name(summary.search_type),
            "key_id": summary.key_id,
            "index_encryption": summary.index_encryption,
            "query_encryption": summary.query_encryption,
            "metadata_encryption": getattr(summary, "metadata_encryption", None),
            "description": getattr(summary, "description", None),
            "created_time": summary.created_time,
            "is_loaded": summary.is_loaded,
            "is_key_loaded": summary.is_key_loaded,
            "index_type": envector_type_pb.IndexType.Name(summary.index_type),
            "state": self._describe_index_state(
                summary.is_loaded,
                summary.is_key_loaded,
            ),
            "can_load_now": summary.can_load_now,
            "remaining_insertable_shards": summary.remaining_insertable_shards,
            "remaining_insertable_vectors_guaranteed": summary.remaining_insertable_vectors_guaranteed,
            "remaining_insertable_vectors_best_effort": summary.remaining_insertable_vectors_best_effort,
            # IVF clustering params (0 for non-IVF / older servers); getattr guards stub skew.
            "nlist": getattr(summary, "nlist", 0),
            "default_nprobe": getattr(summary, "default_nprobe", 0),
        }

    _SUPPORTED_OPERATION_TYPES = frozenset({
        envector_type_pb.IndexOperationType.INSERT,
        envector_type_pb.IndexOperationType.DELETE,
    })

    def get_index_operation_status(
        self,
        index_name: str,
        request_id: str,
        operation_type: Union[str, int] = "INSERT",
        partition_name: Optional[str] = None,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """
        Retrieve completion status for a specific index operation.

        This API is request-scoped. To track an INSERT or DELETE completion, capture the
        server-generated ``request_id`` from the response ``header.id``, and then poll this
        API until ``done=true``.

        Parameters
        ----------
        index_name : str
            Target index name.
        request_id : str
            Server-generated request identifier. This is returned in the response ``header.id``
            from insert or delete operations.
            Must be non-empty and at most ``MAX_REQUEST_ID_LENGTH`` characters.
        operation_type : Union[str, int], optional
            Operation type. You may pass either the proto enum value (int) or a string such as
            ``"INSERT"`` or ``"DELETE"``. Supported types: INSERT, DELETE.

        Notes
        -----
        - ``done`` is computed by the server. For INSERT, ``done`` becomes true when all rows
          are searchable. For DELETE, ``done`` becomes true when shard rebuild is complete.
        - Search requests are not tracked.

        Returns
        -------
        GetIndexOperationStatusResponse
            Status response containing (at least) ``total_row_count``, ``searchable_row_count``, and ``done``.

        Raises
        ------
        EnvectorValidationError
            If parameters are invalid.
        EnvectorApplicationError
            If the server returns a failure status.
        """
        self._validate_request_id(request_id)
        if isinstance(operation_type, str):
            try:
                operation_type = envector_type_pb.IndexOperationType.Value(operation_type.upper())
            except ValueError as e:
                raise EnvectorValidationError(
                    message="operation_type must be a valid IndexOperationType name (e.g. 'INSERT', 'DELETE')",
                ) from e
        elif not isinstance(operation_type, int):
            raise EnvectorValidationError(
                message="operation_type must be a str or an int",
            )

        if operation_type not in self._SUPPORTED_OPERATION_TYPES:
            raise EnvectorValidationError(
                message=f"Unsupported operation_type: {operation_type}. Supported: INSERT, DELETE",
            )

        request = envector_op_pb2.GetIndexOperationStatusRequest()
        request.header.type = envector_type_pb.MessageType.GetIndexOperationStatus
        request.header.id = secrets.token_hex(10)  # unique header ID for this status request
        request.index_name = index_name
        request.request_id = request_id
        request.operation_type = operation_type
        if partition_name:
            request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.get_index_operation_status,
            request,
            "get index operation status",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "get index operation status")

        return response

    def wait_for_insert_searchable(
        self,
        index_name: str,
        request_id: str,
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """
        Wait until an INSERT operation becomes searchable (merge completed).

        This helper polls :meth:`get_index_operation_status` until the server reports ``done=true``.
        Use this only with a ``request_id`` captured from an insert response ``header.id``.

        Parameters
        ----------
        index_name : str
            Target index name.
        request_id : str
            Server-generated insert request identifier (insert response ``header.id``). Must be non-empty
            and at most ``MAX_REQUEST_ID_LENGTH`` characters.
        timeout_s : float, optional
            Maximum time to wait (seconds).
        poll_interval_s : float, optional
            Poll interval (seconds). Increase this value for longer waits to reduce server load.

        Returns
        -------
        GetIndexOperationStatusResponse
            The last status response where ``done=true``.

        Raises
        ------
        EnvectorTimeoutError
            If the operation does not become searchable within ``timeout_s``.
        EnvectorValidationError
            If parameters are invalid.
        """
        return self.wait_for_index_operation_state(
            index_name=index_name,
            request_id=request_id,
            target_state=envector_op_pb2.SEARCHABLE,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )

    def wait_for_insert_persist_completed(
        self,
        index_name: str,
        request_id: str,
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """Wait until an INSERT-backed operation reaches persist completion."""
        return self.wait_for_index_operation_state(
            index_name=index_name,
            request_id=request_id,
            target_state=envector_op_pb2.SPLIT_COMPLETED,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )

    def wait_for_merge_complete(
        self,
        index_name: str,
        request_id: str,
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """Wait until a manual merge reaches its terminal state."""
        return self.wait_for_index_operation_state(
            index_name=index_name,
            request_id=request_id,
            target_state=envector_op_pb2.MERGED_SAVED,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )

    def wait_for_index_operation_state(
        self,
        index_name: str,
        request_id: str,
        target_state: int,
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
        operation_type: Union[str, int] = "INSERT",
        partition_name: Optional[str] = None,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """Wait until a request reaches the target lifecycle state.

        Parameters
        ----------
        operation_type : Union[str, int], optional
            Operation type for status polling (e.g. ``"INSERT"`` or ``"DELETE"``).
        """
        self._validate_request_id(request_id)
        if timeout_s <= 0:
            raise EnvectorValidationError(message="timeout_s must be > 0")
        if poll_interval_s <= 0:
            raise EnvectorValidationError(message="poll_interval_s must be > 0")

        start_time = time.monotonic()
        deadline = start_time + timeout_s
        target_state_name = _validate_index_operation_target_state(target_state)
        logger.debug(
            f"wait_for_index_operation_state: target_state={target_state_name}, timeout_s={timeout_s}, "
            f"start_time={start_time}, deadline={deadline}"
        )
        last = None
        while True:
            last = self.get_index_operation_status(
                index_name=index_name,
                request_id=request_id,
                operation_type=operation_type,
                partition_name=partition_name,
            )
            state = getattr(last, "state", envector_op_pb2.INDEX_OPERATION_STATE_UNSPECIFIED)
            if state == envector_op_pb2.FAILED:
                raise InternalError(
                    message=(
                        f"Index operation failed while waiting for {target_state_name} "
                        f"(index='{index_name}', request_id='{request_id}')."
                    ),
                    request_id=request_id,
                )
            if target_state == envector_op_pb2.SEARCHABLE and last.done:
                return last
            if _INDEX_OPERATION_STATE_RANK.get(state, -1) >= _INDEX_OPERATION_STATE_RANK.get(target_state, -1):
                return last
            now = time.monotonic()
            if now >= deadline:
                elapsed_s = now - start_time
                logger.error(
                    f"wait_for_index_operation_state TIMEOUT: target_state={target_state_name}, elapsed_s={elapsed_s:.2f}, "
                    f"timeout_s={timeout_s}, start_time={start_time}, deadline={deadline}, now={now}"
                )
                raise EnvectorTimeoutError(
                    message=(
                        f"Timed out waiting for index operation state {target_state_name} (index='{index_name}', "
                        f"request_id='{request_id}', total_row_count={last.total_row_count}, "
                        f"searchable_row_count={last.searchable_row_count}, "
                        f"elapsed={elapsed_s:.2f}s, timeout={timeout_s}s)."
                    ),
                    retryable=True,
                    action="Retry with longer timeout",
                    request_id=request_id,
                )
            time.sleep(poll_interval_s)

    def wait_for_index_operations_state(
        self,
        index_name: str,
        request_ids: Sequence[str],
        target_state: int,
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
        operation_type: Union[str, int] = "INSERT",
        partition_name: Optional[str] = None,
    ) -> List[envector_op_pb2.GetIndexOperationStatusResponse]:
        """Wait until multiple requests reach the same target lifecycle state.

        Parameters
        ----------
        operation_type : Union[str, int], optional
            Operation type for status polling (e.g. ``"INSERT"`` or ``"DELETE"``).
        """
        if not request_ids:
            raise EnvectorValidationError(message="request_ids must be non-empty")
        if timeout_s <= 0:
            raise EnvectorValidationError(message="timeout_s must be > 0")
        if poll_interval_s <= 0:
            raise EnvectorValidationError(message="poll_interval_s must be > 0")

        request_ids_list = list(request_ids)
        for req_id in request_ids_list:
            self._validate_request_id(req_id)
        if len(set(request_ids_list)) != len(request_ids_list):
            raise EnvectorValidationError(message="request_ids must not contain duplicates")

        start_time = time.monotonic()
        deadline = start_time + timeout_s
        target_state_name = envector_op_pb2.IndexOperationState.Name(target_state)
        logger.debug(
            f"wait_for_index_operations_state: target_state={target_state_name}, timeout_s={timeout_s}, "
            f"start_time={start_time}, deadline={deadline}, num_request_ids={len(request_ids_list)}"
        )

        results: List[envector_op_pb2.GetIndexOperationStatusResponse] = []
        for idx, req_id in enumerate(request_ids_list, start=1):
            now = time.monotonic()
            if now >= deadline:
                elapsed_s = now - start_time
                logger.error(
                    f"wait_for_index_operations_state TIMEOUT: target_state={target_state_name}, "
                    f"elapsed_s={elapsed_s:.2f}, timeout_s={timeout_s}, start_time={start_time}, "
                    f"deadline={deadline}, now={now}"
                )
                raise EnvectorTimeoutError(
                    message=(
                        f"Timed out waiting for index operations to reach {target_state_name} "
                        f"(index='{index_name}', next_request_id='{req_id}', completed={idx - 1}/{len(request_ids_list)}, "
                        f"elapsed={elapsed_s:.2f}s, timeout={timeout_s}s)."
                    ),
                    retryable=True,
                    action="Retry with longer timeout",
                    request_id=req_id,
                )
            results.append(
                self.wait_for_index_operation_state(
                    index_name=index_name,
                    request_id=req_id,
                    target_state=target_state,
                    timeout_s=deadline - now,
                    poll_interval_s=poll_interval_s,
                    operation_type=operation_type,
                    partition_name=partition_name,
                )
            )

        return results

    def wait_for_inserts_searchable(
        self,
        index_name: str,
        request_ids: Sequence[str],
        timeout_s: float = 60.0,
        poll_interval_s: float = 1.0,
    ) -> List[envector_op_pb2.GetIndexOperationStatusResponse]:
        """
        Wait until multiple INSERT operations become searchable (merge completed).

        This helper polls :meth:`get_index_operation_status` until the server reports ``done=true`` for
        every provided request_id. The ``timeout_s`` applies to the overall wait (not per operation).

        Parameters
        ----------
        index_name : str
            Target index name.
        request_ids : Sequence[str]
            Server-generated insert request identifiers (insert response ``header.id`` values).
        timeout_s : float, optional
            Maximum total time to wait (seconds).
        poll_interval_s : float, optional
            Poll interval (seconds).

        Returns
        -------
        List[GetIndexOperationStatusResponse]
            Status responses in the same order as ``request_ids``.

        Raises
        ------
        EnvectorTimeoutError
            If not all operations become searchable within ``timeout_s``.
        EnvectorValidationError
            If parameters are invalid.
        """
        return self.wait_for_index_operations_state(
            index_name=index_name,
            request_ids=request_ids,
            target_state=envector_op_pb2.MERGED_SAVED,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )

    def load_index(self, index_name: str):
        """
        Loads a specified index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index to be loaded.

        Returns
        -------
        None
        """
        request = envector_msg_pb2.LoadIndexRequest()
        request.header.type = envector_type_pb.MessageType.LoadIndex
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        logger.info(f"Index '{index_name}' loading...")
        response = self._call_unary_with_refresh(
            self.stub.load_index,
            request,
            "load index",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "load index")
        else:
            logger.info(f"Index '{index_name}' loaded successfully.")

    def unload_index(self, index_name: str):
        """
        Unloads a specified index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index to be unloaded.

        Returns
        -------
        None
        """
        request = envector_msg_pb2.UnloadIndexRequest()
        request.header.type = envector_type_pb.MessageType.UnloadIndex
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        response = self._call_unary_with_refresh(
            self.stub.unload_index,
            request,
            "unload index",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "unload index")
        else:
            logger.info(f"Index '{index_name}' unloaded successfully.")

    def delete_index(self, index_name: str):
        """
        Deletes a specified index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index to be deleted.

        Returns
        -------
        None
        """
        request = envector_msg_pb2.DeleteIndexRequest()
        request.header.type = envector_type_pb.MessageType.DeleteIndex
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        response = self._call_unary_with_refresh(
            self.stub.delete_index,
            request,
            "delete index",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "delete index")
        else:
            logger.info(f"Index '{index_name}' deleted successfully.")

    def clone_index(self, source_index_name: str, target_index_name: str):
        """
        Clones an index on the enVector server.

        Parameters
        ----------
        source_index_name : str
            The source index name to clone from.
        target_index_name : str
            The target index name to create.

        Returns
        -------
        Dict
            A dictionary containing the source and target index names.
        """
        request = envector_msg_pb2.CloneIndexRequest()
        request.header.type = envector_type_pb.MessageType.CloneIndex
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.source_index_name = source_index_name
        request.target_index_name = target_index_name

        response = self._call_unary_with_refresh(
            self.stub.clone_index,
            request,
            "clone index",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "clone index")

        resolved_target_name = response.target_index_name or target_index_name
        logger.info(f"Index '{source_index_name}' cloned successfully to '{resolved_target_name}'.")
        return {
            "source_index_name": source_index_name,
            "target_index_name": resolved_target_name,
        }

    ###################################
    # Partition Management
    ###################################

    def create_partition(self, index_name: str, partition_name: str):
        """Create a named partition in an index."""
        request = envector_msg_pb2.CreatePartitionRequest()
        request.header.type = envector_type_pb.MessageType.CreatePartition
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name
        request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.create_partition, request, "create partition", request_id=request.header.id
        )
        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "create partition")
        logger.info(f"Partition '{partition_name}' created in index '{index_name}'.")

    def drop_partition(self, index_name: str, partition_name: str):
        """Drop a named partition from an index."""
        request = envector_msg_pb2.DropPartitionRequest()
        request.header.type = envector_type_pb.MessageType.DropPartition
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name
        request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.drop_partition, request, "drop partition", request_id=request.header.id
        )
        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "drop partition")
        logger.info(f"Partition '{partition_name}' dropped from index '{index_name}'.")

    def list_partitions(self, index_name: str):
        """List partitions of an index as dicts {name, status, num_vectors}."""
        request = envector_msg_pb2.ListPartitionsRequest()
        request.header.type = envector_type_pb.MessageType.ListPartitions
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name

        response = self._call_unary_with_refresh(
            self.stub.list_partitions, request, "list partitions", request_id=request.header.id
        )
        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "list partitions")
        return [
            {"name": p.partition_name, "status": p.status, "num_vectors": p.num_vectors}
            for p in response.partitions
        ]

    ###################################
    # Data Management
    ###################################

    def insert_data_bulk(
        self,
        index_name: str,
        enc_vec: List[evi.Query],
        numitems: List[int],
        metadata: Optional[List[List[str]]] = None,
        centroid_idx: Optional[List[int]] = None,
        out_request_id: Optional[List[str]] = None,
    ) -> List[Any]:
        """
        Submit encrypted vectors to async split processing for bulk insert.

        To enable request-scoped completion tracking (Index Operation Status v0), pass an empty list
        as ``out_request_id``. The server-generated split request ID will be appended to it after the
        async split request completes. Use this request ID with
        :meth:`get_index_operation_status` / :meth:`wait_for_insert_persist_completed`.

        Parameters
        ----------
        index_name : str
            The name of the index where data will be inserted.
        enc_vec : List[evi.Query]
            A list of encrypted vectors to be inserted.
        numitems : List[int]
            Number of items contained in each encrypted vector (per ``enc_vec`` entry).
        metadata : Optional[List[List[str]]], optional
            Metadata per encrypted vector and per item (same shape as ``numitems``). If provided, it is
            attached only to the first chunk of each vector.
        centroid_idx : Optional[List[int]], optional
            Cluster/centroid ids to target for IVF index types. If ``None``, the request omits cluster IDs.
        out_request_id : Optional[List[str]], optional
            If provided, the server-generated request ID (from ``response.header.id``) will be appended
            to this list after the insert completes.

        Returns
        -------
        List[Any]
            Inserted item identifiers in the order they were provided.

        Raises
        ------
        EnvectorValidationError
            If parameters are invalid.
        EnvectorApplicationError
            If the server returns a failure status.
        """
        # Use a unique header ID as an async split batch API identifier.
        header_id = secrets.token_hex(10)
        normalized_centroid_idx = _normalize_cluster_id_sequence(centroid_idx, "centroid_idx")

        def insert_data_request_generator():
            # Local to each generator instance so an auth-refresh retry (which
            # re-invokes this factory) re-sends the cluster ids on the new stream.
            cluster_ids_sent = False
            for vec_idx, vec in enumerate(enc_vec):
                # Batch insert stores rows server-side, where only the first
                # `dim` b-part coefficients are consulted; truncate the zero-pad
                # tail to cut upload size (server zero-fills on decode).
                data = evi.Query.serializeToTruncated(vec)
                chunk_size = CHUNK_SIZE_257MB
                for offset in range(0, len(data), chunk_size):
                    request = envector_msg_pb2.BatchInsertDataRequest()
                    request.header.type = envector_type_pb.MessageType.PersistBatch
                    request.header.id = header_id

                    request.index_name = index_name
                    # Send cluster ids only once per stream to reduce request payload size.
                    if normalized_centroid_idx is not None and not cluster_ids_sent:
                        request.cluster_ids.extend(normalized_centroid_idx)
                        cluster_ids_sent = True
                    chunk = data[offset : offset + chunk_size]

                    packed_vector = request.packed_vectors.add()
                    packed_vector.vector.cipher_vector.id = str(vec_idx)
                    packed_vector.vector.cipher_vector.data = chunk
                    packed_vector.num_vector = numitems[vec_idx] if vec_idx < len(numitems) else 1

                    if metadata is not None and offset == 0:
                        for idx in range(packed_vector.num_vector):
                            packed_vector.metadata.append(
                                metadata[vec_idx][idx]
                                if vec_idx < len(metadata) and idx < len(metadata[vec_idx])
                                else ""
                            )

                    yield request

        response = self._call_client_stream_with_refresh(
            self.stub.persist_batch,
            insert_data_request_generator,
            "async split batch data",
            request_id=header_id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "async split batch data")

        request_id = response.header.id
        if out_request_id is not None:
            out_request_id.append(request_id)

        logger.info(f"Async split batch insert submitted for index '{index_name}'. request_id='{request_id}'")
        return list(response.item_ids)

    def async_persist_data_bulk(
        self,
        index_name: str,
        enc_vec: List[evi.Query],
        numitems: List[int],
        metadata: Optional[List[List[str]]] = None,
        centroid_idx: Optional[List[int]] = None,
        out_request_id: Optional[List[str]] = None,
        partition_name: Optional[str] = None,
    ) -> List[Any]:
        """
        Bulk insert encrypted vectors and stop at split completion.

        This uses the async split endpoint, so the returned request IDs can later be merged
        manually via :meth:`async_merge_by_request_ids`.
        """
        self._check_insertable(index_name)
        header_id = secrets.token_hex(10)
        normalized_centroid_idx = _normalize_cluster_id_sequence(centroid_idx, "centroid_idx")

        def insert_data_request_generator():
            # Local to each generator instance so an auth-refresh retry (which
            # re-invokes this factory) re-sends the cluster ids on the new stream.
            cluster_ids_sent = False
            for vec_idx, vec in enumerate(enc_vec):
                # Batch insert stores rows server-side, where only the first
                # `dim` b-part coefficients are consulted; truncate the zero-pad
                # tail to cut upload size (server zero-fills on decode).
                data = evi.Query.serializeToTruncated(vec)
                chunk_size = CHUNK_SIZE_257MB
                for offset in range(0, len(data), chunk_size):
                    request = envector_msg_pb2.BatchInsertDataRequest()
                    request.header.type = envector_type_pb.MessageType.PersistBatch
                    request.header.id = header_id

                    request.index_name = index_name
                    if partition_name:
                        request.partition_name = partition_name
                    if normalized_centroid_idx is not None and not cluster_ids_sent:
                        request.cluster_ids.extend(normalized_centroid_idx)
                        cluster_ids_sent = True
                    chunk = data[offset : offset + chunk_size]

                    packed_vector = request.packed_vectors.add()
                    packed_vector.vector.cipher_vector.id = str(vec_idx)
                    packed_vector.vector.cipher_vector.data = chunk
                    packed_vector.num_vector = numitems[vec_idx] if vec_idx < len(numitems) else 1

                    if metadata is not None and offset == 0:
                        for idx in range(packed_vector.num_vector):
                            packed_vector.metadata.append(
                                metadata[vec_idx][idx]
                                if vec_idx < len(metadata) and idx < len(metadata[vec_idx])
                                else ""
                            )

                    yield request

        response = self._call_client_stream_with_refresh(
            self.stub.persist_batch,
            insert_data_request_generator,
            "async split batch data",
            request_id=header_id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "async split batch data")

        request_id = response.header.id
        if out_request_id is not None:
            out_request_id.append(request_id)

        logger.info(f"Async split batch inserted data into index '{index_name}'. request_id='{request_id}'")
        return list(response.item_ids)

    def insert_data_rows_batch(
        self,
        index_name: str,
        enc_vecs: List[bytes],
        metadata_list: List[str],
        cluster_ids: Optional[List[int]] = None,
        out_request_id: Optional[List[str]] = None,
        partition_name: Optional[str] = None,
    ) -> List[Any]:
        """
        Submit multiple row-encrypted vectors to async split processing in one streaming RPC call.

        Parameters
        ----------
        index_name : str
            The name of the index where data will be inserted.
        enc_vecs : List[bytes]
            List of serialized encrypted vectors (one per row).
        metadata_list : List[str]
            List of metadata strings, one per vector.
        cluster_ids : Optional[List[int]]
            List of cluster IDs for IVF index types (one per vector).

        Returns
        -------
        List[Any]
            Inserted item identifiers in order.
        """
        header_id = secrets.token_hex(10)
        _validate_row_insert_lengths(enc_vecs, metadata_list, cluster_ids)

        def insert_data_request_generator():
            for vec_idx, enc_vec in enumerate(enc_vecs):
                chunk_size = CHUNK_SIZE_257MB
                # chunk_size should be larger than at least 511 * 1 Ciphertext size
                # TODO Fix this temporary check
                enc_vec_len = enc_vec.size() if hasattr(enc_vec, "size") else len(enc_vec)
                if enc_vec_len > chunk_size:
                    raise ValueError(
                        f"Vector at index {vec_idx} exceeds chunk size ({enc_vec_len} bytes > {chunk_size} bytes). "
                        "Please split the vector into smaller chunks."
                    )
                for offset in range(0, enc_vec_len, chunk_size):
                    request = envector_msg_pb2.InsertDataRequest()
                    request.header.type = envector_type_pb.MessageType.PersistRows
                    request.header.id = header_id
                    request.index_name = index_name
                    if partition_name:
                        request.partition_name = partition_name

                    if cluster_ids is not None:
                        request.cluster_id = cluster_ids[vec_idx]

                    chunk = enc_vec[offset : offset + chunk_size]
                    packed_vector = request.packed_vectors.add()
                    packed_vector.vector.cipher_vector.id = str(vec_idx)
                    packed_vector.vector.cipher_vector.data = chunk
                    packed_vector.num_vector = 1

                    if offset == 0:
                        packed_vector.metadata.append(metadata_list[vec_idx])

                    yield request

        response = self._call_client_stream_with_refresh(
            self.stub.persist_rows,
            insert_data_request_generator,
            "async split data",
            request_id=header_id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "async split data")

        request_id = response.header.id
        if out_request_id is not None:
            out_request_id.append(request_id)

        logger.info(f"Async split row insert submitted for index '{index_name}'. request_id='{request_id}'")
        return list(response.item_ids)

    def async_persist_data_rows_batch(
        self,
        index_name: str,
        enc_vecs: List[bytes],
        metadata_list: List[str],
        cluster_ids: Optional[List[int]] = None,
        out_request_id: Optional[List[str]] = None,
        partition_name: Optional[str] = None,
    ) -> List[Any]:
        """
        Insert multiple row-encrypted vectors and stop at split completion.

        This uses the async split endpoint, so the returned request IDs can later be merged
        manually via :meth:`async_merge_by_request_ids`.
        """
        header_id = secrets.token_hex(10)
        _validate_row_insert_lengths(enc_vecs, metadata_list, cluster_ids)

        def insert_data_request_generator():
            for vec_idx, enc_vec in enumerate(enc_vecs):
                chunk_size = CHUNK_SIZE_257MB
                enc_vec_len = enc_vec.size() if hasattr(enc_vec, "size") else len(enc_vec)
                if enc_vec_len > chunk_size:
                    raise ValueError(
                        f"Vector at index {vec_idx} exceeds chunk size ({enc_vec_len} bytes > {chunk_size} bytes). "
                        "Please split the vector into smaller chunks."
                    )
                for offset in range(0, enc_vec_len, chunk_size):
                    request = envector_msg_pb2.InsertDataRequest()
                    request.header.type = envector_type_pb.MessageType.PersistRows
                    request.header.id = header_id
                    request.index_name = index_name
                    if partition_name:
                        request.partition_name = partition_name

                    if cluster_ids is not None:
                        request.cluster_id = cluster_ids[vec_idx]

                    chunk = enc_vec[offset : offset + chunk_size]
                    packed_vector = request.packed_vectors.add()
                    packed_vector.vector.cipher_vector.id = str(vec_idx)
                    packed_vector.vector.cipher_vector.data = chunk
                    packed_vector.num_vector = 1

                    if offset == 0:
                        packed_vector.metadata.append(metadata_list[vec_idx])

                    yield request

        response = self._call_client_stream_with_refresh(
            self.stub.persist_rows,
            insert_data_request_generator,
            "async split data",
            request_id=header_id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "async split data")

        request_id = response.header.id
        if out_request_id is not None:
            out_request_id.append(request_id)

        logger.info(f"Async split inserted {len(enc_vecs)} rows into index '{index_name}'. request_id='{request_id}'")
        return list(response.item_ids)

    def async_merge_by_request_ids(
        self,
        index_name: str,
        request_ids: Optional[Sequence[str]] = None,
        partition_name: Optional[str] = None,
    ) -> str:
        """Submit an async merge request for previously split insert request IDs.

        When ``request_ids`` is empty or ``None``, the server auto-expands to all
        eligible split-only operations on this index; if every eligible op is
        already in an active manual-merge group, the call returns success as a
        no-op.
        """
        request_ids_list = list(request_ids) if request_ids is not None else []
        for request_id in request_ids_list:
            self._validate_request_id(request_id)
        if len(set(request_ids_list)) != len(request_ids_list):
            raise EnvectorValidationError(message="request_ids must not contain duplicates")

        request = envector_msg_pb2.MergeByRequestIdsRequest()
        request.header.type = envector_type_pb.MessageType.MergeByRequestIds
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name
        request.request_ids.extend(request_ids_list)
        if partition_name:
            request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.merge_by_request_ids,
            request,
            "async merge by request ids",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "async merge by request ids")

        merge_request_id = response.header.id
        logger.info(
            f"Async merge submitted for index '{index_name}' with {len(request_ids_list)} split request(s). "
            f"request_id='{merge_request_id}'"
        )
        return merge_request_id

    @staticmethod
    def _validate_request_id(request_id: Optional[str]) -> None:
        if request_id is None:
            return
        if not isinstance(request_id, str):
            raise EnvectorValidationError(message="request_id must be a str")
        if request_id == "":
            raise EnvectorValidationError(message="request_id must be non-empty")
        if len(request_id) > MAX_REQUEST_ID_LENGTH:
            raise EnvectorValidationError(
                message=f"request_id must be <= {MAX_REQUEST_ID_LENGTH} characters",
            )

    ###################################
    # Delete APIs
    ###################################

    def delete_data(
        self,
        index_name: str,
        item_ids: List[int],
        partition_name: Optional[str] = None,
    ) -> str:
        """
        Submit a DeleteData request to remove items from an index.

        Items are identified by ``item_id`` values originally returned by InsertData responses.

        The server returns as soon as Phase 1 completes: target items are marked
        for search exclusion and merge tasks are registered for physical
        destruction. Shard rebuild, S3 cleanup, and compute-memory unload proceed
        asynchronously. Use :meth:`wait_for_delete_completion` to observe the
        ``SEARCHABLE`` transition that marks full completion.

        Parameters
        ----------
        index_name : str
            The name of the index from which items will be deleted.
        item_ids : List[int]
            List of item IDs to delete. These are the ``item_id`` values returned by
            :meth:`insert_data_bulk`, :meth:`insert_data_rows_batch`, or ``Index.insert()``.

        Returns
        -------
        str
            Server-generated ``request_id`` for tracking operation completion via
            :meth:`get_index_operation_status` with ``operation_type="DELETE"``.

        Raises
        ------
        EnvectorValidationError
            If ``index_name`` is empty, ``item_ids`` is empty, contains duplicates,
            or contains non-positive values.
        EnvectorApplicationError
            If the server returns a failure status.
        EnvectorTransportError
            If the gRPC call fails.
        """
        if not index_name:
            raise EnvectorValidationError(message="index_name must be non-empty")
        if not item_ids:
            raise EnvectorValidationError(message="item_ids must be non-empty")
        if not all(isinstance(i, int) and not isinstance(i, bool) for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only int values")
        if not all(i > 0 for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only positive integers (> 0)")
        if len(set(item_ids)) != len(item_ids):
            raise EnvectorValidationError(message="item_ids must not contain duplicates")

        request = envector_msg_pb2.DeleteDataRequest()
        request.header.type = envector_type_pb.MessageType.DeleteData
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name
        # item_ids: values returned by InsertData response (auto-increment PK, must be > 0)
        request.item_ids.extend(item_ids)
        if partition_name:
            request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.delete_data,
            request,
            "delete data",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "delete data")

        request_id = response.header.id
        logger.info(f"DeleteData submitted for index '{index_name}' with {len(item_ids)} item(s). request_id='{request_id}'")
        return request_id

    def update_metadata(
        self, index_name: str, item_ids: List[int], data_strings: List[str], partition_name: Optional[str] = None
    ) -> dict:
        """
        Submit an UpdateMetadata request to replace the metadata of existing items.

        Items are identified by ``item_id`` (values returned by InsertData). Each
        ``data_strings[i]`` is the full, already-encoded metadata string for
        ``item_ids[i]`` — :meth:`Index.update_metadata` encodes (and, when
        metadata_encryption is enabled, encrypts) each full value before calling
        this; the server replaces the stored string wholesale (last-writer-wins).

        Parameters
        ----------
        index_name : str
            The index whose item metadata is updated.
        item_ids : List[int]
            Positive, unique item IDs to update.
        data_strings : List[str]
            Full replacement metadata strings, one per ``item_ids`` entry (same order).

        Returns
        -------
        dict
            ``{"updated_count": int, "not_found_item_ids": List[int]}``. Missing or
            soft-deleted items are reported in ``not_found_item_ids``; the request
            still succeeds (lenient semantics).

        Raises
        ------
        EnvectorValidationError
            If ``index_name`` is empty, ``item_ids`` is empty/non-positive/duplicated,
            or ``data_strings`` length does not match ``item_ids``.
        EnvectorApplicationError
            If the server returns a failure status.
        EnvectorTransportError
            If the gRPC call fails.
        """
        if not index_name:
            raise EnvectorValidationError(message="index_name must be non-empty")
        if not item_ids:
            raise EnvectorValidationError(message="item_ids must be non-empty")
        if not all(isinstance(i, int) and not isinstance(i, bool) for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only int values")
        if not all(i > 0 for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only positive integers (> 0)")
        if len(set(item_ids)) != len(item_ids):
            raise EnvectorValidationError(message="item_ids must not contain duplicates")
        if len(data_strings) != len(item_ids):
            raise EnvectorValidationError(message="data_strings length must match item_ids length")

        request = envector_msg_pb2.UpdateMetadataRequest()
        request.header.type = envector_type_pb.MessageType.UpdateMetadata
        request.header.id = secrets.token_hex(10)
        request.index_name = index_name
        if partition_name:
            request.partition_name = partition_name
        for item_id, data in zip(item_ids, data_strings):
            u = request.updates.add()
            u.item_id = item_id
            u.data = data

        response = self._call_unary_with_refresh(
            self.stub.update_metadata,
            request,
            "update metadata",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "update metadata")

        logger.info(
            f"UpdateMetadata for index '{index_name}': updated={response.updated_count}, "
            f"not_found={len(response.not_found_item_ids)}"
        )
        return {
            "updated_count": int(response.updated_count),
            "not_found_item_ids": list(response.not_found_item_ids),
        }

    def wait_for_delete_completion(
        self,
        index_name: str,
        request_id: str,
        timeout_s: float = 600.0,
        poll_interval_s: float = 1.0,
        partition_name: Optional[str] = None,
    ) -> envector_op_pb2.GetIndexOperationStatusResponse:
        """
        Wait until a DELETE operation completes (shard rebuild becomes searchable).

        Polls :meth:`get_index_operation_status` with ``operation_type=DELETE`` until the
        server reports the operation has reached SEARCHABLE state.

        Parameters
        ----------
        index_name : str
            Target index name.
        request_id : str
            Server-generated request identifier from :meth:`delete_data`.
        timeout_s : float, optional
            Maximum time to wait (seconds). Default: 600s.
        poll_interval_s : float, optional
            Poll interval (seconds). Default: 1s.

        Returns
        -------
        GetIndexOperationStatusResponse
            The last status response when the operation reaches SEARCHABLE.

        Raises
        ------
        EnvectorTimeoutError
            If the operation does not complete within ``timeout_s``.
        """
        return self.wait_for_index_operation_state(
            index_name=index_name,
            request_id=request_id,
            target_state=envector_op_pb2.SEARCHABLE,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
            operation_type="DELETE",
            partition_name=partition_name,
        )

    ###################################
    # Search APIs
    ###################################

    def search(
        self,
        index_name: str,
        query: List[List[float]],
        topk: Sequence[Sequence[int]] = (),
        nprobe: int = None,
        level: Optional[int] = None,
        partition_names: Optional[List[str]] = None,
    ):
        """
        Performs encrypted similarity search on the specified index from enVector server.
        enVector server performs secure homomorphic encryption operations with the registered evaluation key.

        Parameters
        ----------
        index_name : str
            The name of the index to search.
        query : List[List[float]]
            A list of query vectors to search for.

        Returns
        -------
        List[evi.CiphertextLv0]
            A list of search results, or None if the request failed.
        """
        # PC Search gRPC call
        request = envector_msg_pb2.InnerProductRequest()
        request.header.type = envector_type_pb.MessageType.InnerProduct
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name
        if nprobe is not None:
            request.nprobe = nprobe
        if partition_names:
            request.partition_names.extend(partition_names)

        for i, q in enumerate(query):
            dt = envector_type_pb.DataType()
            dt.plain_vector.id = f"id-{secrets.token_hex(5)}"
            dt.plain_vector.data.extend(q)
            dt.plain_vector.dim = len(q)
            if level is not None:
                dt.plain_vector.level = int(level)
            request.query_vector.append(dt)
            if len(topk) > 0:
                request.cluster_infos.append(envector_type_pb.CentroidsList())
                for idx in topk[i]:
                    request.cluster_infos[-1].centroids.append(idx)

        query_ids = [dt.plain_vector.id for dt in request.query_vector]

        try:
            response_stream = self.stub.inner_product(
                request,
                metadata=self.grpc_metadata,
            )
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "search", request_id=request.header.id) from e

        shard_idx = {k: [] for k in query_ids}
        results = {k: [] for k in query_ids}
        partition_by_query = {k: "" for k in query_ids}
        try:
            for response in response_stream:
                if response.header.return_code != envector_type_pb.ReturnCode.Success:
                    raise self._to_application_error(response.header, "search")
                if len(response.ctxt_score) == 0:
                    logger.warning(f"Index '{index_name}' returned empty scores. The index may be empty.")
                    return []
                output = response.ctxt_score[0]
                results[output.id].append(output.ctxt_score[0])
                shard_idx[output.id].extend(output.shard_idx)
                if output.partition_name:
                    partition_by_query[output.id] = output.partition_name
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "search (stream)", request_id=request.header.id) from e

        outputs = [
            envector_type_pb.CiphertextScore(
                id=query_id,
                ctxt_score=results[query_id],
                shard_idx=shard_idx[query_id],
                partition_name=partition_by_query[query_id],
            )
            for query_id in query_ids
        ]

        results.clear()
        shard_idx.clear()
        del results, shard_idx

        return outputs

    def encrypted_search(self, index_name: str, enc_query: List[CipherBlock], topk: Sequence[Sequence[int]] = (), partition_names: Optional[List[str]] = None):
        """
        Performs encrypted similarity search on the specified index from enVector server.
        enVector server performs secure homomorphic encryption operations with the registered evaluation key.

        Parameters
        ----------
        index_name : str
            The name of the index to search.
        query : List[CipherBlock]
            A list of encrypted query vectors to search for.

        Returns
        -------
        List[evi.CiphertextLv0]
            A list of search results, or None if the request failed.
        """
        # CC Search gRPC call
        request = envector_msg_pb2.InnerProductRequest()
        request.header.type = envector_type_pb.MessageType.InnerProduct
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name
        if partition_names:
            request.partition_names.extend(partition_names)

        for i, vec in enumerate(enc_query):
            dt = envector_type_pb.DataType()
            dt.cipher_vector.id = f"id-{secrets.token_hex(5)}"
            dt.cipher_vector.data = vec.serialize()
            request.query_vector.append(dt)
            if len(topk) > 0:
                request.cluster_infos.append(envector_type_pb.CentroidsList())
                for idx in topk[i]:
                    request.cluster_infos[-1].centroids.append(idx)

        query_ids = [dt.cipher_vector.id for dt in request.query_vector]

        try:
            response_stream = self.stub.inner_product(
                request,
                metadata=self.grpc_metadata,
            )
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "encrypted search", request_id=request.header.id) from e

        shard_idx = {k: [] for k in query_ids}
        results = {k: [] for k in query_ids}
        partition_by_query = {k: "" for k in query_ids}
        try:
            for response in response_stream:
                if response.header.return_code != envector_type_pb.ReturnCode.Success:
                    raise self._to_application_error(response.header, "encrypted search")
                if len(response.ctxt_score) == 0:
                    logger.warning(f"Index '{index_name}' returned empty scores. The index may be empty.")
                    return []
                output = response.ctxt_score[0]
                results[output.id].append(output.ctxt_score[0])
                shard_idx[output.id].extend(output.shard_idx)
                if output.partition_name:
                    partition_by_query[output.id] = output.partition_name
        except grpc.RpcError as e:
            raise self._normalize_transport_error(e, "encrypted search (stream)", request_id=request.header.id) from e

        outputs = [
            envector_type_pb.CiphertextScore(
                id=query_id,
                ctxt_score=results[query_id],
                shard_idx=shard_idx[query_id],
                partition_name=partition_by_query[query_id],
            )
            for query_id in query_ids
        ]

        results.clear()
        shard_idx.clear()
        del results, shard_idx

        return outputs

    ###################################
    # Query APIs
    ###################################

    def get_metadata(self, index_name: str, idx: Union[List, Tuple], fields: Sequence[str] = (), partition_name: Optional[str] = None):
        """
        Retrieves metadata for specified indices and output fields in an index from enVector server.

        Parameters
        ----------
        index_name : str
            The name of the index from which to retrieve metadata.
        idx : Union[List, Tuple]
            A list of Position objects specifying the shard and row indices for metadata retrieval.
        fields : List[str]
            A list of field names to retrieve from the metadata.
            The default is an empty list, which does not retrieve metadata.

        Returns
        -------
        Optional[List]
            A list of metadata entries for the specified positions and fields, or None if the request failed.
        """
        request = envector_msg_pb2.GetMetadataRequest()
        request.header.type = envector_type_pb.MessageType.GetMetadata
        request.header.id = secrets.token_hex(10)  # unique header ID
        request.index_name = index_name

        if isinstance(idx, list) or isinstance(idx, tuple):
            if isinstance(idx[0], dict):
                for position in idx:
                    pos = request.idx.add()
                    pos.shard_idx = position["shard_idx"]
                    pos.row_idx = position["row_idx"]

            elif isinstance(idx[0], list) or isinstance(idx[0], tuple):
                for position in idx:
                    pos = request.idx.add()
                    pos.shard_idx = position[0]
                    pos.row_idx = position[1]

        else:
            raise EnvectorValidationError(
                message=f"Ambiguous format for idx: {type(idx)}. Expected 'List[Position]' or 'List[List[int]]'.",
            )

        if fields:
            for field in fields:
                request.output_fields.append(field)

        if partition_name:
            request.partition_name = partition_name

        response = self._call_unary_with_refresh(
            self.stub.get_metadata,
            request,
            "get metadata",
            request_id=request.header.id,
        )

        if response.header.return_code != envector_type_pb.ReturnCode.Success:
            raise self._to_application_error(response.header, "get metadata")
        else:
            logger.info(f"Metadata for index '{index_name}' received successfully.")
            return list(response.metadata)
