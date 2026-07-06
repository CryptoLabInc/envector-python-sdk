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

"""gRPC client for enVector Key Management Services.

Wraps the managed KMS gateway behind a single ``KMSClient`` facade.
The gRPC channel is created lazily on first use and can be closed via
:meth:`close`.

Authentication mirrors :class:`pyenvector.api.grpc.Indexer`: the client owns
an :class:`pyenvector.api.auth_session._AuthSession` and refreshes the bearer
token in-place when an RPC fails with UNAUTHENTICATED/PERMISSION_DENIED. When
used alongside an ``Indexer`` (typically via ``EnvectorClient``), pass the
indexer's session as ``auth_session=...`` so both clients refresh in lockstep
and observe the same access-token string.
"""

import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Union

import grpc

from pyenvector.api.auth_session import (
    AccessTokenInput,
    _AuthSession,
    is_auth_return_code,
    is_auth_rpc_error,
)
from pyenvector.api.connection import Connection
from pyenvector.errors import EnvectorTransportError, KeyManagementError
from pyenvector.proto_gen.v2.common import common_message_pb2 as common_pb2
from pyenvector.proto_gen.v2.common import type_pb2
from pyenvector.proto_gen.v2.kms import kms_api_pb2 as kms_pb2
from pyenvector.proto_gen.v2.kms import kms_api_pb2_grpc as kms_grpc
from pyenvector.proto_gen.v2.kms import kms_message_pb2 as kms_msg_pb2
from pyenvector.utils.logging_config import logger


def _make_request_header():
    """Build a minimal ES2 RequestHeader for KMS RPCs."""
    return common_pb2.RequestHeader(
        id=secrets.token_hex(8),
        timestamp=int(time.time()),
    )


def _check_response(response, rpc_name: str):
    """Raise on non-Success return_code inside an ES2.ResponseHeader."""
    header = response.header
    rc = header.return_code
    # ReturnCode.Success == 1 in the proto enum.
    if rc != type_pb2.Success:
        err_msg = header.error_message if header.HasField("error_message") else ""
        raise KeyManagementError(
            f"KMS {rpc_name} failed (return_code={rc}): {err_msg}",
            return_code=rc,
        )



class KMSClient:
    """Client for the managed enVector KMS gateway.

    All gRPC services are accessed through a single gateway address.

    Parameters
    ----------
    address : str
        ``host:port`` of the KMS API Gateway (gRPC).
    secure : bool, optional
        Use TLS channels. Defaults to ``True``.
    access_token : str or callable, optional
        Bearer token string, or a callable returning the current token. Ignored
        when ``auth_session`` is provided.
    refresh_token : str, optional
        OIDC refresh token. When provided with ``client_id`` and either
        ``token_endpoint`` or ``oidc_issuer``, the SDK refreshes the bearer
        token internally on UNAUTHENTICATED/PERMISSION_DENIED responses.
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
    ca_cert : str or bytes, optional
        PEM CA bundle used to verify the KMS TLS certificate.
        Pass a ``str`` file path or ``bytes`` PEM data directly.
    auth_session : _AuthSession, optional
        A pre-built session to reuse. When this client is instantiated
        alongside an :class:`Indexer` (e.g. by ``EnvectorClient``), passing the
        indexer's ``_auth_session`` here makes both clients share the same
        token state — refresh happens once and the new access token is visible
        to both. When omitted, a fresh ``_AuthSession`` is built from the
        other auth parameters.
    """

    def __init__(
        self,
        address: str,
        secure: bool = True,
        access_token: AccessTokenInput = None,
        refresh_token: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        ca_cert: Union[str, bytes, None] = None,
        auth_session: Optional[_AuthSession] = None,
    ):
        self._address = address
        self._secure = secure
        self._ca_cert = ca_cert

        if auth_session is not None:
            self._auth_session = auth_session
        else:
            self._auth_session = _AuthSession(
                access_token=access_token,
                refresh_token=refresh_token,
                oidc_issuer=oidc_issuer,
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
            )

        self._conn: Optional[Connection] = None
        self._keygen_stub: Optional[kms_grpc.KeyManagerServiceStub] = None
        self._topk_stub: Optional[kms_grpc.TopKServiceStub] = None

    # ------------------------------------------------------------------
    # Connection (single gateway)
    # ------------------------------------------------------------------

    @property
    def _access_token(self) -> Optional[str]:
        """Live access token from the underlying auth session (post-refresh aware)."""
        return self._auth_session.get_access_token() if self._auth_session else None

    @property
    def _grpc_metadata(self) -> List:
        """Live gRPC metadata; reads from ``_auth_session`` so refreshed tokens are picked up."""
        token = self._access_token
        if not token:
            return []
        return [("authorization", f"Bearer {token}")]

    def _ensure_connected(self):
        if self._conn is None:
            self._conn = Connection(
                self._address,
                secure=self._secure,
                ca_cert=self._ca_cert,
            )
            if not self._conn.is_connected():
                raise EnvectorTransportError(f"Cannot connect to KMS at {self._address}")
            channel = self._conn.get_channel()
            self._keygen_stub = kms_grpc.KeyManagerServiceStub(channel)
            self._topk_stub = kms_grpc.TopKServiceStub(channel)
            logger.debug("Connected to KMS at %s", self._address)

    def _ensure_keygen(self):
        try:
            self._ensure_connected()
        except EnvectorTransportError as exc:
            raise EnvectorTransportError(f"Cannot connect to KeyManagerService at {self._address}") from exc

    def _ensure_topk(self):
        try:
            self._ensure_connected()
        except EnvectorTransportError as exc:
            raise EnvectorTransportError(f"Cannot connect to TopKService at {self._address}") from exc

    # ------------------------------------------------------------------
    # Refresh-aware RPC invocation
    # ------------------------------------------------------------------

    def _refresh_access_token(self) -> bool:
        if self._auth_session is None or not self._auth_session.can_refresh():
            return False
        refreshed = self._auth_session.refresh_access_token()
        logger.info("Refreshed access token for KMS %s", self._address)
        return bool(refreshed)

    def _call_unary_with_refresh(
        self,
        rpc: Callable[[List], Any],
        operation: str,
    ):
        """Invoke a unary RPC and retry once after an OIDC refresh on auth failure.

        ``rpc`` receives the freshly-resolved gRPC metadata so the retry attempt
        uses the post-refresh token, not the snapshot from before the failure.
        """
        allow_refresh = self._auth_session is not None and self._auth_session.can_refresh()
        attempt = 0
        while True:
            metadata = self._grpc_metadata
            try:
                response = rpc(metadata)
            except grpc.RpcError as exc:
                if attempt == 0 and allow_refresh and is_auth_rpc_error(exc):
                    if self._refresh_access_token():
                        attempt += 1
                        continue
                raise EnvectorTransportError(f"{operation} RPC failed: {exc}") from exc

            if (
                attempt == 0
                and allow_refresh
                and hasattr(response, "header")
                and is_auth_return_code(getattr(response.header, "return_code", None))
                and self._refresh_access_token()
            ):
                attempt += 1
                continue
            return response

    def _call_stream_with_refresh(
        self,
        rpc: Callable[[List], Any],
        operation: str,
    ) -> List[Any]:
        """Invoke a server-streaming RPC and retry once on auth failure.

        Materializes the stream into a list so a refresh+retry can start cleanly
        from the first message. KMS streams (e.g. ``DownloadKey``) are small
        enough that buffering them matches the existing chunk-collection path.
        """
        allow_refresh = self._auth_session is not None and self._auth_session.can_refresh()
        attempt = 0
        while True:
            metadata = self._grpc_metadata
            try:
                response_iter = rpc(metadata)
                responses = list(response_iter)
            except grpc.RpcError as exc:
                if attempt == 0 and allow_refresh and is_auth_rpc_error(exc):
                    if self._refresh_access_token():
                        attempt += 1
                        continue
                raise EnvectorTransportError(f"{operation} RPC failed: {exc}") from exc

            if (
                attempt == 0
                and allow_refresh
                and responses
                and hasattr(responses[0], "header")
                and is_auth_return_code(getattr(responses[0].header, "return_code", None))
                and self._refresh_access_token()
            ):
                attempt += 1
                continue
            return responses

    # ------------------------------------------------------------------
    # KeyManagerService RPCs
    # ------------------------------------------------------------------

    def generate_key(
        self,
        key_id: str,
        metadata_encryption: Optional[bool] = None,
        preset: Optional[str] = None,
        eval_mode: Optional[str] = None,
        seed: Optional[bytes] = None,
    ) -> Dict[str, object]:
        """Generate the KMS-managed key bundle for ``key_id``.

        Parameters
        ----------
        key_id : str
            Client-specified identifier for the key.
        metadata_encryption : bool, optional
            Whether to enable metadata encryption. Defaults to server-side default (True).
        preset : str, optional
            Parameter preset (e.g. ``"IP1"``).
        eval_mode : str, optional
            Evaluation mode (e.g. ``"MM"``).
        seed : bytes, optional
            64-byte seed for deterministic key generation. The same seed always
            produces the same key material. Accepts raw ``bytes`` or a 128-character
            hex string (converted automatically).
        """
        self._ensure_keygen()
        if isinstance(seed, str):
            try:
                seed = bytes.fromhex(seed)
            except ValueError as exc:
                raise ValueError("seed hex string must contain only valid hexadecimal characters") from exc
        if seed is not None and len(seed) != 64:
            raise ValueError(f"seed must be exactly 64 bytes, got {len(seed)}")
        request_kwargs = {
            "header": _make_request_header(),
            "key_id": key_id,
        }
        if metadata_encryption is not None:
            request_kwargs["metadata_encryption_enabled"] = metadata_encryption
        if preset is not None:
            request_kwargs["preset"] = preset
        if eval_mode is not None:
            request_kwargs["eval_mode"] = eval_mode
        if seed is not None:
            request_kwargs["seed"] = seed
        request = kms_pb2.GenerateKeyRequest(**request_kwargs)
        response = self._call_unary_with_refresh(
            lambda md: self._keygen_stub.GenerateKey(request, metadata=md),
            "GenerateKey",
        )
        _check_response(response, "GenerateKey")
        return {
            "key_id": response.key_id,
            "version": response.version,
            "status": kms_msg_pb2.KeyGenStatus.Name(response.status),
        }

    def get_key_status(self, key_id: str) -> Dict[str, object]:
        """Poll the status of an async key generation job."""
        self._ensure_keygen()
        request = kms_pb2.GetKeyStatusRequest(
            header=_make_request_header(),
            key_id=key_id,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._keygen_stub.GetKeyStatus(request, metadata=md),
            "GetKeyStatus",
        )
        _check_response(response, "GetKeyStatus")
        return {
            "key_id": response.key_id,
            "status": kms_msg_pb2.KeyGenStatus.Name(response.status),
        }

    def get_key_details(self, key_id: str) -> Dict[str, object]:
        """Return version metadata for ``key_id``.

        The response includes the version number, state, key type, and audit
        metadata for each stored version.
        """
        self._ensure_keygen()
        request = kms_pb2.GetKeyDetailsRequest(
            header=_make_request_header(),
            key_id=key_id,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._keygen_stub.GetKeyDetails(request, metadata=md),
            "GetKeyDetails",
        )
        _check_response(response, "GetKeyDetails")
        return {
            "key_id": response.key_id,
            "versions": [
                {
                    "version": item.version,
                    "state": kms_msg_pb2.KeyState.Name(item.state),
                    "key_type": kms_msg_pb2.KeyType.Name(item.key_type),
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                    "actor": item.actor,
                }
                for item in response.versions
            ],
        }

    def wait_for_key(
        self,
        key_id: str,
        timeout: float = 120,
        poll_interval: float = 1.0,
    ) -> Dict[str, object]:
        """Poll ``get_key_status`` until READY, FAILED, or timeout.

        Raises
        ------
        TimeoutError
            If the key does not reach a terminal state within ``timeout``.
        KeyManagementError
            If key generation reaches a FAILED state.
        """
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_key_status(key_id)
            status_str = str(status.get("status", ""))
            if "READY" in status_str:
                return status
            if "FAILED" in status_str:
                raise KeyManagementError(f"Key generation failed for {key_id}: {status}")
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Key {key_id} did not become ready within {timeout}s (last status: {status_str})")
            time.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Key download
    # ------------------------------------------------------------------

    def download_enc_key(self, key_id: str) -> bytes:
        """Download the raw wrapped EncKey for ``key_id`` via KMS gRPC."""
        return self._download_key(key_id, kms_pb2.KEY_FILE_TYPE_ENC_KEY)

    def download_eval_key(self, key_id: str) -> bytes:
        """Download the raw wrapped EvalKey for ``key_id`` via KMS gRPC."""
        return self._download_key(key_id, kms_pb2.KEY_FILE_TYPE_EVAL_KEY)

    def _download_key(self, key_id: str, file_type: int) -> bytes:
        """Download a key file via server-streaming gRPC and reassemble its chunks."""
        self._ensure_keygen()
        request = kms_pb2.DownloadKeyRequest(
            header=_make_request_header(),
            key_id=key_id,
            file_type=file_type,
        )
        responses = self._call_stream_with_refresh(
            lambda md: self._keygen_stub.DownloadKey(request, metadata=md),
            "DownloadKey",
        )
        if not responses:
            return b""

        chunks: List[bytes] = []
        for response in responses:
            _check_response(response, "DownloadKey")
            if response.content:
                chunks.append(response.content)
            if response.eof:
                break
        return b"".join(chunks)

    # ------------------------------------------------------------------
    # Metadata Encrypt/Decrypt RPCs (via TopKService)
    # ------------------------------------------------------------------

    def encrypt_metadata(
        self,
        key_id: str,
        plaintext_metadata: List[str],
    ) -> List[bytes]:
        """Encrypt plaintext metadata strings via KMS.

        The metadata key remains inside KMS. Clients send plaintext and
        receive ciphertext bytes.
        """
        self._ensure_topk()
        request = kms_pb2.EncryptMetadataRequest(
            header=_make_request_header(),
            key_id=key_id,
            plaintext_metadata=plaintext_metadata,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._topk_stub.EncryptMetadata(request, metadata=md),
            "EncryptMetadata",
        )
        _check_response(response, "EncryptMetadata")
        return list(response.encrypted_metadata)

    def decrypt_metadata(
        self,
        key_id: str,
        encrypted_metadata: List[bytes],
    ) -> List[str]:
        """Decrypt metadata ciphertexts via KMS.

        The metadata key remains inside KMS. Clients send ciphertext and
        receive plaintext strings.
        """
        self._ensure_topk()
        request = kms_pb2.DecryptMetadataRequest(
            header=_make_request_header(),
            key_id=key_id,
            encrypted_metadata=encrypted_metadata,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._topk_stub.DecryptMetadata(request, metadata=md),
            "DecryptMetadata",
        )
        _check_response(response, "DecryptMetadata")
        return list(response.plaintext_metadata)

    def topk(
        self,
        key_id: str,
        encrypted_scores: list,
        k: int,
        score_threshold: Optional[float] = None,
        shard_indices: Optional[List[int]] = None,
    ) -> List["kms_msg_pb2.TopKResult"]:
        """Decrypt encrypted scores via KMS and return ranked TopK results.

        ``shard_indices`` can be provided to restrict evaluation to a subset
        of shards when the caller already knows the search partition.
        """
        self._ensure_topk()
        kwargs = {
            "header": _make_request_header(),
            "key_id": key_id,
            "encrypted_scores": encrypted_scores,
            "k": k,
        }
        if score_threshold is not None:
            kwargs["score_threshold"] = score_threshold
        if shard_indices:
            kwargs["shard_indices"] = shard_indices
        request = kms_pb2.TopKRequest(**kwargs)
        response = self._call_unary_with_refresh(
            lambda md: self._topk_stub.TopK(request, metadata=md),
            "TopK",
        )
        _check_response(response, "TopK")
        return list(response.results)

    def transition_state(
        self,
        key_id: str,
        *,
        version: Optional[int] = None,
        new_state: int,
        reason: str,
    ):
        """Transition the latest key version to a new lifecycle state.

        .. note::
            ``version`` is reserved for future per-version targeting and is
            not yet supported. Passing a non-None value raises
            ``NotImplementedError``.
        """
        if version is not None:
            raise NotImplementedError(
                "Per-version state transition is not yet supported. "
                "Omit the version argument to transition the latest key version."
            )
        self._ensure_keygen()
        request = kms_pb2.TransitionStateRequest(
            header=_make_request_header(),
            key_id=key_id,
            new_state=new_state,
            reason=reason,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._keygen_stub.TransitionState(request, metadata=md),
            "TransitionState",
        )
        _check_response(response, "TransitionState")
        return True

    def rotate_key(self, key_id: str, reason: str, *, version: Optional[int] = None):
        """Rotate the key's Vault Transit KEK and rewrap the latest sealed material."""
        return self.transition_state(
            key_id=key_id,
            version=version,
            new_state=kms_msg_pb2.KEY_STATE_ROTATING,
            reason=reason,
        )

    def suspend_key(self, key_id: str, reason: str, *, version: Optional[int] = None):
        """Suspend the latest key version."""
        return self.transition_state(
            key_id=key_id,
            version=version,
            new_state=kms_msg_pb2.KEY_STATE_SUSPENDED,
            reason=reason,
        )

    def destroy_key(self, key_id: str, reason: str, *, version: Optional[int] = None):
        """Destroy the latest key version irreversibly."""
        return self.transition_state(
            key_id=key_id,
            version=version,
            new_state=kms_msg_pb2.KEY_STATE_DESTROYED,
            reason=reason,
        )

    def delete_key(self, key_id: str, reason: str):
        """Schedule a key for deletion via the managed gateway."""
        self._ensure_keygen()
        request = kms_pb2.DeleteRequest(
            header=_make_request_header(),
            key_id=key_id,
            reason=reason,
        )
        response = self._call_unary_with_refresh(
            lambda md: self._keygen_stub.Delete(request, metadata=md),
            "Delete",
        )
        _check_response(response, "Delete")
        return True

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def health_check_keygen(self) -> bool:
        """Health check for KeyManagerService."""
        self._ensure_keygen()
        request = common_pb2.HeartbeatRequest(header=_make_request_header())
        try:
            response = self._call_unary_with_refresh(
                lambda md: self._keygen_stub.Health(request, metadata=md),
                "Health",
            )
            return response.header.return_code == type_pb2.Success
        except EnvectorTransportError:
            return False

    def health_check_topk(self) -> bool:
        """Health check for TopKService."""
        self._ensure_topk()
        request = common_pb2.HeartbeatRequest(header=_make_request_header())
        try:
            response = self._call_unary_with_refresh(
                lambda md: self._topk_stub.Health(request, metadata=md),
                "Health",
            )
            return response.header.return_code == type_pb2.Success
        except EnvectorTransportError:
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self):
        """Close the gRPC channel."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = None
        self._keygen_stub = None
        self._topk_stub = None
        logger.debug("KMSClient connection closed")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
