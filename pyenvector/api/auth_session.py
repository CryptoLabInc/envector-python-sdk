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

"""Shared OIDC-aware auth session for envector SDK clients.

A single :class:`_AuthSession` can be passed to both :class:`Indexer` and
:class:`KMSClient` so the two clients refresh in lock-step and observe the
same access-token string. The session object is the only coordination point —
wire-level RPCs remain on independent gRPC channels to envector and KMS.
"""

import json
import threading
from typing import Any, Callable, List, Optional, Tuple, Union
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import grpc

from pyenvector.errors import EnvectorTransportError, EnvectorValidationError
from pyenvector.proto_gen.v2.common import type_pb2 as envector_type_pb

AccessTokenProvider = Callable[[], Optional[str]]
AccessTokenInput = Optional[Union[str, AccessTokenProvider]]


def resolve_access_token(access_token: AccessTokenInput) -> Optional[str]:
    """Normalize an access-token input (string or callable provider) to a string or None."""
    if access_token is None:
        return None
    if callable(access_token):
        try:
            access_token = access_token()
        except Exception as e:
            raise EnvectorValidationError(message=f"access_token provider failed: {e}") from e
    if access_token is None:
        return None
    if not isinstance(access_token, str):
        raise EnvectorValidationError(
            message="access_token must be a str, None, or a callable returning str or None",
        )
    token = access_token.strip()
    return token or None


def build_auth_metadata(access_token: AccessTokenInput) -> Optional[List[Tuple[str, str]]]:
    """Build gRPC metadata with an Authorization Bearer header, or None when unauthenticated."""
    token = resolve_access_token(access_token)
    if not token:
        return None
    return [("authorization", f"Bearer {token}")]


def is_auth_rpc_error(error: grpc.RpcError) -> bool:
    """True if the gRPC error indicates an auth failure (UNAUTHENTICATED/PERMISSION_DENIED)."""
    try:
        return error.code() in (grpc.StatusCode.UNAUTHENTICATED, grpc.StatusCode.PERMISSION_DENIED)
    except Exception:
        return False


def is_auth_return_code(return_code: Optional[int]) -> bool:
    """True if an ES2 ResponseHeader.return_code indicates an auth failure."""
    auth_code = getattr(envector_type_pb.ReturnCode, "AuthenticationError", None)
    return auth_code is not None and return_code == auth_code


class _AuthSession:
    def __init__(
        self,
        access_token: AccessTokenInput = None,
        refresh_token: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ):
        if callable(access_token) and refresh_token:
            raise EnvectorValidationError(
                message=(
                    "access_token callable cannot be combined with refresh_token; "
                    "either let the callable manage refresh, or omit it and use the "
                    "SDK's OIDC refresh flow"
                ),
            )
        if refresh_token and not (client_id and (token_endpoint or oidc_issuer)):
            raise EnvectorValidationError(
                message=(
                    "refresh_token requires client_id and either token_endpoint or "
                    "oidc_issuer to perform OIDC refresh"
                ),
            )
        self._access_token_input = access_token
        self._current_access_token = None if callable(access_token) else access_token
        self._refresh_token = refresh_token
        self._oidc_issuer = oidc_issuer.rstrip("/") if oidc_issuer else None
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._lock = threading.Lock()

    def uses_auth(self) -> bool:
        return bool(self._access_token_input or self._refresh_token)

    def can_refresh(self) -> bool:
        return bool(self._refresh_token and (self._token_endpoint or self._oidc_issuer) and self._client_id)

    def get_access_token(self) -> Optional[str]:
        token_input = self._access_token_input if callable(self._access_token_input) else self._current_access_token
        token = resolve_access_token(token_input)
        if token and not callable(self._access_token_input):
            self._current_access_token = token
        return token

    def refresh_access_token(self) -> Optional[str]:
        if not self.can_refresh():
            return None
        # Resolve the token endpoint outside the lock so a slow OIDC discovery
        # I/O on cold start does not block other threads waiting to refresh.
        # Discovery is idempotent and the resolved endpoint is cached on the
        # instance, so concurrent first-time resolves race benignly.
        token_endpoint = self._resolve_token_endpoint()
        # Snapshot before acquiring the lock. If another thread refreshes while we
        # wait, skip the network round-trip — critical for IdPs that enforce
        # single-use refresh tokens or reuse detection.
        pre_refresh_access_token = self._current_access_token
        with self._lock:
            if self._current_access_token != pre_refresh_access_token:
                return self._current_access_token
            form = {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self._client_id,
            }
            if self._client_secret:
                form["client_secret"] = self._client_secret
            if self._scope:
                form["scope"] = self._scope

            body = urllib_parse.urlencode(form).encode("utf-8")
            request = urllib_request.Request(
                token_endpoint,
                data=body,
                headers={"content-type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib_request.urlopen(request, timeout=10) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError, ValueError) as e:
                raise EnvectorTransportError(
                    message=f"Failed to refresh access token: {e}",
                    retryable=True,
                    action="Check OIDC token endpoint, refresh token, and client credentials",
                ) from e

            refreshed_access_token = payload.get("access_token") or payload.get("id_token")
            if not isinstance(refreshed_access_token, str) or not refreshed_access_token.strip():
                raise EnvectorTransportError(
                    message="Failed to refresh access token: token endpoint response missing access_token",
                    action="Check OIDC client scope and token response fields",
                )

            refreshed_refresh_token = payload.get("refresh_token")
            self._current_access_token = refreshed_access_token.strip()
            self._access_token_input = self._current_access_token
            if isinstance(refreshed_refresh_token, str) and refreshed_refresh_token.strip():
                self._refresh_token = refreshed_refresh_token.strip()
            return self._current_access_token

    def _resolve_token_endpoint(self) -> str:
        if self._token_endpoint:
            return self._token_endpoint
        if not self._oidc_issuer:
            raise EnvectorValidationError(
                message="token_endpoint or oidc_issuer must be provided when refresh_token is configured",
            )
        discovery_url = f"{self._oidc_issuer}/.well-known/openid-configuration"
        try:
            with urllib_request.urlopen(discovery_url, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError, ValueError) as e:
            raise EnvectorTransportError(
                message=f"Failed to discover OIDC token endpoint: {e}",
                retryable=True,
                action="Check OIDC issuer URL and discovery endpoint availability",
            ) from e

        token_endpoint = payload.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint.strip():
            raise EnvectorTransportError(
                message="Failed to discover OIDC token endpoint: discovery response missing token_endpoint",
                action="Check OIDC issuer discovery document",
            )
        self._token_endpoint = token_endpoint.strip()
        return self._token_endpoint
