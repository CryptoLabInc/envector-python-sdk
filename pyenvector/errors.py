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

"""enVector SDK exception hierarchy.

All SDK-raised exceptions inherit from EnvectorError.
Application errors (server returned ResponseHeader with return_code != Success)
are EnvectorApplicationError subclasses.
Transport errors (gRPC channel failure) are EnvectorTransportError.
"""


class EnvectorError(Exception):
    """Base exception for all enVector SDK errors."""

    def __init__(self, message, *, return_code=None, retryable=False, action=None, request_id=None):
        self.message = message
        self.return_code = return_code
        self.retryable = retryable
        self.action = action
        self.request_id = request_id
        super().__init__(str(self))

    def __str__(self):
        parts = [self.message]
        if self.action:
            parts.append(f"Action: {self.action}")
        if self.request_id:
            parts.append(f"Request ID: {self.request_id}")
        return " | ".join(parts)


class EnvectorApplicationError(EnvectorError):
    """Server returned an application-level error in ResponseHeader."""

    pass


class InvalidInputError(EnvectorApplicationError):
    """Invalid input parameters (ReturnCode.InvalidInput)."""

    pass


class AuthError(EnvectorApplicationError):
    """Authentication/authorization failure (ReturnCode.AuthenticationError)."""

    pass


class KeyManagementError(EnvectorApplicationError):
    """Key management error (InvalidKeyURL, InvalidKeyAuthInfo, FailedToUnpackKey)."""

    pass


class NotReadyError(EnvectorApplicationError):
    """Resource not ready (ReturnCode.NotReady, NoSuchIndex)."""

    pass


class ResourceLimitError(EnvectorApplicationError):
    """Resource limit exceeded (ReturnCode.ResourceLimitError, InsufficientDiskSpace)."""

    pass


class DependencyError(EnvectorApplicationError):
    """Downstream dependency failure (ReturnCode.DependencyError)."""

    pass


class EnvectorTimeoutError(EnvectorApplicationError, TimeoutError):
    """Operation timed out (ReturnCode.Timeout).

    Inherits from both EnvectorApplicationError and builtin TimeoutError
    so that existing ``except TimeoutError:`` handlers continue to catch it.
    """

    pass


class InternalError(EnvectorApplicationError):
    """Internal server error (ReturnCode.Fail, UnknownError)."""

    pass


class EnvectorTransportError(EnvectorError):
    """gRPC transport/channel failure. No server response available."""

    pass


class EnvectorValidationError(EnvectorError):
    """Client-side input validation failure."""

    pass
