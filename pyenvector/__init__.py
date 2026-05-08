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

# Prevent core dumps that could leak secret key material.
def _disable_core_dumps():
    try:
        import resource
    except ImportError:
        return
    try:
        _soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, _hard))
    except (ValueError, OSError, AttributeError):
        pass


_disable_core_dumps()
del _disable_core_dumps

from pyenvector import api, crypto, utils
from pyenvector.client import *
from pyenvector.crypto import Cipher, KeyGenerator
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
from pyenvector.index import Index

try:
    from pyenvector.kms import KMSClient
except ImportError:
    KMSClient = None
from pyenvector.utils import AWSClient, GCPClient, VaultClient

__version__ = "1.4.2"
