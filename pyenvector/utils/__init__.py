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

from importlib import import_module

from pyenvector.utils.logging_config import logger
from pyenvector.utils.utils import topk
from pyenvector.utils.vault import VaultClient

__all__ = ["AWSClient", "GCPClient", "VaultClient", "logger", "topk"]


def _load_optional_client(module_name: str, attr_name: str, extra_name: str):
    try:
        module = import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"{attr_name} requires optional dependency group '{extra_name}'. "
            f"Install it with `pip install pyenvector[{extra_name}]`."
        ) from exc
    return getattr(module, attr_name)


def __getattr__(name: str):
    if name == "AWSClient":
        return _load_optional_client("pyenvector.utils.aws", name, "aws")
    if name == "GCPClient":
        return _load_optional_client("pyenvector.utils.gcp", name, "gcp")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
