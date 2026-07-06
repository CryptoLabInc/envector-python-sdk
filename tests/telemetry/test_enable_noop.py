# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
# ========================================================================================
"""When the env gate is OFF, enable() must be a true no-op: no monkeypatching,
no opentelemetry import, span() is an inert context manager. This guarantees a
normal SDK run is byte-for-byte unaffected by the presence of the dev module.
"""

import pytest

from pyenvector import telemetry
from pyenvector.api import connection as conn_mod


@pytest.fixture(autouse=True)
def _disabled_env(monkeypatch):
    monkeypatch.delenv("OTEL_TRACES_ENABLED", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    yield
    telemetry.disable()


def test_enable_returns_false_when_disabled():
    assert telemetry.enable() is False


def test_enable_does_not_patch_connection_when_disabled():
    original_init = conn_mod.Connection.__init__
    telemetry.enable()
    assert conn_mod.Connection.__init__ is original_init


def test_span_is_inert_when_disabled():
    with telemetry.span("anything", k=1) as handle:
        assert handle is None


def test_enable_is_idempotent_when_disabled():
    assert telemetry.enable() is False
    assert telemetry.enable() is False


def test_shutdown_safe_when_never_enabled():
    # Must not raise even if nothing was ever set up.
    telemetry.shutdown()
