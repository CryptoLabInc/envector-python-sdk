# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
# ========================================================================================
"""Env-gate logic for the dev-only OpenTelemetry instrumentation.

These tests are pure (no opentelemetry import) and mirror the Go services'
gating convention: tracing is OFF by default, OTEL_TRACES_ENABLED turns it on,
and OTEL_SDK_DISABLED is a hard override.
"""

import pytest

from pyenvector.telemetry import is_tracing_enabled


@pytest.fixture(autouse=True)
def _clear_otel_env(monkeypatch):
    monkeypatch.delenv("OTEL_TRACES_ENABLED", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)


def test_default_is_disabled():
    assert is_tracing_enabled() is False


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE", "On", "YeS"])
def test_truthy_values_enable(monkeypatch, value):
    monkeypatch.setenv("OTEL_TRACES_ENABLED", value)
    assert is_tracing_enabled() is True


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "", "  ", "maybe"])
def test_falsy_values_stay_disabled(monkeypatch, value):
    monkeypatch.setenv("OTEL_TRACES_ENABLED", value)
    assert is_tracing_enabled() is False


@pytest.mark.parametrize("disabled", ["true", "1", "TRUE"])
def test_sdk_disabled_overrides_enabled(monkeypatch, disabled):
    monkeypatch.setenv("OTEL_TRACES_ENABLED", "true")
    monkeypatch.setenv("OTEL_SDK_DISABLED", disabled)
    assert is_tracing_enabled() is False


@pytest.mark.parametrize("disabled", ["false", "0", ""])
def test_sdk_disabled_falsy_does_not_override(monkeypatch, disabled):
    monkeypatch.setenv("OTEL_TRACES_ENABLED", "true")
    monkeypatch.setenv("OTEL_SDK_DISABLED", disabled)
    assert is_tracing_enabled() is True
