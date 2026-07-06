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
"""Dev-only OpenTelemetry instrumentation for the enVector Python SDK.

This subpackage is intentionally EXCLUDED from the distributed wheel
(``[tool.scikit-build] wheel.exclude``). It exists so developers can connect
SDK calls to the server-side traces (search <-> KMS) when debugging or
benchmarking against a live envector-msa + Jaeger stack. It is never shipped to
end users and pulls no opentelemetry dependency into the published package.

Activation is opt-in and gated exactly like the Go services:

* OFF by default.
* ``OTEL_TRACES_ENABLED`` in {true, 1, yes, on} turns it on.
* ``OTEL_SDK_DISABLED`` in {true, 1} is a hard override that forces it off.

Nothing here runs unless ``enable()`` is called AND the env gate is on, so a
normal SDK import has zero behavioral or performance impact. The heavy
opentelemetry imports live in sibling modules that are only imported from inside
``enable()``; importing this package never requires opentelemetry to be present.

Usage (dev / e2e harness only)::

    from pyenvector import telemetry
    telemetry.enable()          # no-op unless OTEL_TRACES_ENABLED is set
    ...
    with telemetry.span("explicit_kms_topk"):
        ctxt = index.scoring(query=q)[0]
        kms_client.top_k(...)
    telemetry.shutdown()        # flush exporter before exit
"""

import contextlib
import logging
import os

_TRUTHY = {"true", "1", "yes", "on"}
_DISABLED_VALUES = {"true", "1"}

_log = logging.getLogger("pyenvector.telemetry")

# The active runtime (a ._runtime.Runtime) once enable() has wired up a tracer
# provider + monkeypatches; None when tracing is off or never enabled.
#
# NOTE: must NOT be named `_runtime` — that collides with the sibling submodule
# ._runtime, so importing the submodule anywhere (e.g. tests, or enable's own
# `from ._runtime import Runtime`) rebinds this package attribute to the module
# object and clobbers the state. Use a distinct name.
_active_runtime = None


def _env_flag(name: str, allowed: set) -> bool:
    return os.environ.get(name, "").strip().lower() in allowed


def is_tracing_enabled() -> bool:
    """Return whether SDK tracing should be active, per the env gate.

    Mirrors ``utils.IsTracingEnabled()`` in the Go services: OFF by default,
    ``OTEL_TRACES_ENABLED`` enables, ``OTEL_SDK_DISABLED`` hard-overrides off.
    Evaluated live on every call so tests and callers can flip the env.
    """
    if _env_flag("OTEL_SDK_DISABLED", _DISABLED_VALUES):
        return False
    return _env_flag("OTEL_TRACES_ENABLED", _TRUTHY)


def enable() -> bool:
    """Activate SDK tracing if the env gate is on. Idempotent, no-op otherwise.

    Returns True when tracing is now active. Returns False (and does nothing —
    no monkeypatching, no opentelemetry import) when the env gate is off or when
    opentelemetry is not installed. Safe to call once at process start in a dev
    or e2e harness; a normal SDK run never calls it.
    """
    global _active_runtime
    if _active_runtime is not None:
        return True
    if not is_tracing_enabled():
        return False
    try:
        from ._runtime import Runtime
    except Exception as exc:  # opentelemetry missing, etc.
        _log.warning(
            "OTEL_TRACES_ENABLED is set but SDK tracing could not start "
            "(opentelemetry not installed?): %s",
            exc,
        )
        return False
    try:
        _active_runtime = Runtime()
        _active_runtime.start()
    except Exception as exc:
        _log.warning("SDK tracing failed to initialize; continuing without it: %s", exc)
        _active_runtime = None
        return False
    return True


def disable() -> None:
    """Undo enable(): restore monkeypatched callables and drop the runtime."""
    global _active_runtime
    if _active_runtime is None:
        return
    try:
        _active_runtime.stop()
    finally:
        _active_runtime = None


def shutdown() -> None:
    """Flush and shut down the tracer provider so spans are exported on exit."""
    if _active_runtime is None:
        return
    _active_runtime.shutdown()


def span(name: str, **attributes):
    """Open a manual span grouping the enclosed work.

    A no-op context manager (yields None) when tracing is disabled, so callers
    can wrap multi-RPC operations unconditionally. When tracing is active it
    starts a current span named ``name`` with the given attributes.
    """
    if _active_runtime is None:
        return _noop_span()
    return _active_runtime.span(name, attributes)


@contextlib.contextmanager
def _noop_span():
    yield None
