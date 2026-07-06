# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
# ========================================================================================
"""When enabled, the dev telemetry must (a) inject a W3C ``traceparent`` header
on every outgoing gRPC call made through a ``Connection`` channel, and (b) emit
a CLIENT span that shares a trace id with the surrounding ``telemetry.span()``
parent -- i.e. the SDK call and its server-side work land in one connected trace.

Requires opentelemetry (dev-only dependency); skipped where it is not installed.
"""

from concurrent import futures

import grpc
import pytest

pytest.importorskip("opentelemetry")
pytest.importorskip("opentelemetry.instrumentation.grpc")

from grpc_health.v1 import health, health_pb2, health_pb2_grpc  # noqa: E402

from pyenvector import telemetry  # noqa: E402


class _CaptureMetadataInterceptor(grpc.ServerInterceptor):
    """Records the invocation metadata of every incoming RPC."""

    def __init__(self):
        self.seen = []

    def intercept_service(self, continuation, handler_call_details):
        self.seen.append(dict(handler_call_details.invocation_metadata or ()))
        return continuation(handler_call_details)


@pytest.fixture
def _tracing_on(monkeypatch):
    monkeypatch.setenv("OTEL_TRACES_ENABLED", "1")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")  # no live collector in unit tests
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry.enable() is True
    yield
    telemetry.disable()


@pytest.fixture
def _health_server():
    capture = _CaptureMetadataInterceptor()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2), interceptors=(capture,))
    health_pb2_grpc.add_HealthServicer_to_server(health.HealthServicer(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        yield f"127.0.0.1:{port}", capture
    finally:
        server.stop(0).wait()


def test_traceparent_injected_on_grpc_call(_tracing_on, _health_server):
    from pyenvector.api.connection import Connection

    addr, capture = _health_server
    conn = Connection(addr, secure=False)
    try:
        stub = health_pb2_grpc.HealthStub(conn.get_channel())
        with telemetry.span("test_parent"):
            stub.Check(health_pb2.HealthCheckRequest())
    finally:
        conn.close()

    assert any("traceparent" in md for md in capture.seen), capture.seen


def test_client_span_shares_trace_with_parent(_tracing_on, _health_server):
    from opentelemetry import trace
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from pyenvector.api.connection import Connection

    exporter = InMemorySpanExporter()
    trace.get_tracer_provider().add_span_processor(SimpleSpanProcessor(exporter))

    addr, _ = _health_server
    conn = Connection(addr, secure=False)
    try:
        stub = health_pb2_grpc.HealthStub(conn.get_channel())
        with telemetry.span("test_parent"):
            stub.Check(health_pb2.HealthCheckRequest())
    finally:
        conn.close()

    spans = exporter.get_finished_spans()
    kinds = {s.kind for s in spans}
    assert trace.SpanKind.CLIENT in kinds, f"no client span: {[(s.name, s.kind) for s in spans]}"
    # parent span + client RPC span belong to exactly one trace
    trace_ids = {s.context.trace_id for s in spans}
    assert len(trace_ids) == 1, f"spans split across traces: {trace_ids}"


def test_disable_restores_unwrapped_connection(monkeypatch):
    from pyenvector.api import connection as conn_mod

    pristine = conn_mod.Connection.__init__
    monkeypatch.setenv("OTEL_TRACES_ENABLED", "1")
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    assert telemetry.enable() is True
    assert conn_mod.Connection.__init__ is not pristine  # patched while active
    telemetry.disable()
    assert conn_mod.Connection.__init__ is pristine  # restored
