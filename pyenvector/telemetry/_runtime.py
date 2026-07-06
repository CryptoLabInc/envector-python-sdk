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
"""OpenTelemetry runtime for the dev-only SDK instrumentation.

Imported only from ``pyenvector.telemetry.enable()`` and only when the env gate
is on, so the top-level opentelemetry imports here never load during a normal
SDK run. Excluded from the distributed wheel together with the rest of the
``pyenvector.telemetry`` subpackage.

Responsibilities:
  * stand up a process-global ``TracerProvider`` (W3C TraceContext + Baggage
    propagation, exporter selected by standard OTEL_* env vars);
  * monkeypatch ``Connection`` so every gRPC channel the SDK creates carries a
    client-span + ``traceparent``-injecting interceptor (per-RPC tracing);
  * wrap the public SDK entry points (search / scoring / insert / KMS topk) in a
    parent span so a multi-RPC operation reads as one subtree.

All patches are recorded and reversed by ``stop()``.
"""

import functools
import logging
import os

_log = logging.getLogger("pyenvector.telemetry")

_TRUTHY = {"1", "true", "yes", "on"}

# (module dotted path, class name, method name, span name) for the public
# operations wrapped in a parent span. Best-effort: a target whose module fails
# to import is skipped, so partial SDK builds still get per-RPC tracing.
_PUBLIC_METHOD_TARGETS = [
    ("pyenvector.index.index", "Index", "insert", "pyenvector.insert"),
    ("pyenvector.index.index", "Index", "search", "pyenvector.search"),
    ("pyenvector.index.index", "Index", "scoring", "pyenvector.scoring"),
    ("pyenvector.kms.client", "KMSClient", "topk", "pyenvector.kms.topk"),
]


def _build_span_processors():
    """Build span processors from standard OTEL env vars (BatchSpanProcessor).

    OTEL_TRACES_EXPORTER selects otlp (default) / console / none. The OTLP
    transport honours OTEL_EXPORTER_OTLP_PROTOCOL (grpc default, http/protobuf).
    ENVECTOR_OTEL_STDOUT additionally tees spans to stdout (mirrors the Go
    services). OTLP exporter modules are imported lazily so 'none'/'console'
    never pull the otlp/protobuf stack.
    """
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    kind = os.environ.get("OTEL_TRACES_EXPORTER", "otlp").strip().lower()
    processors = []

    if kind == "none":
        pass
    elif kind == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        processors.append(BatchSpanProcessor(ConsoleSpanExporter()))
    else:  # otlp (default)
        proto = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc").strip().lower()
        if proto in ("http/protobuf", "http"):
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        else:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        processors.append(BatchSpanProcessor(OTLPSpanExporter()))

    if kind != "console" and os.environ.get("ENVECTOR_OTEL_STDOUT", "").strip().lower() in _TRUTHY:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        processors.append(BatchSpanProcessor(ConsoleSpanExporter()))

    return processors


class Runtime:
    """Owns the tracer provider and the set of active monkeypatches."""

    def __init__(self):
        self._provider = None
        self._tracer = None
        # True only when start() created and installed the provider. When we
        # instead adopt a host-app-owned global provider, we must not shut it
        # down on shutdown() (that would disable tracing for the whole process).
        self._owns_provider = False
        # Recorded (owner, attr, original) tuples to undo on stop().
        self._patches = []

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        provider = trace.get_tracer_provider()
        if not isinstance(provider, TracerProvider):
            # No real SDK provider yet (default is the proxy/no-op): create and
            # install one. If a host app already set a TracerProvider, reuse it
            # rather than fighting otel's set-once global.
            from opentelemetry.sdk.resources import SERVICE_NAME, Resource

            service_name = os.environ.get("OTEL_SERVICE_NAME", "").strip() or "envector-sdk"
            provider = TracerProvider(resource=Resource.create({SERVICE_NAME: service_name}))
            for proc in _build_span_processors():
                provider.add_span_processor(proc)
            trace.set_tracer_provider(provider)
            self._owns_provider = True

        self._provider = provider
        self._tracer = trace.get_tracer("pyenvector")
        self._install_w3c_propagator()
        self._patch_connection()
        self._patch_public_methods()

    def stop(self):
        # Reverse in LIFO order so re-wrapped attributes restore cleanly.
        for owner, attr, original in reversed(self._patches):
            try:
                setattr(owner, attr, original)
            except Exception as exc:  # pragma: no cover - defensive
                _log.warning("failed to restore %s.%s: %s", owner, attr, exc)
        self._patches = []

    def shutdown(self):
        if self._provider is None:
            return
        try:
            if self._owns_provider:
                self._provider.shutdown()
            else:
                # Adopted a host-app provider: flush our spans but leave the
                # provider running so the rest of the process keeps tracing.
                self._provider.force_flush()
        except Exception as exc:  # pragma: no cover - defensive
            _log.warning("tracer provider flush/shutdown failed: %s", exc)

    # -- spans -------------------------------------------------------------

    def span(self, name, attributes):
        return self._tracer.start_as_current_span(name, attributes=attributes or None)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _install_w3c_propagator():
        from opentelemetry.baggage.propagation import W3CBaggagePropagator
        from opentelemetry.propagate import set_global_textmap
        from opentelemetry.propagators.composite import CompositePropagator
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        set_global_textmap(
            CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])
        )

    def _wrap_channel(self, channel):
        # opentelemetry-instrumentation-grpc uses its own grpcext interceptor
        # abstraction (not the native grpc.*ClientInterceptor ABCs), so the
        # interceptor must be attached with grpcext.intercept_channel rather
        # than grpc.intercept_channel.
        from opentelemetry.instrumentation.grpc import client_interceptor, grpcext

        return grpcext.intercept_channel(channel, client_interceptor(tracer_provider=self._provider))

    def _patch_connection(self):
        import pyenvector.api.connection as conn_mod

        original_init = conn_mod.Connection.__init__
        wrap_channel = self._wrap_channel

        @functools.wraps(original_init)
        def patched_init(conn_self, *args, **kwargs):
            original_init(conn_self, *args, **kwargs)
            try:
                conn_self.channel = wrap_channel(conn_self.channel)
            except Exception as exc:  # pragma: no cover - defensive
                _log.warning("failed to wrap gRPC channel for tracing: %s", exc)

        conn_mod.Connection.__init__ = patched_init
        self._patches.append((conn_mod.Connection, "__init__", original_init))

    def _patch_public_methods(self):
        import importlib

        for module_path, class_name, method_name, span_name in _PUBLIC_METHOD_TARGETS:
            try:
                module = importlib.import_module(module_path)
                cls = getattr(module, class_name)
                original = getattr(cls, method_name)
            except Exception as exc:
                _log.debug("skip tracing %s.%s.%s: %s", module_path, class_name, method_name, exc)
                continue

            runtime = self

            @functools.wraps(original)
            def traced(self_, *args, _orig=original, _span_name=span_name, **kwargs):
                with runtime.span(_span_name, None):
                    return _orig(self_, *args, **kwargs)

            setattr(cls, method_name, traced)
            self._patches.append((cls, method_name, original))
