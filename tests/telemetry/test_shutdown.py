# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
# ========================================================================================
"""shutdown() must not tear down a TracerProvider it did not create.

When a host application already configured a global OpenTelemetry provider,
enable() reuses it; shutting that provider down would disable tracing for the
rest of the process. We must force-flush instead. _runtime imports opentelemetry
lazily, so these branch tests run without opentelemetry installed.
"""

from pyenvector.telemetry._runtime import Runtime


class _FakeProvider:
    def __init__(self):
        self.shut = False
        self.flushed = False

    def shutdown(self):
        self.shut = True

    def force_flush(self, *args, **kwargs):
        self.flushed = True


def test_shutdown_force_flushes_reused_provider_without_tearing_it_down():
    rt = Runtime()
    fake = _FakeProvider()
    rt._provider = fake
    rt._owns_provider = False  # adopted a host-app-owned provider

    rt.shutdown()

    assert fake.flushed is True
    assert fake.shut is False  # must NOT shut down a provider we didn't create


def test_shutdown_tears_down_provider_it_created():
    rt = Runtime()
    fake = _FakeProvider()
    rt._provider = fake
    rt._owns_provider = True  # this runtime installed the provider

    rt.shutdown()

    assert fake.shut is True


def test_owns_provider_defaults_false():
    # A fresh Runtime owns nothing until start() installs a provider.
    assert Runtime()._owns_provider is False
