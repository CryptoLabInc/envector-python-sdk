# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
# ========================================================================================
"""Telemetry tests share a process-global runtime (telemetry._active_runtime). Reset it
before AND after every test so order does not matter — pytest-randomly shuffles
the suite, and a test that calls enable() must not leak the active runtime into
the next test's view of enable()/is_tracing_enabled().
"""

import pytest

from pyenvector import telemetry


@pytest.fixture(autouse=True)
def _reset_telemetry_state():
    telemetry.disable()
    yield
    telemetry.disable()
