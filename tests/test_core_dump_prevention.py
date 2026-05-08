import sys

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="resource module is Unix-only")
def test_core_dump_disabled_after_import():
    import resource

    soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
    assert soft == 0, f"Expected RLIMIT_CORE soft=0, got {soft}"
