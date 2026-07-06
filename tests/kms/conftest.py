# Override the session-scoped setup_and_cleanup_keys fixture from tests/conftest.py.
# KMS tests do not require evi key generation; they use gRPC stubs.
import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_and_cleanup_keys():
    """No-op override -- KMS tests do not need local evi key generation."""
    yield
