from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _stub_metadata_key_resolution(monkeypatch):
    # Index tests mock encrypt_metadata/decrypt_metadata to stay off the filesystem.
    # The metadata key is now resolved once via resolve_metadata_key before those
    # calls, so stub it here too with a valid 32-byte key.
    monkeypatch.setattr(
        "pyenvector.index.index.resolve_metadata_key",
        MagicMock(return_value=b"\x00" * 32),
    )
