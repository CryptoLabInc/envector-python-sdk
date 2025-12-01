from unittest.mock import patch

import pytest

from pyenvector.crypto.block import CipherBlock


@pytest.fixture
def query():
    with patch("evi.Query", autospec=True) as MockQuery:
        return MockQuery()


@pytest.fixture
def serialized_ciphertext():
    with patch("pyenvector.proto_gen.type_pb2.CiphertextScore", autospec=True) as MockCiphertextScore:
        return MockCiphertextScore()


def test_cipherblock_with_query(query):
    with patch("evi.Query", autospec=True):
        block = CipherBlock(query)
        assert block.data == [query]
        assert block._is_score is False


def test_cipherblock_with_serialized_ciphertext(serialized_ciphertext):
    with (
        patch("pyenvector.proto_gen.type_pb2.CiphertextScore", autospec=True),
    ):
        block = CipherBlock(serialized_ciphertext)
        assert block.data == serialized_ciphertext
        assert block._is_score is True


def test_cipherblock_invalid_data_type():
    with pytest.raises(ValueError):
        CipherBlock("not a list")


def test_cipherblock_empty_list():
    with pytest.raises(ValueError):
        CipherBlock([])


def test_cipherblock_data_setter_type_check(query, serialized_ciphertext):
    with (
        patch("evi.Query", autospec=True),
        patch("pyenvector.proto_gen.type_pb2.CiphertextScore", autospec=True),
    ):
        block = CipherBlock(query)
        block.data = serialized_ciphertext
        assert block._is_score is True
        block.data = query
        assert block._is_score is False
