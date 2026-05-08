from unittest.mock import patch

import pytest

from pyenvector.crypto.block import CipherBlock


@pytest.fixture
def query():
    with patch("evi.Query", autospec=True) as MockQuery:
        return MockQuery()


@pytest.fixture
def serialized_ciphertext():
    with patch("pyenvector.proto_gen.v2.common.type_pb2.CiphertextScore", autospec=True) as MockCiphertextScore:
        return MockCiphertextScore()


def test_cipherblock_with_query(query):
    with patch("evi.Query", autospec=True):
        block = CipherBlock(query)
        assert block.data == [query]
        assert block._is_score is False


def test_cipherblock_with_serialized_ciphertext(serialized_ciphertext):
    with (
        patch("pyenvector.proto_gen.v2.common.type_pb2.CiphertextScore", autospec=True),
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
        patch("pyenvector.proto_gen.v2.common.type_pb2.CiphertextScore", autospec=True),
    ):
        block = CipherBlock(query)
        block.data = serialized_ciphertext
        assert block._is_score is True
        block.data = query
        assert block._is_score is False


def test_cipherblock_centroids_idx_setter(query):
    with patch("evi.Query", autospec=True):
        query.getInnerItemCount.return_value = 1
        block = CipherBlock(query, centroids_idx=[7])
        assert block.centroids_idx == [7]


def test_cipherblock_centroids_idx_scalar_for_single_vector(query):
    with patch("evi.Query", autospec=True):
        query.getInnerItemCount.return_value = 1
        block = CipherBlock(query, centroids_idx=5)
        assert block.centroids_idx == [5]


def test_cipherblock_centroids_idx_length_mismatch_raises(query):
    with patch("evi.Query", autospec=True):
        query.getInnerItemCount.return_value = 1
        with pytest.raises(ValueError, match="centroids_idx length"):
            CipherBlock(query, centroids_idx=[1, 2])


def test_cipherblock_centroids_idx_rejected_for_score(serialized_ciphertext):
    with patch("pyenvector.proto_gen.v2.common.type_pb2.CiphertextScore", autospec=True):
        block = CipherBlock(serialized_ciphertext)
        with pytest.raises(ValueError, match="only supported for vector ciphertext blocks"):
            block.centroids_idx = [1]


def test_cipherblock_data_reassign_warns_if_centroids_set(query):
    with patch("evi.Query", autospec=True):
        query.getInnerItemCount.return_value = 1
        block = CipherBlock(query, centroids_idx=[3])
        with pytest.warns(UserWarning, match="centroids_idx has been reset"):
            block.data = query
        assert block.centroids_idx is None


def test_cipherblock_centroids_idx_type_error_before_length_error(query):
    with patch("evi.Query", autospec=True):
        query.getInnerItemCount.return_value = 1
        with pytest.raises(ValueError, match="must contain only integers"):
            CipherBlock(query, centroids_idx=["not_int"])


def test_cipherblock_num_vectors_for_serialized_row_ciphertexts():
    block = CipherBlock([b"ctxt-1", b"ctxt-2"])

    assert block.num_vectors == 2


def test_cipherblock_num_item_list_for_serialized_row_ciphertexts():
    block = CipherBlock([b"ctxt-1", b"ctxt-2", b"ctxt-3"])

    assert block.num_item_list == [1, 1, 1]


def test_cipherblock_centroids_idx_accepts_serialized_row_ciphertexts():
    block = CipherBlock([b"ctxt-1", b"ctxt-2"], centroids_idx=[4, 5])

    assert block.centroids_idx == [4, 5]


def test_cipherblock_centroids_idx_length_mismatch_for_serialized_row_ciphertexts():
    with pytest.raises(ValueError, match="centroids_idx length"):
        CipherBlock([b"ctxt-1", b"ctxt-2"], centroids_idx=[1])
