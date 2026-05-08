"""Tests for Index._validate_insert_data method.

This module tests the modularized validation logic for insert data,
including empty data detection and dimension validation.
"""

from types import SimpleNamespace

import numpy as np
import pytest

import pyenvector.index.index as index_module
from pyenvector.index import Index


def _make_index(dim: int = 2, index_encryption: str = "cipher"):
    """Create a minimal Index instance for validation testing."""
    index = Index.__new__(Index)
    index._is_loaded = True
    index.index_config = SimpleNamespace(dim=dim, index_encryption=index_encryption)
    return index


class TestValidateInsertDataEmpty:
    """Test cases for empty data validation."""

    def test_empty_list_raises_value_error(self):
        """Empty list should raise ValueError, not IndexError."""
        index = _make_index()
        with pytest.raises(ValueError, match="Data cannot be empty"):
            index._validate_insert_data(data=[])

    def test_empty_2d_ndarray_raises_value_error(self):
        """Empty 2D numpy array should raise ValueError."""
        index = _make_index()
        data = np.array([]).reshape(0, 2)
        with pytest.raises(ValueError, match="Data cannot be empty"):
            index._validate_insert_data(data=data)

    def test_empty_1d_ndarray_raises_value_error(self):
        """Empty 1D numpy array should raise ValueError."""
        index = _make_index()
        data = np.array([])
        with pytest.raises(ValueError, match="Data cannot be empty"):
            index._validate_insert_data(data=data)


class TestValidateInsertDataDimension:
    """Test cases for dimension validation."""

    def test_list_of_lists_correct_dimension(self):
        """List of lists with correct dimension should pass."""
        index = _make_index(dim=3)
        data = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]
        index._validate_insert_data(data=data)  # Should not raise

    def test_list_of_lists_wrong_dimension(self):
        """List of lists with wrong dimension should raise ValueError."""
        index = _make_index(dim=3)
        data = [[1.0, 2.0]]  # Wrong dimension
        with pytest.raises(ValueError, match="Data dimension 2 does not match index dimension 3"):
            index._validate_insert_data(data=data)

    def test_2d_ndarray_correct_dimension(self):
        """2D numpy array with correct dimension should pass."""
        index = _make_index(dim=4)
        data = np.array([[1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]])
        index._validate_insert_data(data=data)  # Should not raise

    def test_2d_ndarray_wrong_dimension(self):
        """2D numpy array with wrong dimension should raise ValueError."""
        index = _make_index(dim=4)
        data = np.array([[1.0, 2.0, 3.0]])  # Wrong dimension (3 instead of 4)
        with pytest.raises(ValueError, match="Data dimension 3 does not match index dimension 4"):
            index._validate_insert_data(data=data)

    def test_list_of_ndarrays_correct_dimension(self):
        """List of numpy arrays with correct dimension should pass."""
        index = _make_index(dim=2)
        data = [np.array([1.0, 2.0]), np.array([3.0, 4.0])]
        index._validate_insert_data(data=data)  # Should not raise

    def test_list_of_ndarrays_wrong_dimension(self):
        """List of numpy arrays with wrong dimension should raise ValueError."""
        index = _make_index(dim=3)
        data = [np.array([1.0, 2.0])]  # Wrong dimension (2 instead of 3)
        with pytest.raises(ValueError, match="Data dimension 2 does not match index dimension 3"):
            index._validate_insert_data(data=data)


class TestValidateInsertDataFormat:
    """Test cases for data format validation."""

    def test_invalid_format_raises_value_error(self):
        """Invalid data format should raise ValueError."""
        index = _make_index()
        data = ["invalid", "strings"]  # Invalid format
        with pytest.raises(ValueError, match="Data must be a CipherBlock, list of floats"):
            index._validate_insert_data(data=data)


class TestValidateInsertDataCipher:
    """Test cases for CipherBlock input normalization and validation."""

    def test_single_cipherblock_wrapped_to_list(self, monkeypatch):
        """Single CipherBlock should be normalized to list[CipherBlock]."""

        class FakeCipherBlock:
            pass

        monkeypatch.setattr(index_module, "CipherBlock", FakeCipherBlock)
        index = _make_index(index_encryption="cipher")
        block = FakeCipherBlock()

        result = index._validate_insert_data(data=block)

        assert result == [block]

    def test_mixed_cipher_and_plaintext_raises_value_error(self, monkeypatch):
        """Mixed ciphertext/plaintext in one insert call should be rejected."""

        class FakeCipherBlock:
            pass

        monkeypatch.setattr(index_module, "CipherBlock", FakeCipherBlock)
        index = _make_index(dim=2, index_encryption="cipher")
        block = FakeCipherBlock()

        with pytest.raises(ValueError, match="cannot mix CipherBlock and plaintext vectors"):
            index._validate_insert_data(data=[block, [1.0, 2.0]])

    def test_cipherblock_requires_encrypted_index_mode(self, monkeypatch):
        """CipherBlock input should fail when index encryption is disabled."""

        class FakeCipherBlock:
            pass

        monkeypatch.setattr(index_module, "CipherBlock", FakeCipherBlock)
        index = _make_index(index_encryption="plain")
        block = FakeCipherBlock()

        with pytest.raises(ValueError, match="Index encryption must be enabled"):
            index._validate_insert_data(data=block)


class TestValidateInsertDataSingleVector:
    """Test cases for single vector auto-wrapping."""

    def test_single_vector_list_of_floats_wrapped(self):
        """Single vector as list of floats should be wrapped to [[...]]."""
        index = _make_index(dim=3)
        data = [1.0, 2.0, 3.0]
        result = index._validate_insert_data(data=data)
        assert isinstance(result, np.ndarray)
        assert result.shape == (1, 3)
        np.testing.assert_array_equal(result[0], [1.0, 2.0, 3.0])

    def test_single_vector_1d_ndarray_wrapped(self):
        """Single vector as 1D numpy array should be wrapped to 2D."""
        index = _make_index(dim=3)
        data = np.array([1.0, 2.0, 3.0])
        result = index._validate_insert_data(data=data)
        assert result.shape == (1, 3)
        np.testing.assert_array_equal(result[0], [1.0, 2.0, 3.0])

    def test_single_vector_wrong_dimension_raises_error(self):
        """Single vector with wrong dimension should raise ValueError."""
        index = _make_index(dim=3)
        data = [1.0, 2.0]  # Wrong dimension (2 instead of 3)
        with pytest.raises(ValueError, match="Data dimension 2 does not match index dimension 3"):
            index._validate_insert_data(data=data)

    def test_single_vector_1d_ndarray_wrong_dimension_raises_error(self):
        """Single 1D numpy array with wrong dimension should raise ValueError."""
        index = _make_index(dim=3)
        data = np.array([1.0, 2.0])  # Wrong dimension (2 instead of 3)
        with pytest.raises(ValueError, match="Data dimension 2 does not match index dimension 3"):
            index._validate_insert_data(data=data)

    def test_single_vector_with_int_values(self):
        """Single vector with int values should also be wrapped."""
        index = _make_index(dim=3)
        data = [1, 2, 3]  # integers
        result = index._validate_insert_data(data=data)
        assert isinstance(result, np.ndarray)
        assert result.shape == (1, 3)
        np.testing.assert_array_equal(result[0], [1, 2, 3])


class TestValidateInsertDataNormalization:
    """Test cases for plaintext normalization contract."""

    def test_multi_vector_list_of_lists_returns_ndarray(self):
        """list[list[float]] should normalize to 2D ndarray."""
        index = _make_index(dim=3)
        data = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]

        result = index._validate_insert_data(data=data)

        assert isinstance(result, np.ndarray)
        assert result.shape == (2, 3)
        np.testing.assert_array_equal(result, np.array(data))

    def test_multi_vector_list_of_ndarrays_returns_ndarray(self):
        """list[np.ndarray] should normalize to 2D ndarray."""
        index = _make_index(dim=3)
        data = [np.array([1.0, 2.0, 3.0]), np.array([4.0, 5.0, 6.0])]

        result = index._validate_insert_data(data=data)

        assert isinstance(result, np.ndarray)
        assert result.shape == (2, 3)
        np.testing.assert_array_equal(result, np.array(data))


class TestValidateInsertDataCipherCentroidsIdx:
    """Test cases for CipherBlock centroids_idx validation."""

    def test_cipherblock_centroids_idx_mixed_presence_raises_value_error(self, monkeypatch):
        """Mixing present/missing centroids_idx across CipherBlocks should fail."""

        class FakeCipherBlock:
            def __init__(self, num_vectors, centroids_idx):
                self.num_vectors = num_vectors
                self.centroids_idx = centroids_idx

        monkeypatch.setattr(index_module, "CipherBlock", FakeCipherBlock)
        index = _make_index(index_encryption="cipher")

        data = [
            FakeCipherBlock(num_vectors=2, centroids_idx=[0, 1]),
            FakeCipherBlock(num_vectors=1, centroids_idx=None),
        ]

        with pytest.raises(ValueError, match="centroids_idx must be present on all CipherBlocks or none"):
            index._validate_insert_data(data=data)

    def test_cipherblock_centroids_idx_length_mismatch_raises_value_error(self, monkeypatch):
        """num_vectors and len(centroids_idx) mismatch should fail."""

        class FakeCipherBlock:
            def __init__(self, num_vectors, centroids_idx):
                self.num_vectors = num_vectors
                self.centroids_idx = centroids_idx

        monkeypatch.setattr(index_module, "CipherBlock", FakeCipherBlock)
        index = _make_index(index_encryption="cipher")

        data = [FakeCipherBlock(num_vectors=2, centroids_idx=[0])]

        with pytest.raises(ValueError, match="The length of centroids_idx must equal num_vectors"):
            index._validate_insert_data(data=data)


class TestInsertEmptyDataIntegration:
    """Integration test for insert method with empty data.

    This is a regression test for the bug where Index.insert
    raised IndexError instead of ValueError for empty input.
    """

    def test_insert_empty_data_raises_value_error(self):
        """Calling insert with empty list should raise ValueError."""
        index = _make_index()
        with pytest.raises(ValueError):
            index.insert(data=[], metadata=[])
