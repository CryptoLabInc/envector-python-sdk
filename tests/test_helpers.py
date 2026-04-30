"""
Regression tests for pyenvector helper functions.

These tests verify the fixes for bugs found during static analysis
for the 400K IVFGAS experiment.
"""

import numpy as np
import pytest

from pyenvector.helpers import (
    CHUNK_SIZE_1MB,
    AddressRegistry,
    deduplicate_item_ids,
    generate_deterministic_centroids,
    safe_get_metadata,
    validate_centroids,
    validate_nprobe,
)


class TestGenerateDeterministicCentroids:
    """Tests for deterministic centroid generation."""

    def test_determinism(self):
        """Verify same seed produces identical results."""
        result1 = generate_deterministic_centroids(256, 512, seed=42)
        result2 = generate_deterministic_centroids(256, 512, seed=42)
        assert np.allclose(result1, result2), "Same seed should produce identical centroids"

    def test_different_seeds_produce_different_results(self):
        """Verify different seeds produce different results."""
        result1 = generate_deterministic_centroids(256, 512, seed=42)
        result2 = generate_deterministic_centroids(256, 512, seed=123)
        assert not np.allclose(result1, result2), "Different seeds should produce different centroids"

    def test_no_nan_or_inf(self):
        """Verify epsilon prevents NaN/Inf on normalization."""
        # Test with various sizes
        for nlist in [1, 10, 256]:
            for dim in [1, 128, 512]:
                centroids = generate_deterministic_centroids(nlist, dim)
                assert not np.isnan(centroids).any(), f"NaN found for {nlist}x{dim}"
                assert not np.isinf(centroids).any(), f"Inf found for {nlist}x{dim}"

    def test_output_shape(self):
        """Verify output has correct shape."""
        centroids = generate_deterministic_centroids(256, 512)
        assert centroids.shape == (256, 512)

    def test_output_dtype(self):
        """Verify output is float32."""
        centroids = generate_deterministic_centroids(10, 10)
        assert centroids.dtype == np.float32

    def test_normalization(self):
        """Verify rows are approximately normalized (sum close to 1)."""
        centroids = generate_deterministic_centroids(100, 100)
        row_sums = np.sum(centroids, axis=1)
        # Should be close to 1 (not exactly 1 due to epsilon)
        assert np.allclose(row_sums, 1.0, atol=1e-5)


class TestDeduplicateItemIds:
    """Tests for item ID deduplication."""

    def test_no_duplicates(self):
        """Verify unique items are preserved."""
        existing = [1, 2, 3]
        new = [4, 5, 6]
        result, seen = deduplicate_item_ids(existing, new)
        assert result == [1, 2, 3, 4, 5, 6]
        assert seen == {1, 2, 3, 4, 5, 6}

    def test_duplicates_removed(self):
        """Verify duplicates are properly removed."""
        existing = [1, 2, 3]
        new = [2, 3, 4]  # 2 and 3 are duplicates
        result, seen = deduplicate_item_ids(existing, new)
        assert result == [1, 2, 3, 4]
        assert seen == {1, 2, 3, 4}

    def test_non_adjacent_duplicates(self):
        """Verify non-adjacent duplicates are detected (this was the bug)."""
        # Simulate batch processing
        result = []
        seen = set()

        # Batch 1
        result, seen = deduplicate_item_ids(result, [1, 2, 3], seen)
        # Batch 2
        result, seen = deduplicate_item_ids(result, [4, 5, 6], seen)
        # Batch 3 - duplicates from batch 1 (non-adjacent!)
        result, seen = deduplicate_item_ids(result, [1, 2, 3], seen)

        assert result == [1, 2, 3, 4, 5, 6], "Non-adjacent duplicates should be detected"
        assert len(result) == 6

    def test_empty_inputs(self):
        """Verify empty inputs work correctly."""
        result, seen = deduplicate_item_ids([], [])
        assert result == []
        assert seen == set()

    def test_with_existing_seen_set(self):
        """Verify existing seen set is used."""
        seen = {1, 2, 3}
        result, seen = deduplicate_item_ids([1, 2, 3], [3, 4, 5], seen)
        assert result == [1, 2, 3, 4, 5]


class TestSafeGetMetadata:
    """Tests for safe metadata access."""

    def test_valid_index(self):
        """Verify valid index returns correct value."""
        metadata = ["a", "b", "c"]
        assert safe_get_metadata(metadata, 0) == "a"
        assert safe_get_metadata(metadata, 1) == "b"
        assert safe_get_metadata(metadata, 2) == "c"

    def test_out_of_bounds(self):
        """Verify out of bounds returns default."""
        metadata = ["a", "b"]
        assert safe_get_metadata(metadata, 5) == ""
        assert safe_get_metadata(metadata, 100) == ""

    def test_negative_index(self):
        """Verify negative index returns default."""
        metadata = ["a", "b"]
        assert safe_get_metadata(metadata, -1) == ""

    def test_none_metadata(self):
        """Verify None metadata returns default."""
        assert safe_get_metadata(None, 0) == ""
        assert safe_get_metadata(None, 5) == ""

    def test_custom_default(self):
        """Verify custom default is used."""
        metadata = ["a"]
        assert safe_get_metadata(metadata, 5, "custom") == "custom"


class TestValidateNprobe:
    """Tests for nprobe validation."""

    def test_matching_values(self):
        """Verify matching values don't raise."""
        validate_nprobe(10, 10)  # Should not raise

    def test_mismatched_values(self):
        """Verify mismatched values raise ValueError."""
        with pytest.raises(ValueError, match="nprobe mismatch"):
            validate_nprobe(10, 5)

    def test_error_message_format(self):
        """Verify error message contains expected and actual values."""
        try:
            validate_nprobe(10, 5)
            pytest.fail("Should have raised ValueError")
        except ValueError as e:
            assert "10" in str(e)
            assert "5" in str(e)


class TestValidateCentroids:
    """Tests for centroids validation."""

    def test_valid_centroids(self):
        """Verify valid centroids don't raise."""
        centroids = np.random.rand(10, 10).astype(np.float32)
        validate_centroids(centroids)  # Should not raise

    def test_none_centroids(self):
        """Verify None raises ValueError with helpful message."""
        with pytest.raises(ValueError, match="not initialized"):
            validate_centroids(None)

    def test_empty_centroids(self):
        """Verify empty array raises ValueError."""
        centroids = np.array([])
        with pytest.raises(ValueError, match="empty"):
            validate_centroids(centroids)


class TestAddressRegistry:
    """Tests for address registry."""

    def test_register_and_check(self):
        """Verify basic registration works."""
        registry = AddressRegistry()
        assert not registry.is_registered("localhost:50050")
        registry.register("localhost:50050")
        assert registry.is_registered("localhost:50050")

    def test_no_substring_matching(self):
        """Verify substring matching doesn't occur (this was the bug)."""
        registry = AddressRegistry()
        registry.register("localhost:50050")

        # "host" should NOT match "localhost:50050"
        assert not registry.is_registered("host")
        # "local" should NOT match "localhost:50050"
        assert not registry.is_registered("local")

    def test_exact_matching(self):
        """Verify exact matching works."""
        registry = AddressRegistry()
        registry.register("server1:50050")
        registry.register("server2:50050")

        assert registry.is_registered("server1:50050")
        assert registry.is_registered("server2:50050")
        assert not registry.is_registered("server3:50050")

    def test_clear(self):
        """Verify clear removes all addresses."""
        registry = AddressRegistry()
        registry.register("addr1")
        registry.register("addr2")
        registry.clear()
        assert not registry.is_registered("addr1")
        assert not registry.is_registered("addr2")


class TestChunkSize:
    """Tests for chunk size constant."""

    def test_chunk_size_is_1mb(self):
        """Verify CHUNK_SIZE_1MB is actually 1MB (not 129MB as was the bug)."""
        assert CHUNK_SIZE_1MB == 1024 * 1024
        assert CHUNK_SIZE_1MB == 1_048_576  # 1MB in bytes

    def test_chunk_size_not_129mb(self):
        """Verify chunk size is NOT the buggy 129MB value."""
        buggy_size = 1024 * 1024 * 129
        assert CHUNK_SIZE_1MB != buggy_size


class TestRegressionBugs:
    """Integration tests that verify specific bug fixes."""

    def test_centroid_determinism_across_100_runs(self):
        """Regression test: 100 runs should produce identical centroids."""
        first_result = None
        for i in range(100):
            centroids = generate_deterministic_centroids(256, 512, seed=42)
            if first_result is None:
                first_result = centroids
            else:
                assert np.allclose(centroids, first_result), f"Run {i} produced different result"

    def test_dedup_handles_400k_scenario(self):
        """Regression test: Simulate 400K items across 100 batches."""
        result = []
        seen = set()

        # 100 batches of 4000 items each
        for batch in range(100):
            batch_ids = list(range(batch * 4000, (batch + 1) * 4000))
            result, seen = deduplicate_item_ids(result, batch_ids, seen)

        assert len(result) == 400_000
        assert len(seen) == 400_000

        # Now add duplicates from random batches
        for batch in [0, 25, 50, 75]:
            duplicate_ids = list(range(batch * 4000, batch * 4000 + 100))
            result, seen = deduplicate_item_ids(result, duplicate_ids, seen)

        # Should still be 400K (duplicates rejected)
        assert len(result) == 400_000

    def test_sparse_metadata_handling(self):
        """Regression test: Handle sparse metadata without IndexError."""
        # 1000 data items but only 500 metadata items
        metadata = [f"meta_{i}" for i in range(500)]

        for idx in range(1000):
            value = safe_get_metadata(metadata, idx)
            if idx < 500:
                assert value == f"meta_{idx}"
            else:
                assert value == ""  # Default for out of bounds
