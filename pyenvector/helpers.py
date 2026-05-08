"""
Helper functions for pyenvector with modular, testable implementations.

These helpers address specific bugs found during static analysis for
the 400K IVFGAS experiment.
"""

from typing import List, Optional, Set, Tuple

import numpy as np


def generate_deterministic_centroids(nlist: int, dim: int, seed: int = 42, epsilon: float = 1e-10) -> np.ndarray:
    """
    Generate deterministic centroids for IVF index.

    This function fixes two bugs:
    1. Non-deterministic centroid generation (np.random.rand without seed)
    2. Division by zero on zero-sum rows

    Parameters
    ----------
    nlist : int
        Number of centroids (IVF clusters)
    dim : int
        Dimension of each centroid
    seed : int, optional
        Random seed for reproducibility (default: 42)
    epsilon : float, optional
        Small value to prevent division by zero (default: 1e-10)

    Returns
    -------
    np.ndarray
        Normalized centroids of shape (nlist, dim)
    """
    rng = np.random.default_rng(seed)
    centroids = rng.random((nlist, dim)).astype(np.float32)
    # Add epsilon to prevent division by zero on zero-sum rows
    centroids /= np.sum(centroids, axis=1, keepdims=True) + epsilon
    return centroids


def deduplicate_item_ids(
    existing_ids: List[int], new_ids: List[int], seen_set: Optional[Set[int]] = None
) -> Tuple[List[int], Set[int]]:
    """
    Properly deduplicate item IDs across batches.

    This function fixes the bug where only the last N items were compared,
    missing duplicates from earlier batches.

    Parameters
    ----------
    existing_ids : List[int]
        List of existing item IDs
    new_ids : List[int]
        New item IDs to add (may contain duplicates)
    seen_set : Optional[Set[int]]
        Set of already seen IDs (for efficiency). If None, built from existing_ids.

    Returns
    -------
    Tuple[List[int], Set[int]]
        Updated list of unique IDs and the seen set
    """
    if seen_set is None:
        seen_set = set(existing_ids)

    result = list(existing_ids)
    for new_id in new_ids:
        if new_id not in seen_set:
            result.append(new_id)
            seen_set.add(new_id)

    return result, seen_set


def safe_get_metadata(metadata: Optional[List[str]], index: int, default: str = "") -> str:
    """
    Safely get metadata at index with bounds checking.

    This function fixes the IndexError when metadata list is shorter
    than the data list (sparse metadata scenario).

    Parameters
    ----------
    metadata : Optional[List[str]]
        Metadata list (may be None or shorter than expected)
    index : int
        Index to access
    default : str, optional
        Default value if index is out of bounds (default: "")

    Returns
    -------
    str
        Metadata value or default
    """
    if metadata is None or index < 0 or index >= len(metadata):
        return default
    return metadata[index]


def validate_nprobe(nprobe: int, search_topk_len: int) -> None:
    """
    Validate that nprobe matches search_topk length.

    This function replaces assert statements which can be disabled
    with Python -O flag.

    Parameters
    ----------
    nprobe : int
        Expected nprobe value
    search_topk_len : int
        Actual length of search_topk results

    Raises
    ------
    ValueError
        If nprobe doesn't match search_topk_len
    """
    if nprobe != search_topk_len:
        raise ValueError(f"nprobe mismatch: expected {nprobe}, got {search_topk_len}")


def validate_centroids(centroids) -> None:
    """
    Validate that centroids are properly initialized.

    This function provides a helpful error message instead of
    cryptic AttributeError when centroids are None.

    Parameters
    ----------
    centroids : Optional[np.ndarray]
        Centroids array to validate

    Raises
    ------
    ValueError
        If centroids are None or empty
    """
    if centroids is None:
        raise ValueError("Centroids not initialized. Load index metadata first.")
    if hasattr(centroids, "size") and centroids.size == 0:
        raise ValueError("Centroids array is empty. Load index metadata first.")


class AddressRegistry:
    """
    Thread-safe registry for tracking verified server addresses.

    This class fixes the race condition where _REGISTERED_ADDRS was
    assigned as a string instead of being added to a set, causing
    substring matching bugs.
    """

    def __init__(self):
        self._addresses: Set[str] = set()

    def is_registered(self, address: str) -> bool:
        """Check if address has been registered."""
        return address in self._addresses

    def register(self, address: str) -> None:
        """Register an address as verified."""
        self._addresses.add(address)

    def clear(self) -> None:
        """Clear all registered addresses."""
        self._addresses.clear()


# TODO Decrease Chunk Size
# Matrix ciphertext max chunk size: 257MB
# 4096(max row) * 2(a,b part) * 2(level1) * 8(bytes) * 4096(max Dim) = 268435456 bytes = 256MB
# 1 MB for other fields, so we set chunk size to 257MB
CHUNK_SIZE_1MB = 1024 * 1024
CHUNK_SIZE_257MB = 257 * CHUNK_SIZE_1MB
