# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

import warnings
from numbers import Integral
from typing import List, Optional, Sequence, Union

import evi
from evi import Query

from pyenvector.proto_gen.v2.common.type_pb2 import CiphertextScore


class CipherBlock:
    """
    CipherBlock class for handling ciphertexts.

    Ciphertexts can be either an encrypted vector or an encrypted similarity scores.
    """

    def __init__(
        self,
        data: Union[Query, CiphertextScore],
        enc_type: Optional[str] = None,
        centroids_idx: Optional[Sequence[int]] = None,
    ):
        self._is_score = None
        self._centroids_idx = None
        self.data = data
        self.enc_type = enc_type
        self.centroids_idx = centroids_idx

    @property
    def data(self):
        return self._data

    @property
    def enc_type(self):
        return self._enc_type

    @property
    def is_score(self):
        return self._is_score

    @property
    def shard_idx(self):
        return self._shard_idx

    @property
    def centroids_idx(self):
        return self._centroids_idx

    @enc_type.setter
    def enc_type(self, value: Optional[str]):
        if value and value not in ["multiple", "single"]:
            raise ValueError("Invalid enc_type. Must be 'multiple' or 'single'.")
        self._enc_type = value

    @shard_idx.setter
    def shard_idx(self, value: Optional[int]):
        self._shard_idx = value if value else None

    @centroids_idx.setter
    def centroids_idx(self, value: Optional[Sequence[int]]):
        if value is None:
            self._centroids_idx = None
            return
        if self.is_score:
            raise ValueError("centroids_idx is only supported for vector ciphertext blocks.")
        if isinstance(value, Integral):
            normalized = [int(value)]
        else:
            if not isinstance(value, (list, tuple)):
                raise ValueError("centroids_idx must be an integer or a list/tuple of integers.")
            normalized = list(value)
        if not all(isinstance(v, Integral) for v in normalized):
            raise ValueError("centroids_idx must contain only integers.")
        if len(normalized) != self.num_vectors:
            raise ValueError(f"centroids_idx length {len(normalized)} must match num_vectors {self.num_vectors}.")
        self._centroids_idx = [int(v) for v in normalized]

    @property
    def num_vectors(self):
        if not self.is_score:
            total = 0
            for vec in self.data:
                total += vec.getInnerItemCount()
            return total
        else:
            raise ValueError("Invalid data type for num_vectors.")

    @property
    def num_item_list(self):
        if not self.is_score:
            if self.enc_type == "multiple":
                item_list = []
                for vec in self.data:
                    item_list.append(vec.getInnerItemCount())
                return item_list
            else:
                return [len(self.data)]
        else:
            raise ValueError("Invalid data type for num_item_list.")

    @property
    def num_ciphertexts(self):
        if not self.is_score:
            return len(self.data)
        else:
            raise ValueError("Invalid data type for num_ciphertexts.")

    @data.setter
    def data(self, value: Union[Query, List[Query], CiphertextScore]):
        if not value:
            raise ValueError("Data list cannot be empty.")
        if isinstance(value, CiphertextScore):
            self._is_score = True
            self._data = value
            self.shard_idx = getattr(value, "shard_idx", None)
            if self._centroids_idx is not None:
                warnings.warn(
                    "centroids_idx has been reset because data was reassigned to a CiphertextScore.",
                    UserWarning,
                    stacklevel=2,
                )
            self._centroids_idx = None
            return self
        elif isinstance(value, Query):
            self._is_score = False
            self.enc_type = "single"
            self._data = [value]
            if self._centroids_idx is not None:
                warnings.warn(
                    "centroids_idx has been reset because data was reassigned to a new Query.",
                    UserWarning,
                    stacklevel=2,
                )
            self._centroids_idx = None
            return self
        elif isinstance(value, list) and all(isinstance(v, Query) for v in value):
            self._is_score = False
            self.enc_type = "multiple"
            self._data = value
            if self._centroids_idx is not None:
                warnings.warn(
                    "centroids_idx has been reset because data was reassigned to a new list of Queries.",
                    UserWarning,
                    stacklevel=2,
                )
            self._centroids_idx = None
            return self
        elif isinstance(value, list) and all(isinstance(v, bytes) for v in value):
            self._is_score = False
            self._data = value
            if self._centroids_idx is not None:
                warnings.warn(
                    "centroids_idx has been reset because data was reassigned to a new list of bytes.",
                    UserWarning,
                    stacklevel=2,
                )
            self._centroids_idx = None
            return self
        else:
            raise ValueError("Data must be a list of Query or CiphertextScore.")

    def serialize(self) -> bytes:
        """
        Serializes the CipherBlock to bytes.

        Returns:
            bytes: Serialized bytes of the CipherBlock.
        """
        if self.is_score is True:
            raise ValueError("CipherBlock data must be set before serialization.")
        return evi.Query.serializeTo(self.data[0])
