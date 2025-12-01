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

from typing import List, Optional, Union

import evi
from evi import Query

from pyenvector.proto_gen.type_pb2 import CiphertextScore


class CipherBlock:
    """
    CipherBlock class for handling ciphertexts.

    Ciphertexts can be either an encrypted vector or an encrypted similarity scores.
    """

    def __init__(self, data: Union[Query, CiphertextScore], enc_type: Optional[str] = None):
        self._is_score = None
        self.data = data
        self.enc_type = enc_type

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

    @enc_type.setter
    def enc_type(self, value: Optional[str]):
        if value and value not in ["multiple", "single"]:
            raise ValueError("Invalid enc_type. Must be 'multiple' or 'single'.")
        self._enc_type = value

    @shard_idx.setter
    def shard_idx(self, value: Optional[int]):
        self._shard_idx = value if value else None

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
            return self
        elif isinstance(value, Query):
            self._is_score = False
            self.enc_type = "single"
            self._data = [value]
            return self
        elif isinstance(value, list) and all(isinstance(v, Query) for v in value):
            self._is_score = False
            self.enc_type = "multiple"
            self._data = value
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
