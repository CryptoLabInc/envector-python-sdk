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

"""
Cipher Module

This module provides encryption and decryption functionalities for vectors
and scores using the pyenvector/enVector framework.

Classes:
    Cipher: Handles encryption and decryption operations.

Example:
    # Initialize with key paths
    cipher = Cipher(dim=512, enc_key_path="./temp/keys/EncKey.bin", sec_key_path="./temp/keys/SecKey.bin")
    vec = [0.0] * 512
    enc_vec = cipher.encrypt(vec, "item")
    dec_vec = cipher.decrypt(enc_vec)

    # Or specify key paths at method call
    cipher = Cipher(dim=512)
    enc_vec = cipher.encrypt(vec, enc_key_path="./temp/keys/EncKey.bin")
    dec_vec = cipher.decrypt(enc_vec, sec_key_path="./temp/keys/SecKey.bin")
"""

import os
from numbers import Integral
from typing import TYPE_CHECKING, Optional, Sequence

import numpy as np

from pyenvector.crypto.block import CipherBlock
from pyenvector.crypto.decryptor import Decryptor
from pyenvector.crypto.encryptor import Encryptor
from pyenvector.crypto.parameter import ContextParameter

if TYPE_CHECKING:
    from pyenvector.index import IndexConfig

from ..utils import utils


class Cipher:
    """
    Cipher class for handling encryption and decryption operations.
    """

    def __init__(
        self,
        enc_key_path: Optional[str] = None,
        sec_key_path: Optional[str] = None,
        preset: Optional[str] = None,
        dim: Optional[int] = None,
        eval_mode: Optional[str] = None,
        level: Optional[int] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        seal_kek: Optional[str] = None,
        use_key_stream: bool = False,
        enc_key: Optional[str] = None,
        sec_key: Optional[str] = None,
    ):
        if dim is None or not (dim >= 32 and dim <= 4096):
            raise ValueError("Dimension (dim) must be specified for Cipher initialization.")
        self._context_param = ContextParameter(preset=preset, dim=dim, eval_mode=eval_mode, level=level)
        if seal_kek is None and seal_kek_path is not None:
            seal_kek = seal_kek_path
        if enc_key_path is not None:
            if os.path.exists(enc_key_path) is False:
                raise ValueError(f"Encryption key not found in {enc_key_path}.")
            enc_key_stream = utils.get_key_stream(enc_key_path)
            self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key_stream)
        elif use_key_stream and enc_key is not None:
            enc_key_stream = utils.get_key_stream(enc_key)
            self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key_stream)
        else:
            env_enc_key = utils.get_envector_enc_key()
            if env_enc_key is not None:
                enc_key_stream = utils.get_key_stream(env_enc_key)
                self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key_stream)
            else:
                self._encryptor = None
        env_sec_key = utils.get_envector_sec_key()
        self._seal_info = None
        self._decryptor = None
        self._sec_key_path = None
        self._sec_key = None

        if sec_key_path is not None:
            if os.path.exists(sec_key_path) is False:
                sec_key_path = None  # SK not available locally (e.g. fully-managed mode)
            self._seal_info = utils._get_seal_info(seal_mode, seal_kek)
            self._decryptor = Decryptor._create_from_context_parameter(
                self._context_param, sec_key_path, self._seal_info
            )
            self._sec_key_path = sec_key_path
            self._sec_key = sec_key_path
        elif use_key_stream and sec_key is not None:
            self._seal_info = utils._get_seal_info(seal_mode, seal_kek)
            self._decryptor = Decryptor._create_from_context_parameter(self._context_param, sec_key, self._seal_info)
            self._sec_key = sec_key
        elif env_sec_key is not None:
            self._seal_info = utils._get_seal_info(seal_mode, seal_kek)
            self._decryptor = Decryptor._create_from_context_parameter(
                self._context_param, env_sec_key, self._seal_info
            )
            self._sec_key = env_sec_key

    @classmethod
    def _create_from_index_config(cls, index_config: "IndexConfig"):
        """
        Initializes the Cipher class from an IndexConfig.

        Args:
            index_config (IndexConfig): The configuration for the index, including preset and key paths.
        """

        return cls(
            enc_key_path=index_config.enc_key_path,
            sec_key_path=index_config.sec_key_path,
            preset=index_config.preset,
            dim=index_config.dim,
            eval_mode=index_config.eval_mode,
            level=index_config.level,
            seal_mode=index_config.seal_mode,
            seal_kek=index_config.seal_kek,
            use_key_stream=index_config.use_key_stream,
            enc_key=index_config.enc_key,
            sec_key=index_config.sec_key,
        )

    def _normalize_item_encrypt_input(self, data):
        """
        Normalizes input formats for item encryption to match Index.insert-style inputs.

        Returns:
            Tuple[List[Union[list, np.ndarray]], bool]: (normalized_vectors, is_single_input)
        """
        if isinstance(data, np.ndarray):
            if data.size == 0:
                raise ValueError("Data cannot be empty.")
            if data.ndim == 1:
                if data.shape[0] != self._context_param.dim:
                    raise ValueError(
                        f"Data dimension {data.shape[0]} does not match context dimension {self._context_param.dim}."
                    )
                return [data], True
            if data.ndim == 2:
                if data.shape[1] != self._context_param.dim:
                    raise ValueError(
                        f"Data dimension {data.shape[1]} does not match context dimension {self._context_param.dim}."
                    )
                return list(data), False
            raise ValueError("Data must be a 1D or 2D numpy array.")

        if isinstance(data, list):
            if not data:
                raise ValueError("Data cannot be empty.")
            first = data[0]
            if isinstance(first, (int, float, np.floating, np.integer)):
                if not all(isinstance(v, (int, float, np.floating, np.integer)) for v in data):
                    raise ValueError("All elements in a flat list input must be numeric.")
                if len(data) != self._context_param.dim:
                    raise ValueError(
                        f"Data dimension {len(data)} does not match context dimension {self._context_param.dim}."
                    )
                return [data], True
            if isinstance(first, list):
                if not all(isinstance(v, list) for v in data):
                    raise ValueError("All elements in a list-of-lists input must be lists.")
                if len(first) != self._context_param.dim:
                    raise ValueError(
                        f"Data dimension {len(first)} does not match context dimension {self._context_param.dim}."
                    )
                return data, False
            if isinstance(first, np.ndarray):
                if first.ndim != 1:
                    raise ValueError("Each numpy vector in list input must be 1D.")
                if first.shape[0] != self._context_param.dim:
                    raise ValueError(
                        f"Data dimension {first.shape[0]} does not match context dimension {self._context_param.dim}."
                    )
                return data, False

        raise ValueError("Data must be a list of floats, list of lists, numpy arrays, or 2D numpy array.")

    def encrypt(
        self,
        vector,
        encode_type: str = "item",
        enc_key_path: Optional[str] = None,
        enc_key: Optional[str] = None,
        centroids_idx: Optional[Sequence[int]] = None,
        use_row_encrypt: bool = False,
        split_batch_size: int = 4096,
    ):
        """
        Encrypts one or multiple vectors.

        Args:
            vector (Union[list[float], list[list[float]], list[np.ndarray], np.ndarray]):
                Input vector(s) to encrypt.

                - 1D list of floats or 1-D ``np.ndarray``: single vector.
                - 2D ``np.ndarray`` of shape ``(N, dim)``: batch of N vectors.
                - list of lists or list of 1-D ``np.ndarray``: batch of N vectors.

            encode_type (str): Encoding type. ``"item"`` (default) or ``"query"``.
                When ``"query"``, delegates to :meth:`encrypt_query` and returns a single
                :class:`CipherBlock`; batch input is rejected.
            enc_key_path (str, optional): Path to the encryption key file.
            enc_key (Union[str, bytes], optional): Raw key bytes or serialized key string.
            centroids_idx (Sequence[int], optional): Centroid IDs for each input vector,
                stored in the returned :class:`CipherBlock` for IVF insert.
            use_row_encrypt (bool, optional): If ``True``, uses :meth:`encrypt_row` instead
                of :meth:`encrypt_multiple`.
            split_batch_size (int, optional): Maximum number of vectors per
                :class:`CipherBlock`. When the total exceeds this value the result is a
                ``list`` of :class:`CipherBlock` objects. Defaults to ``4096``.

        Returns:
            Union[CipherBlock, list[CipherBlock]]:
                A single :class:`CipherBlock` for single-vector input or when the total
                vector count does not exceed *split_batch_size*.
                A ``list`` of :class:`CipherBlock` when the batch is split.

        Examples:
            >>> cipher = Cipher(dim=512, enc_key_path="./temp/keys/EncKey.bin")
            >>> vec = [0.0] * 512
            >>> enc_vec = cipher.encrypt(vec)

            >>> cipher = Cipher(dim=512)
            >>> vec = [0.0] * 512
            >>> enc_vec = cipher.encrypt(vec, enc_key_path="./temp/keys/EncKey.bin")
        """
        if encode_type == "query":
            if (isinstance(vector, list) and vector and isinstance(vector[0], (list, np.ndarray))) or (
                isinstance(vector, np.ndarray) and vector.ndim == 2
            ):
                raise ValueError(
                    "encrypt(..., encode_type='query') expects a single vector. "
                    "Use encrypt_query() per vector for batched queries."
                )
            return self.encrypt_query(vector, enc_key_path=enc_key_path, enc_key=enc_key)
        if encode_type != "item":
            raise ValueError(f"Unsupported encode_type '{encode_type}'. Use 'item' or call encrypt_query().")
        vectors, is_single = self._normalize_item_encrypt_input(vector)
        total_vectors = len(vectors)
        normalized_centroids = None
        if centroids_idx is not None:
            if isinstance(centroids_idx, Integral):
                if total_vectors != 1:
                    raise ValueError("centroids_idx as integer is allowed only for single-vector input.")
                normalized_centroids = [int(centroids_idx)]
            else:
                normalized_centroids = list(centroids_idx)
                if len(normalized_centroids) != total_vectors:
                    raise ValueError(
                        f"centroids_idx length {len(normalized_centroids)} must match number of vectors {total_vectors}."
                    )

        if is_single:
            if use_row_encrypt:
                result = self.encrypt_row(
                    vectors,
                    encode_type="item",
                    enc_key_path=enc_key_path,
                    enc_key=enc_key,
                    centroids_idx=normalized_centroids,
                )
            else:
                result = self.encrypt_multiple(
                    vectors,
                    encode_type="item",
                    enc_key_path=enc_key_path,
                    enc_key=enc_key,
                    centroids_idx=normalized_centroids,
                )
            result.enc_type = "single"
            return result

        if split_batch_size is not None and split_batch_size <= 0:
            raise ValueError("split_batch_size must be a positive integer.")
        if split_batch_size is None or total_vectors <= split_batch_size:
            if use_row_encrypt:
                return self.encrypt_row(
                    vectors,
                    encode_type="item",
                    enc_key_path=enc_key_path,
                    enc_key=enc_key,
                    centroids_idx=normalized_centroids,
                )
            return self.encrypt_multiple(
                vectors,
                encode_type="item",
                enc_key_path=enc_key_path,
                enc_key=enc_key,
                centroids_idx=normalized_centroids,
            )

        split_blocks = []
        for i in range(0, total_vectors, split_batch_size):
            end_idx = min(i + split_batch_size, total_vectors)
            vectors_chunk = vectors[i:end_idx]
            centroids_chunk = normalized_centroids[i:end_idx] if normalized_centroids is not None else None
            if use_row_encrypt:
                chunk_block = self.encrypt_row(
                    vectors_chunk,
                    encode_type="item",
                    enc_key_path=enc_key_path,
                    enc_key=enc_key,
                    centroids_idx=centroids_chunk,
                )
            else:
                chunk_block = self.encrypt_multiple(
                    vectors_chunk,
                    encode_type="item",
                    enc_key_path=enc_key_path,
                    enc_key=enc_key,
                    centroids_idx=centroids_chunk,
                )
            split_blocks.append(chunk_block)
        return split_blocks

    def encrypt_query(self, vector, enc_key_path: Optional[str] = None, enc_key: Optional[str] = None):
        """
        Encrypts a single query vector.
        """
        if isinstance(vector, list):
            vector = np.array(vector)
        if isinstance(vector, np.ndarray) and vector.ndim != 1:
            raise ValueError("encrypt_query() expects a single vector (1D).")
        if vector.shape[0] != self._context_param.dim:
            raise ValueError(
                f"Vector dimension {vector.shape[0]} does not match context dimension {self._context_param.dim}."
            )
        if enc_key_path:
            if os.path.exists(enc_key_path) is False:
                raise ValueError(f"Encryption key not found in {enc_key_path}.")
            enc_key = enc_key_path
        if enc_key is not None:
            enc_key = utils.get_key_stream(enc_key)
            self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key)
        elif self._encryptor is None:
            raise ValueError("Encryptor is not initialized. Ensure the encryption key path is set.")

        enc_res = self.encryptor.encrypt(vector, "query")
        return CipherBlock(data=enc_res, enc_type="single")

    def encrypt_multiple(
        self,
        vectors,
        encode_type: str = "item",
        enc_key_path: Optional[str] = None,
        enc_key: Optional[str] = None,
        centroids_idx: Optional[Sequence[int]] = None,
    ):
        """
        Encrypts multiple vectors.

        Args:
            vectors (Sequence[Union[list, np.ndarray]]): The vectors to encrypt.
            encode_type (str): The encoding type used during encryption. Only ``"item"`` is supported.
            enc_key_path (str, optional): Path to the encryption key file.
            enc_key (Union[str, bytes], optional): Raw key bytes or serialized key string
                                                    to use instead of loading from disk.

        Returns:
            CipherBlock: Batched encrypted vectors.

        Examples:
            >>> cipher = Cipher(dim=512, enc_key_path="./temp/keys/EncKey.bin")
            >>> vecs = [[0.0] * 512] * 100
            >>> enc_vec = cipher.encrypt_multiple(vecs, "item")

            >>> cipher = Cipher(dim=512)
            >>> vecs = [[0.0] * 512] * 100
            >>> enc_vec = cipher.encrypt_multiple(vecs, "item", enc_key_path="./temp/keys/EncKey.bin")
        """
        if encode_type != "item":
            raise ValueError("encrypt_multiple() supports only encode_type='item'. Use encrypt_query().")
        if enc_key_path:
            if os.path.exists(enc_key_path) is False:
                raise ValueError(f"Encryption key not found in {enc_key_path}.")
            enc_key = enc_key_path
        if enc_key is not None:
            enc_key = utils.get_key_stream(enc_key)
            self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key)
        elif self._encryptor is None:
            raise ValueError("Encryptor is not initialized. Ensure the encryption key path is set.")

        enc_res = []
        level = self._context_param.level if getattr(self._context_param, "level", None) is not None else 0
        enc_res = self.encryptor.encrypt_multiple(vectors, encode_type, level)  # Hand over level info to encryptor
        enc_type = "multiple"
        return CipherBlock(data=enc_res, enc_type=enc_type, centroids_idx=centroids_idx)

    def encrypt_row(
        self,
        vectors,
        encode_type: str = "item",
        enc_key_path: Optional[str] = None,
        enc_key: Optional[str] = None,
        centroids_idx: Optional[Sequence[int]] = None,
    ):
        """
        Encrypts multiple vectors.

        Args:
            vectors (Sequence[Union[list, np.ndarray]]): The vectors to encrypt.
            encode_type (str): The encoding type used during encryption. Only ``"item"`` is supported.
            enc_key_path (str, optional): Path to the encryption key file.
            enc_key (Union[str, bytes], optional): Raw key bytes or serialized key string
                                                    to use instead of loading from disk.

        Returns:
            CipherBlock: Batched encrypted vectors.

        Examples:
            >>> cipher = Cipher(dim=512, enc_key_path="./temp/keys/EncKey.bin")
            >>> vecs = [[0.0] * 512] * 100
            >>> enc_vec = cipher.encrypt_row(vecs, "item")

            >>> cipher = Cipher(dim=512)
            >>> vecs = [[0.0] * 512] * 100
            >>> enc_vec = cipher.encrypt_row(vecs, "item", enc_key_path="./temp/keys/EncKey.bin")
        """
        if encode_type != "item":
            raise ValueError("encrypt_row() supports only encode_type='item'. Use encrypt_query().")
        if enc_key_path:
            if os.path.exists(enc_key_path) is False:
                raise ValueError(f"Encryption key not found in {enc_key_path}.")
            enc_key = enc_key_path
        if enc_key is not None:
            enc_key = utils.get_key_stream(enc_key)
            self._encryptor = Encryptor._create_from_context_parameter(self._context_param, enc_key)
        elif self._encryptor is None:
            raise ValueError("Encryptor is not initialized. Ensure the encryption key path is set.")

        enc_res = []
        level = self._context_param.level if getattr(self._context_param, "level", None) is not None else 0
        enc_res = self.encryptor.encrypt_row(vectors, encode_type, level)  # Hand over level info to encryptor
        enc_type = "single"
        return CipherBlock(data=enc_res, enc_type=enc_type, centroids_idx=centroids_idx)

    def decrypt(
        self,
        encrypted_vector,
        sec_key_path: Optional[str] = None,
        idx: int = 0,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        seal_kek: Optional[str] = None,
        sec_key: Optional[str] = None,
    ):
        """
        Decrypts an encrypted vector.

        Args:
            encrypted_vector (CipherBlock): The vector to be decrypted.
            sec_key_path (str, optional): The path to the secret key file for decryption
            (defaults to the configured path).
            idx (int, optional): The index of the vector to decrypt when the ciphertext contains multiple vectors.
            seal_mode (str, optional): Seal mode used for the secret key.
            seal_kek_path (str, optional): Path to the KEK file if the key is sealed.
            seal_kek (Union[str, bytes], optional): Raw KEK bytes or string to unseal the key.
            sec_key (Union[str, bytes], optional): Raw secret-key bytes/string.

        Returns:
            ``list`` : Decrypted vector.

        Examples:
            >>> cipher = Cipher(dim=512, enc_key_path="./temp/keys/EncKey.bin")
            >>> enc_vec = cipher.encrypt([0.0] * 512, "item")
            >>> dec_vec = cipher.decrypt(enc_vec, sec_key_path="./temp/keys/SecKey.bin")
        """
        if not isinstance(encrypted_vector, CipherBlock):
            raise ValueError("The encrypted vector must be an instance of CipherBlock.")
        if encrypted_vector.is_score:
            raise ValueError("The encrypted vector must not be a score. use decrypt_score().")
        if sec_key_path:
            sec_key = sec_key_path
            self._sec_key_path = sec_key_path
            self._sec_key = sec_key_path
        elif sec_key is None:
            sec_key = self.sec_key
        else:
            self._sec_key = sec_key
        if seal_kek_path and seal_kek is None:
            seal_kek = seal_kek_path
        if self._decryptor is None:
            seal_info = utils._get_seal_info(seal_mode, seal_kek)
            decryptor = Decryptor._create_from_context_parameter(self._context_param, seal_info=seal_info)
        else:
            seal_info = self._seal_info
            decryptor = self.decryptor
        sec_key = utils.get_key_stream(sec_key)
        if encrypted_vector.enc_type == "single":
            result = decryptor.decrypt(encrypted_vector.data[0], sec_key=sec_key)
            del sec_key
            return result
        else:
            if idx < 0 or idx >= encrypted_vector.num_vectors:
                raise IndexError("Index out of range for the encrypted vector.")
            total = 0
            for i, count in enumerate(encrypted_vector.num_item_list):
                if idx < total + count:
                    block_idx = i
                    dec_idx = idx - total
                    break
                total += count
            result = decryptor.decrypt_with_idx(encrypted_vector.data[block_idx], dec_idx, sec_key=sec_key)
            del sec_key
            return result

    def decrypt_score(
        self,
        encrypted_score,
        sec_key_path: Optional[str] = None,
        sec_key: Optional[str] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        seal_kek: Optional[str] = None,
    ):
        """
        Decrypts an encrypted score.

        Args:
            encrypted_score (CipherBlock): The score to be decrypted.
            sec_key_path (str, optional): The path to the secret key file.
            sec_key (Union[str, bytes], optional): Raw secret-key bytes or serialized string.
            seal_mode (str, optional): Seal mode used for the secret key.
            seal_kek_path (str, optional): Path to the KEK when unsealing the key.
            seal_kek (Union[str, bytes], optional): Raw KEK bytes/string when available.

        Returns:
            ``list`` : Decrypted score.

        Examples:
            >>> result_ctxt = index.search(...)
            >>> dec_score = cipher.decrypt_score(result_ctxt, sec_key_path="./temp/keys/SecKey.bin")
        """
        if not isinstance(encrypted_score, CipherBlock):
            raise ValueError("The encrypted score must be an instance of CipherBlock.")
        if not encrypted_score._is_score:
            raise ValueError("The encrypted score must be a CipherBlock with is_score set to True.")
        if sec_key_path:
            sec_key = sec_key_path
            self._sec_key_path = sec_key_path
            self._sec_key = sec_key_path
        elif sec_key is None:
            sec_key = self.sec_key
        else:
            self._sec_key = sec_key
        if seal_kek_path and seal_kek is None:
            seal_kek = seal_kek_path
        if self._decryptor is None:
            seal_info = utils._get_seal_info(seal_mode, seal_kek)
            decryptor = Decryptor._create_from_context_parameter(self._context_param, seal_info=seal_info)
        else:
            decryptor = self._decryptor
        sec_key = utils.get_key_stream(sec_key)
        result = []
        for score in encrypted_score.data.ctxt_score:
            result.append(decryptor.decrypt_score(score, sec_key=sec_key))
        del sec_key
        ret = {"score": result}

        if encrypted_score.shard_idx:
            assert len(result) == len(encrypted_score.shard_idx)
            shard_idx = encrypted_score.shard_idx
            ret["shard_idx"] = shard_idx

        return ret

    @property
    def encryptor(self):
        """
        Returns the encryptor object.

        Returns:
            Encryptor: The encryptor object for encryption operations.
        """
        if self._encryptor is None:
            raise ValueError("Encryptor is not initialized. Ensure the encryption key path is set.")
        return self._encryptor

    @property
    def decryptor(self):
        """
        Returns the decryptor object.

        Returns:
            Decryptor: The decryptor object for decryption operations.
        """
        if self._decryptor is None:
            raise ValueError("Decryptor is not initialized. Ensure the secret key path is set.")
        return self._decryptor

    @property
    def sec_key_path(self):
        """
        Returns the path to the secret key file.

        Returns:
            ``str``: The path to the secret key file used for decryption.
        """
        if self._sec_key_path is None:
            raise ValueError("Secret key path is not set. Ensure the secret key file exists.")
        return self._sec_key_path

    @property
    def sec_key(self):
        """
        Returns the configured secret key source (path or bytes).

        Returns:
            ``Union[str, bytes]``: The secret key material used for decryption.
        """
        if self._sec_key is not None:
            return self._sec_key
        if self._sec_key_path is not None:
            self._sec_key = self._sec_key_path
            return self._sec_key
        env_sec_key = utils.get_envector_sec_key()
        if env_sec_key is not None:
            self._sec_key = env_sec_key
            return self._sec_key
        raise ValueError("Secret key path is not set. Ensure the secret key file exists.")
