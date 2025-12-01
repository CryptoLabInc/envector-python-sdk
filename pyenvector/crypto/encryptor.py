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

from typing import List

import evi

from pyenvector.crypto.context import Context
from pyenvector.crypto.parameter import ContextParameter, EncodingType

###################################
# Encryptor Class
###################################


class Encryptor:
    """
    Provides encryption and encoding functionality for vectors using the homomorphic encryption library.
    Supports both float and double vector types, with options for different encoding types and parameters.
    Encryptor requires a file path to the encryption key (asymmetric encryption)
    or secret key path (symmetric encryption).

    Parameters
    -----------
    key_path: str
        The file path to the encrypted key or secret key.

    Example
    --------
    >>> enc = Encryptor(key_path="/path/to/EncKey.bin")
    >>> encrypted_vector = enc.encrypt(vector, encoding="item")
    """

    _context: Context = None

    def __init__(self, enc_key: str):
        if Encryptor._context is None:
            raise ValueError("Context must be initialized before creating an Encryptor instance.")
        self._encryptor = evi.Encryptor(Encryptor._context._context)
        self._enc_key = self._init_key(enc_key)

    def _init_key(self, enc_key: str = None):
        """
        Initialize the encryption key.

        Parameters
        ----------
        key : str
            The file path to the encryption key.

        Returns
        -------
        evi.EncryptionKey
            The initialized encryption key.
        """
        enc_keypack = evi.KeyPack(Encryptor._context._context)
        if isinstance(enc_key, str) and enc_key.endswith(".bin"):
            enc_keypack.load_enc_key_file(enc_key)
        else:
            enc_keypack.load_enc_key_stream(enc_key)
        return enc_keypack

    @classmethod
    def _create_from_context_parameter(cls, context_param: ContextParameter, enc_key: str = None):
        """
        Create a context for the Encryptor.

        Parameters
        ----------
        key_path : str
            The file path to the encryption key.

        Returns
        -------
        Context
            The context object for encryption operations.
        """
        if cls._context is None or cls._context.parameter.dim != context_param.dim:
            cls._context = Context._create_from_parameter(context_param)
        return cls(enc_key)

    @property
    def encryptor(self):
        """
        Returns the underlying evi.Encryptor object.

        Returns:
            evi.Encryptor: The encryptor object for encryption operations.
        """
        return self._encryptor

    # def load_enc_key_from_file(self, enc_key_path: str):
    #     """
    #     Load the encrypted key from a file.

    #     Parameters
    #     ----------
    #     enc_key_path : str
    #         The file path to the encrypted key.

    #     Returns
    #     -------
    #     None
    #     """
    #     self.encryptor.load_enc_key_from_file(enc_key_path)

    # def load_enc_key_from_stream(self, enc_key_stream: IO):
    #     """
    #     Load the encrypted key from a stream.

    #     Parameters
    #     ----------
    #     enc_key_stream : IO
    #         A stream containing the encrypted key.

    #     Returns
    #     -------
    #     None
    #     """
    #     self.encryptor.load_enc_key_from_stream(enc_key_stream)

    def encrypt(self, msg: List[float], encoding: str):
        """
        Encrypts a vector.

        Parameters
        ----------
        msg : List[float]
            The vector to encrypt.
        type : str
            The type of encoding, either "item" or "query".

        Returns
        -------
        evi.Query
            The encrypted vector as a Query object.
        """
        enc_type = EncodingType(encoding)

        return self.encryptor.encrypt(msg, self._enc_key, enc_type.encoding_type, False)  # No considering qf now

    def encrypt_multiple(self, msg: List[List[float]], encoding: str):
        """
        Encrypts multiple vectors.

        Parameters
        ----------
        msg : List[List[float]]
            The list of vectors to encrypt.
        encoding : str
            The type of encoding, either "item" or "query".

        Returns
        -------
        evi.Query
            The list of encrypted vectors as Quey objects.
        """
        enc_type = EncodingType(encoding)

        return self.encryptor.encrypt_bulk(msg, self._enc_key, enc_type.encoding_type, False)

    # def encrypt_with_key(self, msg: List[float], sec_key_path: str, encoding: str):
    #     """
    #     Encrypts a vector using a specific secret key.

    #     Parameters
    #     ----------
    #     msg : List[float]
    #         The vector to encrypt.
    #     sec_key : evi.SecretKey
    #         The secret key to use for encryption.
    #     encoding : str
    #         The type of encoding, either "item" or "query".

    #     Returns
    #     -------
    #     evi.Quey
    #         The encrypted vector as a Query object.
    #     """
    #     sec_key = evi.SecretKey(sec_key_path)
    #     enc_type = EncodingType(encoding)
    #     if enc_type.is_item:
    #         return self.encryptor.encrypt(
    #             msg, sec_key, enc_type.encoding_type, False, float(1 << 25)
    #         )  # No considering qf now
    #     else:  # EncodeType.QUERY
    #         return self.encryptor.encrypt(msg, sec_key, enc_type.encoding_type, False)  # No considering qf now

    # EncryptHERS, EncryptBulk, Encode, EncodeHERS, EncodeBulk
    #  => Add these methods later (Codes are ready, but not in use for now)
