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

import json
from pathlib import Path
from typing import List, Optional, Union

import evi

from pyenvector.crypto.context import Context
from pyenvector.crypto.parameter import ContextParameter, KeyParameter

from ..utils.aes import generate_aes256_key, seal_metadata_enc_key
from ..utils.utils import _get_seal_info, is_empty_dir

# *********************************************************************
# * Key generation module for the pyenvector/enVector workflow (CCMM)
# * Plans for now:
#     1. Make pybind11 wrapper of EVI (DONE)
#     2. Keygen class just need to call pybind11 wrapped code + a (WIP)
# *********************************************************************

###################################
# KeyGenerator Class
###################################


class KeyGenerator:
    """
    Key Generator with the given parameters.

    Parameters
    ------------
    key_path : str
        The path where keys will be stored.
    dim_list : list, optional
        List of dimensions for the context. Defaults to powers of 2 from 32 to 4096.
    preset : str, optional
        The parameter preset to use for the context. Defaults to "ip".
    seal_info : SealInfo, optional
        The seal information for the keys. Defaults to "SealMode.NONE".
    eval_mode : str, optional
        The evaluation mode for the context. Defaults to "RMP".
    metadata_encryption: bool, optional
        Whether to enable metadata encryption. Defaults to None.

    Example
    --------
    >>> keygen = KeyGenerator("./keys")
    >>> keygen.generate_keys()
    """

    def __init__(
        self,
        key_path,
        dim_list: Optional[Union[int, List[int]]] = None,
        preset: Optional[str] = "ip",
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        seal_kek: Optional[Union[bytes, str]] = None,
        eval_mode: Optional[str] = "RMP",
        metadata_encryption: Optional[bool] = None,
    ):
        if dim_list is None:
            dim_list = [2**i for i in range(5, 13)]
        if isinstance(dim_list, int):
            dim_list = [dim_list]
        context_list = [Context(preset, d, eval_mode)._context for d in dim_list]
        if seal_kek is None and seal_kek_path is not None:
            seal_kek = seal_kek_path
        self._seal_mode = seal_mode
        self._seal_kek = seal_kek
        self.sInfo = _get_seal_info(seal_mode, seal_kek)
        key_param = KeyParameter(
            key_path=key_path, seal_mode=seal_mode, seal_kek=seal_kek, metadata_encryption=metadata_encryption
        )
        self._key_generator = evi.MultiKeyGenerator(context_list, key_path, self.sInfo)
        self._context_param = ContextParameter(preset, eval_mode=eval_mode)
        self._key_param = key_param
        self._dim_list = dim_list
        self.key_path = key_path

    @classmethod
    def _create_from_parameter(cls, context_param: ContextParameter, key_param: KeyParameter):
        """
        Initializes the KeyGenerator with the given context and key parameters.

        Args:
            context_param (ContextParameter): The context parameters for the key generation.
            key_param (KeyParameter): The key parameters for the key generation.
        """
        return cls(
            key_param.key_dir,
            preset=context_param.preset_name,
            eval_mode=context_param.eval_mode,
            seal_mode=key_param.seal_mode_name,
            seal_kek=key_param.seal_kek,
            metadata_encryption=key_param.metadata_encryption,
        )

        # *********************************************************************
        # Call EVI keygen code which is member of EnvectorClient.KeyGenerator
        # With this, key file will be automatically saved to key_path
        # *********************************************************************

    def generate_keys(self):
        """
        Generate all keys including encryption, evaluation, and secret keys.

        Parameters
        ----------
        None

        Returns
        -------
        KeyGenerator: The KeyGenerator instance with generated keys.
        """

        # Ensure the key path exists, create directories if necessary
        key_path = Path(self.key_path).expanduser().resolve()
        key_path.mkdir(parents=True, exist_ok=True)

        # Check if the directory is empty
        if not is_empty_dir(self.key_path):
            raise ValueError(f"Key path '{self.key_path}' is not empty. Key generation canceled.")

        # Generate keys
        self._key_generator.generate_keys()
        if self._key_param.metadata_encryption:
            # Generate metadata encryption key
            sealing = self._key_param.seal_info.mode != evi.SealMode.NONE
            metadata_enc_key = generate_aes256_key(self._key_param.metadata_key_path, not sealing)

            # If KEK sealing is enabled, seal the metadata encryption key
            if self._key_param.seal_info.mode != evi.SealMode.NONE:
                sealed_key_path = self._key_param.metadata_key_path
                seal_metadata_enc_key(metadata_enc_key, self._seal_kek, sealed_key_path)
        # Check if eval_mode_name is "MM" and ensure EvalKey.bin exists
        if self._context_param.eval_mode_name == "MM":
            eval_key_path = Path(self.key_path) / "EvalKey.bin"
            if not eval_key_path.exists():
                # Create a dummy 1-byte EvalKey.bin file
                with open(eval_key_path, "wb") as f:
                    f.write(b"\x00")
        # Create metadata JSON
        metadata = {
            "preset": self._context_param.preset_name,
            "eval_mode": self._context_param.eval_mode_name,
            "seal_mode": self._key_param.seal_mode_name,
            "dim_list": self._dim_list,
            "metadata_encryption": self._key_param.metadata_encryption,
        }

        metadata_path = Path(self._key_param.key_dir) / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=4)
        return self

    # def generate_secret_key(self):
    # 	# This function generates secret key only
    # 	# When if user generated secret key, return it
    # 	return self.key_generator.generateSecKey()

    # def generate_public_keys(self):
    # 	# This function generates public keys only
    # 	# This function cannot be called before secret key has been generated
    # 	self.key_generator.generatePublicKey(self.key_dir + "SecKey.bin")
    # 	# TODO) Public key generation with secret key that has loaded to memory space
    # 	# Like, self.key_generator.generate_pub_key(enVector.FRSecKey)
