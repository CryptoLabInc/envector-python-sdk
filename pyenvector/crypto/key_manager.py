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
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

import evi

from pyenvector.crypto.context import Context
from pyenvector.crypto.parameter import ContextParameter, KeyParameter

from ..utils.aes import generate_aes256_key
from ..utils.utils import (
    _decode_blob,
    _encode_blob,
    _extract_v2_sealed_bytes,
    _get_seal_info,
    _metadata_bytes_to_serializable,
    _metadata_serializable_to_bytes,
    is_empty_dir,
)

UTC = timezone.utc

# *********************************************************************
# * Key generation module for the pyenvector/enVector workflow (CCMM)
# * Plans for now:
#     1. Make pybind11 wrapper of EVI (DONE)
#     2. Keygen class just need to call pybind11 wrapped code + a (WIP)
# *********************************************************************

###################################
# KeyGenerator Class
###################################


class KeyManager:
    _km = evi.KeyManager()

    def __init__(
        self,
        key_id=None,
        key_store=None,
        region_name=None,
        bucket_name=None,
        secret_prefix=None,
        vault_addr=None,
        vault_mount=None,
    ):
        """
        Initialize a KeyManager instance for wrapping and unwrapping cryptographic keys.

        Args:
            key_id (Optional): Identifier for the key to be used in wrapping/unwrapping operations.
                This allows the KeyManager to select the appropriate key for secure key management tasks.

        The KeyManager class provides methods to wrap (encrypt) and unwrap (decrypt) keys,
        facilitating secure storage and transfer of cryptographic material.
        """
        self.key_id = key_id
        self.key_store = key_store
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.secret_prefix = secret_prefix
        self.vault_addr = vault_addr
        self.vault_mount = vault_mount
        self._init_client()

    def _init_client(self):
        if self.key_store == "aws":
            from pyenvector.utils import AWSClient

            self.client = AWSClient(self.region_name, s3_bucket=self.bucket_name, secret_prefix=self.secret_prefix)
        elif self.key_store == "gcp":
            from pyenvector.utils import GCPClient

            self.client = GCPClient(bucket_name=self.bucket_name, secret_prefix=self.secret_prefix)
        elif self.key_store == "vault":
            from pyenvector.utils import VaultClient

            self.client = VaultClient(
                vault_addr=self.vault_addr,
                vault_mount=self.vault_mount,
                secret_prefix=self.secret_prefix,
            )
        else:
            self.client = None

    @staticmethod
    def save_wrapped_key(key_stream, key_path):
        """Persist wrapped key data to a JSON file."""
        json_path = Path(key_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        serializable = _encode_blob(key_stream)
        with open(json_path, "w") as f:
            json.dump(serializable, f, indent=4)

    @staticmethod
    def load_wrapped_key(key_path):
        with open(Path(key_path), "r") as f:
            data = json.load(f)
        return _decode_blob(data)

    def sec_bin_to_json(self, bin_path, json_path, seal_info: Optional[evi.SealInfo] = None):
        if os.path.exists(bin_path):
            if seal_info is None:
                KeyManager._km.wrap_sec_key(self.key_id, bin_path, json_path)
            else:
                KeyManager._km.wrap_sec_key(self.key_id, bin_path, json_path, seal_info)
            os.remove(bin_path)

    def enc_bin_to_json(self, bin_path, json_path):
        if os.path.exists(bin_path):
            KeyManager._km.wrap_enc_key(self.key_id, bin_path, json_path)
            os.remove(bin_path)

    def eval_bin_to_json(self, bin_path, json_path):
        if os.path.exists(bin_path):
            KeyManager._km.wrap_eval_key(self.key_id, bin_path, json_path)
            os.remove(bin_path)

    def wrap_key_stream(self, key_dict, key_id, seal_info: Optional[evi.SealInfo] = None):
        wrapped_sec = self.wrap_sec_key_bytes(key_dict["sec_blob"], key_id, seal_info=seal_info)
        wrapped_enc = KeyManager._km.wrap_enc_key_bytes(key_id, key_dict["enc_blob"])
        wrapped_eval = KeyManager._km.wrap_eval_key_bytes(key_id, key_dict["eval_blob"])
        res_dict = {"sec_blob": wrapped_sec, "enc_blob": wrapped_enc, "eval_blob": wrapped_eval}
        metadata_blob = key_dict.get("metadata_blob")
        if metadata_blob is not None:
            res_dict["metadata_blob"] = self.wrap_metadata_key_bytes(metadata_blob, key_id, seal_info=seal_info)
        return res_dict

    def wrap_sec_key_bytes(self, sec_key_bytes: bytes, key_id: str, seal_info: Optional[evi.SealInfo] = None):
        if seal_info is None:
            wrapped_sec = KeyManager._km.wrap_sec_key_bytes(key_id, sec_key_bytes)
        else:
            wrapped_sec = KeyManager._km.wrap_sec_key_bytes(key_id, sec_key_bytes, seal_info)
        return wrapped_sec

    def wrap_enc_key_bytes(self, enc_key_bytes: bytes, key_id: str):
        wrapped_enc = KeyManager._km.wrap_enc_key_bytes(key_id, enc_key_bytes)
        return wrapped_enc

    def wrap_eval_key_bytes(self, eval_key_bytes: bytes, key_id: str):
        wrapped_eval = KeyManager._km.wrap_eval_key_bytes(key_id, eval_key_bytes)
        return wrapped_eval

    def wrap_metadata_key_bytes(
        self,
        metadata_key_bytes: bytes,
        key_id: str,
        *,
        is_sealed: bool = False,
        seal_info: Optional[evi.SealInfo] = None,
    ):
        if isinstance(metadata_key_bytes, (dict, list, str)):
            metadata_key_bytes = _metadata_serializable_to_bytes(metadata_key_bytes)

        if seal_info is not None:
            return KeyManager._km.wrap_metadata_key_bytes(key_id, metadata_key_bytes, seal_info)

        if not is_sealed:
            return KeyManager._km.wrap_metadata_key_bytes(key_id, metadata_key_bytes)

        # Backward compatibility: keep legacy v0 envelope for pre-sealed metadata blobs.
        metadata_obj = _metadata_bytes_to_serializable(metadata_key_bytes)

        payload = {
            "metadata_blob": metadata_obj,
            "key_id": key_id,
            "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def unwrap_enc_key_bytes(self, wrapped_enc_key: bytes):
        return KeyManager._km.unwrap_enc_key_bytes(wrapped_enc_key)

    def unwrap_eval_key_bytes(self, wrapped_eval_key: bytes):
        return KeyManager._km.unwrap_eval_key_bytes(wrapped_eval_key)

    def unwrap_sec_key_bytes(self, wrapped_sec_key: bytes, seal_info: Optional[evi.SealInfo] = None):
        if seal_info is None:
            sec_blob = KeyManager._km.unwrap_sec_key_bytes(wrapped_sec_key)
        else:
            sec_blob = KeyManager._km.unwrap_sec_key_bytes(wrapped_sec_key, seal_info)
        return sec_blob

    def unwrap_metadata_key_bytes(
        self, wrapped_metadata_key: Union[bytes, dict, str], seal_info: Optional[evi.SealInfo] = None
    ):
        payload = wrapped_metadata_key
        if isinstance(payload, dict):
            raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        elif isinstance(payload, str):
            raw_bytes = payload.encode("utf-8")
        else:
            raw_bytes = bytes(payload)

        try:
            if seal_info is None:
                return KeyManager._km.unwrap_metadata_key_bytes(raw_bytes)
            return KeyManager._km.unwrap_metadata_key_bytes(raw_bytes, seal_info)
        except Exception:
            pass

        # Backward compatibility: parse legacy pyenvector v0/v2 metadata payloads when native unwrap fails.
        if isinstance(payload, bytes):
            try:
                payload = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        elif isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
        # TODO(next update): Legacy compatibility path for old metadata payload format.
        # Remove this fallback once all persisted metadata keys use the new envelope format.
        if isinstance(payload, dict):
            fmt = payload.get("format")
            if fmt == "sealed-key-v2":
                return _extract_v2_sealed_bytes(payload)
            if fmt is not None:
                # Unknown format value -> fail-closed (spec §4.2)
                raise ValueError(f"Unknown sealed-key format: {fmt!r}")
            serialized = payload.get("metadata_blob", payload)
        else:
            serialized = payload
        return _metadata_serializable_to_bytes(serialized)

    def unwrap_key_stream(self, wrapped_key_dict: dict, seal_info: Optional[evi.SealInfo] = None):
        sec_blob = self.unwrap_sec_key_bytes(wrapped_key_dict["sec_blob"], seal_info=seal_info)
        enc_blob = KeyManager._km.unwrap_enc_key_bytes(wrapped_key_dict["enc_blob"])
        eval_blob = KeyManager._km.unwrap_eval_key_bytes(wrapped_key_dict["eval_blob"])
        res_dict = {"sec_blob": sec_blob, "enc_blob": enc_blob, "eval_blob": eval_blob}
        metadata_payload = wrapped_key_dict.get("metadata_blob")
        if metadata_payload is not None:
            metadata_blob = self.unwrap_metadata_key_bytes(metadata_payload, seal_info=seal_info)
            res_dict["metadata_blob"] = metadata_blob
        return res_dict

    def unwrap_key_json(self, json_path):
        with open(json_path, "rb") as f:
            raw_bytes = f.read()
        filename = Path(json_path).name
        if filename.endswith("SecKey.json"):
            return KeyManager._km.unwrap_sec_key_bytes(raw_bytes)
        elif filename.endswith("EncKey.json"):
            return KeyManager._km.unwrap_enc_key_bytes(raw_bytes)
        elif filename.endswith("EvalKey.json"):
            return KeyManager._km.unwrap_eval_key_bytes(raw_bytes)
        elif filename.endswith("MetadataKey.json"):
            return self.unwrap_metadata_key_bytes(raw_bytes)

        # Fallback for non-standard filenames (e.g., sec_blob.json from external stores).
        unwrap_candidates = (
            KeyManager._km.unwrap_sec_key_bytes,
            KeyManager._km.unwrap_enc_key_bytes,
            KeyManager._km.unwrap_eval_key_bytes,
        )
        for unwrap in unwrap_candidates:
            try:
                return unwrap(raw_bytes)
            except Exception:
                continue

        try:
            return self.unwrap_metadata_key_bytes(raw_bytes)
        except Exception as exc:
            raise ValueError(f"unsupported key payload: {json_path}") from exc

    def get_key_stream(self, key_path: str) -> bytes:
        """
        Reads and returns the bytes of the key file at the specified path.

        Args:
            key_path (str): The path to the key file.
        Returns:
            bytes: The bytes of the key file.
        """
        if isinstance(key_path, str):
            if not key_path.endswith(".json"):
                import ast

                key_bytes = ast.literal_eval(key_path)
            else:
                key_bytes = self.unwrap_key_json(key_path)
        elif isinstance(key_path, bytes):
            key_bytes = key_path
        else:
            raise TypeError("key_path must be a file path (str) or bytes")
        return key_bytes

    def save(self, key_dict):
        if self.key_store in ["aws", "gcp", "vault"]:
            self.save_to_remote(key_dict)
            return
        raise ValueError("Remote key store is not configured.")

    def load(self, key_type: Optional[Union[str, List[str]]] = None):
        if self.key_store in ["aws", "gcp", "vault"]:
            key_dict = self.load_from_remote(key_type=key_type)
            return key_dict
        raise ValueError("Remote key store is not configured.")

    def delete(self, key_id=None):
        if key_id is None:
            key_id = self.key_id
        if self.key_store in ["aws", "gcp", "vault"]:
            if self.client is None:
                raise ValueError("Remote key client is not initialized.")
            self.client.delete_all_keys(key_id)
            return
        raise ValueError("Remote key store is not configured.")

    def verify_key_id(self, key_id=None):
        if key_id is None:
            key_id = self.key_id
        if self.client:
            return self.client.verify_key_id(key_id)
        return True

    def save_to_remote(self, key_dict):
        if self.client:
            if self.verify_key_id(self.key_id):
                raise ValueError(f"Cannot store key '{self.key_id}' because remote blobs already exist.")
            payload = dict(key_dict)
            metadata_blob = payload.get("metadata_blob")
            if metadata_blob is not None:
                metadata_payload = self.wrap_metadata_key_bytes(metadata_blob, self.key_id)
                payload["metadata_blob"] = metadata_payload
            self.client.store_key_dict(payload, self.key_id)
        else:
            raise ValueError("Remote key client is not initialized.")

    def load_from_remote(self, key_type: Optional[Union[str, List[str]]] = None):
        if self.client:
            return self.client.load_key_dict(self.key_id, key_type=key_type)
        else:
            raise ValueError("Remote key client is not initialized.")


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
        The parameter preset to use for the context. Defaults to "ip1".
    seal_info : SealInfo, optional
        The seal information for the keys. Defaults to "SealMode.NONE".
    eval_mode : str, optional
        The evaluation mode for the context. Defaults to "MM".
    metadata_encryption: bool, optional
        Whether to enable metadata encryption. Defaults to None.

    Example
    --------
    >>> keygen = KeyGenerator("./keys")
    >>> keygen.generate_keys()
    """

    def __init__(
        self,
        key_path: Optional[str] = None,
        key_id: Optional[str] = None,
        dim_list: Optional[Union[int, List[int]]] = None,
        preset: Optional[str] = "ip2",
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        seal_kek: Optional[Union[bytes, str]] = None,
        eval_mode: Optional[str] = "MM32",
        metadata_encryption: Optional[bool] = None,
    ):
        if key_path is None:
            if key_id is None:
                raise ValueError("key id required")
            key_path = tempfile.mkdtemp(prefix="envector_keys_")

        key_dir = key_path
        # Ensure the key path exists, create directories if necessary
        _key_path = Path(key_path).expanduser().resolve()
        _key_path.mkdir(parents=True, exist_ok=True)
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
            key_path=key_dir, seal_mode=seal_mode, seal_kek=seal_kek, metadata_encryption=metadata_encryption
        )
        self._key_generator = evi.MultiKeyGenerator(context_list, key_dir, self.sInfo)
        self._context_param = ContextParameter(preset, eval_mode=eval_mode)
        self._key_param = key_param
        self._dim_list = dim_list
        self.key_path = key_path
        self.key_dir = key_dir
        self.key_id = key_id if key_id is not None else key_dir
        self._km = KeyManager(key_id=self.key_id)

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
            key_param.key_id,
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

    def _wrap_stream_payloads(self, wrapped_dict: dict) -> dict:
        """Convert wrapped key bytes into JSON dictionaries for serialization-free transport."""
        decoded = {}
        for name, payload in wrapped_dict.items():
            if isinstance(payload, (bytes, bytearray)):
                try:
                    decoded[name] = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    decoded[name] = payload
            else:
                decoded[name] = payload
        return decoded

    def generate_keys_stream(self):
        """
        Generate keys and return wrapped payloads matching on-disk JSON format.

        Returns
        -------
        dict
            Dictionary with ``sec_blob``, ``enc_blob``, ``eval_blob`` (and optionally ``metadata_blob``)
            containing wrapped payload dictionaries.
        """
        key_dict = self._generate_keys_stream()
        wrapped_dict = self._km.wrap_key_stream(key_dict, self.key_id)
        return self._wrap_stream_payloads(wrapped_dict)

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
        # Check if the directory is empty
        if not is_empty_dir(self.key_dir):
            raise ValueError(f"Key path '{self.key_dir}' is not empty. Key generation canceled.")

        # Generate keys
        self._key_generator.generate_keys()
        if self._key_param.metadata_encryption:
            # Generate metadata encryption key
            sealing_active = self._key_param.seal_info.mode != evi.SealMode.NONE
            metadata_enc_key = generate_aes256_key(self._key_param.metadata_key_path, False)
            if sealing_active:
                wrapped_metadata = self._km.wrap_metadata_key_bytes(
                    metadata_enc_key,
                    self.key_id,
                    seal_info=self.sInfo,
                )
            else:
                wrapped_metadata = self._km.wrap_metadata_key_bytes(metadata_enc_key, self.key_id)
            self._km.save_wrapped_key(wrapped_metadata, self._key_param.metadata_key_path)
        # Check if eval_mode_name is "MM" and ensure EvalKey.bin exists
        if self._context_param.eval_mode_name == "MM":
            eval_key_path = Path(self.key_dir) / "EvalKey.bin"
            if not eval_key_path.exists():
                # Create a dummy 1-byte EvalKey.bin file
                with open(eval_key_path, "wb") as f:
                    f.write(b"\x00")
        self._km.sec_bin_to_json(self._key_param.sec_key_bin_path, self._key_param.sec_key_path)
        self._km.enc_bin_to_json(self._key_param.enc_key_bin_path, self._key_param.enc_key_path)
        self._km.eval_bin_to_json(self._key_param.eval_key_bin_path, self._key_param.eval_key_path)

        return self

    def _generate_keys_stream(self):
        """
        Generate all keys including encryption, evaluation, and secret keys.

        Parameters
        ----------
        None

        Returns
        -------
        KeyGenerator: The KeyGenerator instance with generated keys.
        """
        # Generate keys
        _, sec_blob, enc_blob, eval_blob = self._key_generator.generate_keys_per_stream()
        res_dict = {"sec_blob": sec_blob, "enc_blob": enc_blob, "eval_blob": eval_blob}
        if self._key_param.metadata_encryption:
            # Generate metadata encryption key
            sealing = self._key_param.seal_info.mode != evi.SealMode.NONE
            if sealing:
                raise ValueError("Sealing is not supported in stream key generation.")
            metadata_enc_key = generate_aes256_key(self._key_param.metadata_key_path, False)
            res_dict["metadata_blob"] = metadata_enc_key
        return res_dict

    # def save_key_json(self, key_dict: dict, key_dir: str):
    #     save_wrapped_key(key_dict["sec_blob"], key_dir + "/" + "SecKey.json")
    #     save_wrapped_key(key_dict["enc_blob"], key_dir + "/" + "EncKey.json")
    #     save_wrapped_key(key_dict["eval_blob"], key_dir + "/" + "EvalKey.json")
    #     metadata_blob = key_dict.get("metadata_blob")
    #     if metadata_blob is not None:
    #         save_wrapped_key(key_dict["metadata_blob"], key_dir + "/" + "MetadataKey.json")
    #     return
