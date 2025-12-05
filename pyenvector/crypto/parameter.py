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

import os
import site
from typing import Dict, List, Optional, Union

import evi

from ..utils import utils
from ..utils.utils import _get_seal_info

SealInfo = evi.SealInfo
SealMode = evi.SealMode


def check_libheaan_exists():
    site_paths = site.getsitepackages()
    found = False
    for sp in site_paths:
        lib_dir = os.path.join(sp, "evi", "lib")
        lib_candidates = [
            os.path.join(lib_dir, "libHEaaN.so"),
            os.path.join(lib_dir, "libHEaaN.dylib"),
        ]
        for lib in lib_candidates:
            if os.path.exists(lib):
                found = True
                break
        if found:
            break
    return found


PARAMETER_PRESET: List[str] = [
    "IP",
    "IP0",
    # "QF",
    # "QF0",
    # "QF1",
    # "QF2",
    # "QF3",
]

EVAL_MODE: List[str] = [
    # "FLAT",
    # "MS",
    "RMP",
    # "RMS",
    "MM",
]

DEVICE_TYPE: List[str] = [
    "CPU",
]

ENCODING_TYPE: List[str] = [
    "ITEM",
    "QUERY",
]

SEAL_MODE: List[str] = [
    "NONE",
    "AES_KEK",
]

INDEX_TYPE: List[str] = [
    "FLAT",
    "IVF_FLAT",
]


class ContextParameter:
    """
    ContextParameter class for handling encryption and decryption parameters.

    Attributes:
        preset (evi.ParameterPreset): The preset configuration for the index.
        preset_name (str): The name of the preset.
        eval_mode (evi.EvalMode): The evaluation mode for the index.
        eval_mode_name (str): The name of the evaluation mode.
        device_type (evi.DeviceType): The device type for the index.
        device_type_name (str): The name of the device type.

    Methods:
        __init__(preset, dim, key_path): Initializes the ContextParameter with preset, dimension, and key path.
    """

    def __init__(
        self,
        preset: Optional[Union[str, evi.ParameterPreset]] = None,
        dim: Optional[int] = None,
        eval_mode: Optional[Union[str, evi.EvalMode]] = None,
        device_type: Optional[Union[str, evi.DeviceType]] = None,
    ):
        """
        Initializes the ContextParameter class.
        """
        self.preset = preset
        self.dim = dim
        self.eval_mode = eval_mode
        self.device_type = device_type

    def __repr__(self):
        """
        Returns a string representation of the ContextParameter object.
        """
        return (
            "ContextParameter(\n"
            f"  preset={self.preset_name},\n"
            f"  dim={self.dim},\n"
            f"  eval_mode={self.eval_mode_name},\n"
            f"  search_type={self.search_type}\n"
            ")"
        )

    @property
    def preset(self):
        if self._preset is None:
            raise ValueError("Preset is not set. Please set the preset using set_preset method.")
        return self._preset

    @preset.setter
    def preset(self, preset: Optional[Union[str, evi.ParameterPreset]] = None):
        """
        Sets the preset configuration for the index.
        Args:
            preset (str): The preset configuration for the index.
        Raises:
            ValueError: If the preset is unsupported.
        """
        if preset is None:
            preset = "ip"
        if isinstance(preset, str):
            preset_upper = preset.upper()
            if preset_upper not in PARAMETER_PRESET:
                raise ValueError(f"Unsupported preset: {preset}. Supported presets are: {', '.join(PARAMETER_PRESET)}")

            if preset_upper.startswith("IP"):
                if preset_upper == "IP":
                    preset_upper = "IP0"

            elif preset_upper.startswith("QF"):
                if not check_libheaan_exists():
                    raise ValueError("QF parameter is not allowed without libHEaaN.")
                if preset_upper == "QF":
                    preset_upper = "QF0"
            else:
                raise ValueError(f"Unsupported preset: {preset}")
            self._preset = getattr(evi.ParameterPreset, preset_upper)
        else:
            if preset.name.startswith("QF"):
                if not check_libheaan_exists():
                    raise ValueError("QF parameter is not allowed without libHEaaN.")
            self._preset = preset  # Assume preset is already an evi.ParameterPreset instance

    @property
    def preset_name(self):
        """
        Returns the name of the preset.
        Returns:
            str: The name of the preset.
        """
        return self.preset.name

    @property
    def eval_mode(self):
        if self._eval_mode is None:
            raise ValueError("Eval mode is not set. Please set the eval mode using set_eval_mode method.")
        return self._eval_mode

    @eval_mode.setter
    def eval_mode(self, mode: Optional[Union[str, evi.EvalMode]] = "RMP"):
        """
        Sets the evaluation mode for the index.
        Args:
            mode (str): The evaluation mode for the index.
        Raises:
            ValueError: If the evaluation mode is unsupported.
        """
        if mode is None:
            mode = "RMP"  # Default to RMP if not provided
        if isinstance(mode, str):
            mode_upper = mode.upper()
            if mode_upper not in EVAL_MODE:
                raise ValueError(f"Unsupported eval mode: {mode}. Supported modes are: {', '.join(EVAL_MODE)}")
            self._eval_mode = getattr(evi.EvalMode, mode_upper)
        else:
            self._eval_mode = mode

    @property
    def eval_mode_name(self):
        """
        Returns the name of the evaluation mode.
        Returns:
            str: The name of the evaluation mode.
        """
        return self.eval_mode.name

    @property
    def device_type(self):
        """
        Returns the device type for the index.
        Returns:
            str: The device type, either "CPU" or "GPU".
        """
        return self._device_type

    @device_type.setter
    def device_type(self, device_type: Optional[Union[str, evi.DeviceType]] = None):
        """
        Sets the device type for the index.
        Args:
            device_type (str): The device type, either "CPU" or "GPU".
        Raises:
            ValueError: If the device type is unsupported.
        """
        if device_type is None:
            device_type = "CPU"  # Default to CPU if not provided
        if isinstance(device_type, str):
            device_type_upper = device_type.upper()
            if device_type_upper not in DEVICE_TYPE:
                raise ValueError(
                    f"Unsupported device type: {device_type}. Supported types are: {', '.join(DEVICE_TYPE)}"
                )
            self._device_type = getattr(evi.DeviceType, device_type_upper)
        else:
            self._device_type = device_type

    @property
    def device_type_name(self):
        """
        Returns the name of the device type.
        Returns:
            str: The name of the device type, either "CPU" or "GPU".
        """
        return self.device_type.name

    @property
    def dim(self):
        """
        Returns the dimension of the context.
        Returns:
            int: The dimension of the context.
        """
        return self._dim

    @dim.setter
    def dim(self, dim: Optional[int]):
        """
        Sets the dimension of the context.
        Args:
            dim (int): The dimension of the context, which should be a power of 2 (e.g., 32, 64, ..., 4096).
        Raises:
            ValueError: If the dimension is not a power of 2 or not within the range [32, 4096].
        """
        if dim is not None and (dim < 32 or dim > 4096):
            raise ValueError("Dimension must be a power of 2 within the range [32, 4096].")
        self._dim = dim

    @property
    def is_ip(self):
        """
        Checks if the preset is IP or IP0.
        Returns:
            bool: True if the preset is IP or IP0, False otherwise.
        """
        return self.preset.name.startswith("IP")

    @property
    def is_qf(self):
        """
        Checks if the preset is QF or any of its variants.
        Returns:
            bool: True if the preset is QF or any of its variants, False otherwise.
        """
        return self.preset.name.startswith("QF")

    @property
    def search_type(self):
        """
        Returns the search type based on the preset.
        Returns:
            str: The search type, either "IP" or "QF".
        """
        if self.is_ip:
            return "IP"
        elif self.is_qf:
            return "QF"
        else:
            raise ValueError("Unsupported preset for search type.")


class EncodingType:
    """
    EncodingType class for handling encoding types.

    Attributes:
        ITEM (evi.EncodeType): Encoding type for item vectors.
        QUERY (evi.EncodeType): Encoding type for query vectors.
    """

    def __init__(self, encoding_type: Union[str, evi.EncodeType]):
        """
        Initializes the EncodingType class.

        Args:
            encoding_type (str or evi.EncodeType): The encoding type to be set.
        """
        self.encoding_type = encoding_type

    @property
    def encoding_type(self):
        """
        Returns the encoding type.
        Returns:
            evi.EncodeType: The encoding type.
        """
        if self._encoding_type is None:
            raise ValueError("Encoding type is not set. Please set the encoding type using set_encoding_type method.")
        return self._encoding_type

    @encoding_type.setter
    def encoding_type(self, encoding_type: Union[str, evi.EncodeType]):
        """
        Sets the encoding type.
        Args:
            encoding_type (str or evi.EncodeType): The encoding type to be set.
        Raises:
            ValueError: If the encoding type is unsupported.
        """
        if isinstance(encoding_type, str):
            encoding_type_upper = encoding_type.upper()
            if encoding_type_upper not in ENCODING_TYPE:
                raise ValueError(
                    f"Unsupported encoding type: {encoding_type}. Supported types are: {', '.join(ENCODING_TYPE)}"
                )
            self._encoding_type = getattr(evi.EncodeType, encoding_type_upper)
        else:
            self._encoding_type = encoding_type

    @property
    def encoding_type_name(self):
        """
        Returns the name of the encoding type.
        Returns:
            str: The name of the encoding type, either "ITEM" or "QUERY".
        """
        return self.encoding_type.name

    @property
    def is_item(self):
        """
        Checks if the encoding type is ITEM.
        Returns:
            bool: True if the encoding type is ITEM, False otherwise.
        """
        return self.encoding_type.name == "ITEM"

    @property
    def is_query(self):
        """
        Checks if the encoding type is QUERY.
        Returns:
            bool: True if the encoding type is QUERY, False otherwise.
        """
        return self.encoding_type.name == "QUERY"


class IndexParameter:
    """
    CipherEncryptionType class for handling encryption types.

    Attributes:
        index_encryption: (str): Indicates if the encryption type is for database, e.g. "plain", "cipher", "hybrid".
        query_encryption: (str): Indicates if the encryption type is for query, e.g. "plain", "cipher", "hybrid".
    """

    def __init__(
        self,
        index_encryption: Optional[str] = None,
        query_encryption: Optional[str] = None,
        index_params: Optional[Dict] = None,
    ):
        """
        Initializes the CipherEncryptionType class.

        Args:
            index_encryption (str): Indicates if the encryption type is for database, e.g. "plain", "cipher", "hybrid".
            query_encryption (str): Indicates if the encryption type is for query, e.g. "plain", "cipher", "hybrid".
            index_params (dict, optional): Additional parameters for the index such as ``index_type``,
                ``nlist`` and ``default_nprobe``.
        """
        self.index_encryption = index_encryption
        self.query_encryption = query_encryption
        if index_encryption is False:
            # CP and PP are not allowed
            raise ValueError("Searching plain DB is not supported")
        self.index_params = index_params

    @property
    def index_encryption(self):
        """
        Returns whether the encryption type is for database.
        Returns:
            str: The encryption type for database, e.g. "plain", "cipher", "hybrid".
        """
        if self._index_encryption is None:
            raise ValueError(
                "Database encryption type is not set. "
                "Please set the index_encryption using set_index_encryption method."
            )
        return self._index_encryption

    @index_encryption.setter
    def index_encryption(self, index_encryption: str):
        """
        Sets whether the encryption type is for database.
        Args:
            index_encryption (str): The encryption type for database, e.g. "plain", "cipher", "hybrid".
        """
        if index_encryption is None:
            index_encryption = "cipher"

        index_encryption_lower = index_encryption.lower()
        if index_encryption_lower not in ["plain", "cipher", "hybrid"]:
            raise ValueError(
                f"Unsupported index encryption type: {index_encryption}. Supported types are: plain, cipher, hybrid."
            )
        self._index_encryption = index_encryption_lower

    @property
    def query_encryption(self):
        """
        Returns whether the encryption type is for query.
        Returns:
            str: The encryption type for query, e.g. "plain", "cipher", "hybrid".
        """
        if self._query_encryption is None:
            raise ValueError(
                "Query encryption type is not set. Please set the query_encryption using set_query_encryption method."
            )
        return self._query_encryption

    @query_encryption.setter
    def query_encryption(self, query_encryption: str):
        """
        Sets whether the encryption type is for query.
        Args:
            query_encryption (bool): True if the encryption type is for query, False otherwise.
        """
        if query_encryption is None:
            query_encryption = "plain"
        query_encryption_lower = query_encryption.lower()
        if query_encryption_lower not in ["plain", "cipher", "hybrid"]:
            raise ValueError(
                f"Unsupported query encryption type: {query_encryption}. Supported types are: plain, cipher, hybrid."
            )
        self._query_encryption = query_encryption_lower

    @property
    def index_type(self):
        """
        Returns the index type.
        Returns:
            str: The index type, e.g., "FLAT", "IVF_FLAT", etc.
        """
        if self.index_params is None:
            raise ValueError("Index type is not set. Please set the index type using set_index_type method.")
        return self.index_params["index_type"]

    @property
    def nlist(self):
        """
        Returns the nlist parameter for IVF_FLAT index type.
        Returns:
            int: The nlist parameter for IVF_FLAT index type.
        """
        if self.index_type != "IVF_FLAT":
            raise ValueError("nlist is only applicable for IVF_FLAT index type.")
        if "nlist" not in self.index_params:
            raise ValueError("nlist is not set. Please set the nlist parameter for IVF_FLAT index type.")
        return self.index_params["nlist"]

    @nlist.setter
    def nlist(self, nlist):
        if self.index_type != "IVF_FLAT":
            raise ValueError("nlist is only applicable for IVF_FLAT index type.")
        self.index_params["nlist"] = nlist

    @property
    def default_nprobe(self):
        """
        Returns the default_nprobe parameter for IVF_FLAT index type.
        Returns:
            int: The default_nprobe parameter for IVF_FLAT index type.
        """
        if self.index_type != "IVF_FLAT":
            raise ValueError("default_nprobe is only applicable for IVF_FLAT index type.")
        if "default_nprobe" not in self.index_params:
            raise ValueError(
                "default_nprobe is not set. Please set the default_nprobe parameter for IVF_FLAT index type."
            )
        return self.index_params["default_nprobe"]

    @default_nprobe.setter
    def default_nprobe(self, nprobe):
        if self.index_type != "IVF_FLAT":
            raise ValueError("default_nprobe is only applicable for IVF_FLAT index type.")
        self.index_params["default_nprobe"] = nprobe

    @property
    def centroids(self):
        """
        Returns the centroids for IVF_FLAT index type.
        Returns:
            np.ndarray: The centroids for IVF_FLAT index type.
        """
        if self.index_type != "IVF_FLAT":
            raise ValueError("centroids is only applicable for IVF_FLAT index type.")
        if "centroids" not in self.index_params:
            raise ValueError("centroids is not set. Please set the centroids parameter for IVF_FLAT index type.")
        return self.index_params["centroids"]

    @centroids.setter
    def centroids(self, centroids):
        if self.index_type != "IVF_FLAT":
            raise ValueError("centroids is only applicable for IVF_FLAT index type.")
        self.index_params["centroids"] = centroids

    @property
    def index_params(self):
        """
        Returns the additional parameters for the index.
        Returns:
            dict: The additional parameters for the index.
        """
        if getattr(self, "_index_params", None) is None:
            self._index_params = {"index_type": "FLAT"}
        return self._index_params

    @index_params.setter
    def index_params(self, index_params: Optional[dict]):
        """
        Sets the additional parameters for the index.
        Args:
            index_params (dict): The additional parameters for the index.
        """
        if not index_params:
            self._index_params = {"index_type": "FLAT"}
            return self._index_params

        index_params["index_type"] = index_params["index_type"].upper()
        if index_params["index_type"] not in INDEX_TYPE:
            raise ValueError(
                f"Unsupported index type: {index_params['index_type']}. Supported types are: {', '.join(INDEX_TYPE)}"
            )

        if index_params["index_type"] == "IVF_FLAT":
            if "nlist" not in index_params:
                default_nlist = self.index_params.get("nlist", 4096)
                index_params["nlist"] = default_nlist
            if "default_nprobe" not in index_params:
                default_nprobe = self.index_params.get("default_nprobe", 1)
                index_params["default_nprobe"] = default_nprobe
        self._index_params = index_params
        return self._index_params

    def __repr__(self):
        """
        Returns a string representation of the IndexParameter object.
        """
        return (
            "IndexParameter(\n"
            f"  index_encryption={self.index_encryption},\n"
            f"  query_encryption={self.query_encryption},\n"
            f"  index_type={self.index_type}, \n"
            f"  index_params={self.index_params}\n"
            ")"
        )


class KeyParameter:
    """
    KeyParameter class for handling key parameters.

    Attributes:
        key_path (str): The file path to the secret key.
        key_id (str): The ID of the secret key.
    """

    def __init__(
        self,
        key_path: Optional[str] = None,
        key_id: Optional[str] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[Union[bytes, str]] = None,
        seal_kek: Optional[Union[bytes, str]] = None,
        metadata_encryption: Optional[bool] = None,
        use_key_stream: Optional[bool] = False,
        enc_key: Optional[Union[bytes, str]] = None,
        eval_key: Optional[Union[bytes, str]] = None,
        sec_key: Optional[Union[bytes, str]] = None,
        metadata_key: Optional[Union[bytes, str]] = None,
        key_store: Optional[str] = None,
        region_name: Optional[str] = None,
        bucket_name: Optional[str] = None,
        secret_prefix: Optional[str] = None,
    ):
        """
        Initializes the KeyParameter class.

        Args:
            key_path (str, optional): The base directory where key material is stored.
            key_id (str, optional): Identifier used to locate on-disk keys.
            seal_mode (str, optional): Seal mode name accepted by ``evi.SealMode``.
            seal_kek_path (str or bytes, optional): Path or raw bytes for the KEK used to unseal secret keys.
            seal_kek (str or bytes, optional): Explicit KEK bytes that override ``seal_kek_path``.
            metadata_encryption (bool, optional): Whether metadata encryption is enabled.
            use_key_stream (bool, optional): If True, expect in-memory key streams instead of files.
            enc_key (str or bytes, optional): Encryption key stream when ``use_key_stream`` is enabled.
            eval_key (str or bytes, optional): Evaluation key stream when ``use_key_stream`` is enabled.
            sec_key (str or bytes, optional): Secret key stream when ``use_key_stream`` is enabled.
            metadata_key (str or bytes, optional): Metadata key stream when ``use_key_stream`` is enabled.
            key_store (str, optional): External key storage provider (e.g., "aws").
            region_name (str, optional): External key store region (for AWS).
            bucket_name (str, optional): S3 bucket name for AWS key storage.
            secret_prefix (str, optional): Secrets Manager prefix for AWS key storage.
        """
        self.use_key_stream = use_key_stream
        self.key_path = key_path
        self.key_id = key_id
        self.seal_kek_path = seal_kek_path
        self.seal_kek = seal_kek_path if seal_kek_path and seal_kek is None else seal_kek
        self.seal_info = _get_seal_info(seal_mode, self.seal_kek)
        self.metadata_encryption = metadata_encryption
        self.enc_key_stream = enc_key
        self.eval_key_stream = eval_key
        self.sec_key_stream = sec_key
        self.metadata_key_stream = metadata_key
        self.key_store = key_store
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.secret_prefix = secret_prefix

    #     self._init_keys()

    # def _init_keys(self):
    #     if self.use_key_stream:
    #         self.enc_key = self.enc_key_stream
    #         self.eval_key = self.eval_key_stream
    #         self.sec_key = self.sec_key_stream
    #         self.metadata_key = self.metadata_key_stream
    #     else:
    #         self.enc_key = self.enc_key_path
    #         self.eval_key = self.eval_key_path
    #         self.sec_key = self.sec_key_path
    #         self.metadata_key = self.metadata_key_path

    @property
    def key_store(self):
        """
        Returns the key store type.
        Returns:
            str: The key store type.
        """
        return self._key_store

    @key_store.setter
    def key_store(self, key_store: Optional[str]):
        """
        Sets the key store type.
        Args:
            key_store (str): The key store type.
        """
        if key_store is None:
            key_store = None
        elif key_store == "aws":
            key_store = "aws"
        else:
            raise ValueError(f"Unsupported key store type: {key_store}. Supported types are: aws.")
        self._key_store = key_store

    @property
    def region_name(self):
        return getattr(self, "_region_name", None)

    @region_name.setter
    def region_name(self, region_name: Optional[str]):
        self._region_name = region_name

    @property
    def bucket_name(self):
        return getattr(self, "_bucket_name", None)

    @bucket_name.setter
    def bucket_name(self, bucket_name: Optional[str]):
        self._bucket_name = bucket_name

    @property
    def secret_prefix(self):
        return getattr(self, "_secret_prefix", None)

    @secret_prefix.setter
    def secret_prefix(self, secret_prefix: Optional[str]):
        self._secret_prefix = secret_prefix

    @property
    def key_path(self):
        """
        Returns the file path to the secret key.
        Returns:
            str: The file path to the secret key.
        """
        return self._key_path

    @key_path.setter
    def key_path(self, key_path: Optional[str]):
        """
        Sets the file path to the secret key.
        Args:
            key_path (str): The file path to the secret key.
        """
        if key_path is None:
            if self.use_key_stream:
                self._key_path = key_path
                return
            raise ValueError("Key path cannot be None. Please provide a valid key path.")
        if hasattr(self, "_key_path") and key_path != self._key_path:
            raise ValueError(
                f"Key path cannot be changed from {self._key_path} to {key_path}. "
                "Please create a Index Config instance with the new key path."
            )
        self._key_path = key_path

    @property
    def key_id(self):
        """
        Returns the ID of the secret key.
        Returns:
            str: The ID of the secret key.
        """
        return self._key_id

    @key_id.setter
    def key_id(self, key_id: Optional[str]):
        """
        Sets the ID of the secret key.
        Args:
            key_id (str): The ID of the secret key.
        """
        self._key_id = key_id

    @property
    def seal_info(self):
        """
        Returns the seal information.
        Returns:
            evi.SealInfo: The seal information.
        """
        return self._seal_info

    @seal_info.setter
    def seal_info(self, seal_info: Optional[evi.SealInfo]):
        """
        Sets the seal mode.
        Args:
            seal_info (SealInfo): The seal info to be set.
        Raises:
            ValueError: If the seal mode is unsupported.
        """
        if seal_info is None:
            seal_info = evi.SealInfo(evi.SealMode.NONE)
        self._seal_info = seal_info

    @property
    def seal_mode(self):
        """
        Returns the seal mode.
        Returns:
            SealMode: The seal mode.
        """
        return self.seal_info.mode

    @property
    def seal_kek_path(self):
        """
        Returns the KEK path.
        Returns:
            str: The KEK path.
        """
        return self._seal_kek_path

    @seal_kek_path.setter
    def seal_kek_path(self, seal_kek_path: Optional[str]):
        """
        Sets the KEK path.
        Args:
            seal_kek_path (str): The KEK path on disk.
        """
        self._seal_kek_path = seal_kek_path

    @property
    def seal_kek(self):
        """
        Returns the KEK path.
        Returns:
            str: The KEK path.
        """
        return self._seal_kek

    @seal_kek.setter
    def seal_kek(self, seal_kek: Optional[str]):
        """
        Sets the KEK path.
        Args:
            seal_kek (str): The KEK path.
        """
        self._seal_kek = seal_kek

    @property
    def seal_mode_name(self):
        """
        Returns the name of the seal mode.
        Returns:
            str: The name of the seal mode, either "NONE" or "AES_KEK".
        """
        return self.seal_info.mode.name

    @property
    def metadata_encryption(self):
        """
        Returns whether metadata encryption is enabled.
        Returns:
            bool: True if metadata encryption is enabled, False otherwise.
        """
        return self._metadata_encryption

    @metadata_encryption.setter
    def metadata_encryption(self, metadata_encryption: Optional[bool]):
        """
        Sets whether metadata encryption is enabled.
        Args:
            metadata_encryption (bool): True if metadata encryption is enabled, False otherwise.
        """
        if metadata_encryption is None:
            metadata_encryption = True
        self._metadata_encryption = metadata_encryption

    @property
    def metadata_key_path(self):
        """
        Returns whether metadata encryption key is used.
        Returns:
            bool: True if metadata encryption key is used, False otherwise.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/MetadataKey.json"

    @property
    def metadata_key_bin_path(self):
        """
        Returns whether metadata encryption key is used.
        Returns:
            bool: True if metadata encryption key is used, False otherwise.
        """
        if self.key_dir is None:
            return None
        if self.seal_info.mode == evi.SealMode.AES_KEK:
            return self.key_dir + "/MetadataKey_sealed.bin"
        elif self.seal_info.mode == evi.SealMode.NONE:
            return self.key_dir + "/MetadataKey.bin"

    @property
    def metadata_enc_key_path(self):
        """
        Backward compatible alias for metadata_key_path.

        Returns:
            str: Path to the metadata encryption key (sealed or plain).
        """
        return self.metadata_key_path

    @property
    def eval_key_path(self):
        """
        Returns the file path to the evaluation key.
        Returns:
            str: The file path to the evaluation key.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/EvalKey.json"

    @property
    def eval_key_bin_path(self):
        """
        Returns the file path to the evaluation key.
        Returns:
            str: The file path to the evaluation key.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/EvalKey.bin"

    @property
    def enc_key_path(self):
        """
        Returns the file path to the encryption key.
        Returns:
            str: The file path to the encryption key.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/EncKey.json"

    @property
    def enc_key_bin_path(self):
        """
        Returns the file path to the encryption key.
        Returns:
            str: The file path to the encryption key.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/EncKey.bin"

    @property
    def sec_key_bin_path(self):
        """
        Returns the file path to the secret key for evi.
        Returns:
            str: The file path to the secret key for evi.
        """
        if self.key_dir is None:
            return None
        if self.seal_info.mode == evi.SealMode.AES_KEK:
            return self.key_dir + "/SecKey_sealed.bin"
        elif self.seal_info.mode == evi.SealMode.NONE:
            return self.key_dir + "/SecKey.bin"

    @property
    def evi_sec_key_path(self):
        """
        Returns the file path to the secret key for evi.
        Returns:
            str: The file path to the secret key for evi.
        """
        if self.key_dir is None:
            return None
        return self.key_dir + "/SecKey.json"

    @property
    def sec_key_path(self):
        """
        Returns the file path to the secret key.
        Returns:
            str: The file path to the secret key.
        """
        return self.evi_sec_key_path

    @property
    def key_dir(self):
        """
        Returns the directory where the keys are stored.
        Returns:
            str: The directory where the keys are stored.
        """
        if self.key_path is None:
            return None
        if self.key_id is None:
            return self.key_path
        return self.key_path + "/" + self.key_id

    @property
    def enc_key(self):
        if self.enc_key_stream:
            return utils.get_key_stream(self.enc_key_stream)
        if self.enc_key_path:
            return utils.get_key_stream(self.enc_key_path)
        return None

    @enc_key.setter
    def enc_key(self, enc_key):
        self._enc_key = utils.get_key_stream(enc_key)

    @property
    def eval_key(self):
        if self.eval_key_stream:
            return utils.get_key_stream(self.eval_key_stream)
        if self.eval_key_path:
            return utils.get_key_stream(self.eval_key_path)
        return None

    @eval_key.setter
    def eval_key(self, eval_key):
        self._eval_key = utils.get_key_stream(eval_key)

    @property
    def sec_key(self):
        if self.sec_key_stream:
            return utils.get_key_stream(self.sec_key_stream)
        if self.sec_key_path:
            return utils.get_key_stream(self.sec_key_path)
        return None

    @sec_key.setter
    def sec_key(self, sec_key):
        self._sec_key = utils.get_key_stream(sec_key)

    @property
    def metadata_key(self):
        if self.metadata_key_stream:
            return utils.get_key_stream(self.metadata_key_stream)
        if self.metadata_key_path:
            return utils.get_key_stream(self.metadata_key_path)
        return None

    @metadata_key.setter
    def metadata_key(self, metadata_key):
        self._metadata_key = utils.get_key_stream(metadata_key)

    def check_key_dir(self) -> bool:
        """
        Checks if the key directory structure is valid.

        Returns:
            bool: True if the directory structure and required files exist, False otherwise.
        """
        from pathlib import Path

        base_dir = Path(self.key_path).expanduser().resolve()

        # Check if key_path exists and is a directory
        if not base_dir.exists() or not base_dir.is_dir():
            return False

        # Check if key_id directory exists
        key_dir = base_dir / self.key_id
        if not key_dir.exists() or not key_dir.is_dir():
            return False

        # Check for required files in the key_id directory
        required_files = ["EncKey.json", "EvalKey.json"]
        for file_name in required_files:
            file_path = key_dir / file_name
            if not file_path.exists():
                raise ValueError(f"[ERROR] Required file '{file_name}' is missing in '{key_dir}'.")
        optional_files = ["SecKey.json"]
        if not any((key_dir / file_name).exists() for file_name in optional_files):
            raise ValueError(f"[ERROR] At least one of {optional_files} must exist in '{key_dir}'.")

        return True

    def __repr__(self):
        """
        Returns a string representation of the KeyParameter object.
        """
        return (
            f"KeyParameter(\n  key_path={self.key_path},\n  key_id={self.key_id},\n  seal_info={self.seal_mode_name}\n)"
        )
