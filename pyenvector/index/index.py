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
Index Module

This module provides classes and methods for managing index configurations and operations.

Classes:
    IndexConfig: Configuration class for index settings.
    Index: Class for managing index operations.

"""

from typing import Any, List, Optional, Union

import numpy as np
from tqdm import tqdm

from pyenvector.api import Indexer
from pyenvector.crypto.block import CipherBlock
from pyenvector.crypto.cipher import Cipher
from pyenvector.crypto.parameter import ContextParameter, IndexParameter, KeyParameter, SealInfo
from pyenvector.utils.aes import decrypt_metadata, encrypt_metadata
from pyenvector.utils.logging_config import logger
from pyenvector.utils.utils import topk

ENCRYPTION_BATCH_SIZE = 4096
KNN_BATCH_SIZE = 4096


class IndexConfig:
    """
    Configuration class for index settings.

    Parameters
    ----------
    index_name : str, optional
        Name of the index.
    dim : int, optional
        Dimensionality of the index.
    key_path : str, optional
        Path to the key.
    key_id : str, optional
        ID of the key.
    seal_mode : str, optional
        Seal mode for the key.
    seal_kek_path: str, optional
        KeK for AES Seal Mode
    preset : str, optional
        Preset for the index.
    eval_mode : str, optional
        Evaluation mode for the index.
    query_encryption : str, optional
        The encryption type for query, e.g. "plain", "cipher", "hybrid".
    index_encryption : str, optional
        The encryption type for database, e.g. "plain", "cipher", "hybrid".
    index_params : dict, optional
        Parameters for the index.
    metadata_encryption: bool, optional
        The encryption type for metadata, e.g. True, False.
    description : str, optional
        Human-readable text describing the index.
    key_store : str, optional
        External key storage provider (currently only ``"aws"``).
    region_name : str, optional
        Region used by the external key store.
    bucket_name : str, optional
        S3 bucket for AWS key storage.
    secret_prefix : str, optional
        Secret prefix for AWS Secrets Manager.

    Examples
    --------
    >>> from pyenvector.index import IndexConfig, Index
    >>> index_config = IndexConfig(
    ...   key_path="./keys",
    ...   key_id="example_key",
    ...   preset="ip",
    ...   query_encryption="plain",
    ...   index_encryption="cipher",
    ...   index_params={"index_type": "flat"},
    ...   index_name="test_index",
    ...   dim=128
    ... )
    >>> from pyenvector.api import Indexer
    >>> indexer = Indexer.connect(address="localhost:50050")
    >>> index = Index.create_index(indexer=indexer, index_config=index_config)
    """

    def __init__(
        self,
        index_name: Optional[str] = None,
        dim: Optional[int] = None,
        key_path: Optional[str] = None,
        key_id: Optional[str] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        preset: Optional[str] = None,
        eval_mode: Optional[str] = None,
        query_encryption: Optional[str] = None,
        index_encryption: Optional[str] = None,
        index_params: Optional[dict] = None,
        index_type: Optional[str] = None,
        metadata_encryption: Optional[bool] = None,
        description: Optional[str] = None,
        use_key_stream: Optional[bool] = None,
        enc_key: Optional[bytes] = None,
        eval_key: Optional[bytes] = None,
        sec_key: Optional[bytes] = None,
        metadata_key: Optional[bytes] = None,
        seal_kek: Optional[bytes] = None,
        key_store: Optional[str] = None,
        region_name: Optional[str] = None,
        bucket_name: Optional[str] = None,
        secret_prefix: Optional[str] = None,
    ):
        """
        Initializes the IndexConfig class.
        """
        self.index_name = index_name
        self.description = description
        self.context_param = ContextParameter(preset=preset, dim=dim, eval_mode=eval_mode)
        self.key_param = KeyParameter(
            key_path=key_path,
            key_id=key_id,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
            metadata_encryption=metadata_encryption,
            use_key_stream=use_key_stream,
            enc_key=enc_key,
            eval_key=eval_key,
            sec_key=sec_key,
            metadata_key=metadata_key,
            seal_kek=seal_kek,
            key_store=key_store,
            region_name=region_name,
            bucket_name=bucket_name,
            secret_prefix=secret_prefix,
        )
        if index_params is None and index_type is not None:
            index_params = {"index_type": index_type}
        self.index_param = IndexParameter(
            index_encryption=index_encryption, query_encryption=query_encryption, index_params=index_params
        )

    @property
    def index_name(self) -> str:
        """
        Returns the index name.

        Returns:
            ``str``: Name of the index.
        """
        return self._index_name

    @index_name.setter
    def index_name(self, index_name: str):
        """
        Sets the index name.

        Args:
            index_name (str): Name of the index.
        """
        self._index_name = index_name
        return self

    @property
    def description(self) -> Optional[str]:
        """
        Returns the description for the index.

        Returns:
            Optional[str]: Description text if configured.
        """
        return getattr(self, "_description", None)

    @description.setter
    def description(self, description: Optional[str]):
        """
        Sets the description for the index.

        Args:
            description (Optional[str]): Description text.
        """
        self._description = description
        return self

    @property
    def context_param(self) -> ContextParameter:
        """
        Returns the context parameter object.

        Returns:
            ContextParameter: The parameter object for this context.
        """
        return self._context_param

    @context_param.setter
    def context_param(self, context_param: ContextParameter):
        """
        Sets the context parameter object.

        Args:
            context_param (ContextParameter): The parameter object for this context.
        """
        self._context_param = context_param
        return self

    @property
    def key_param(self) -> KeyParameter:
        """
        Returns the key parameter object.

        Returns:
            KeyParameter: The parameter object for the key.
        """
        return self._key_param

    @key_param.setter
    def key_param(self, key_param: KeyParameter):
        """
        Sets the key parameter object.

        Args:
            key_param (KeyParameter): The parameter object for the key.
        """
        self._key_param = key_param
        return self

    @property
    def index_param(self) -> IndexParameter:
        """
        Returns the index parameter object.

        Returns:
            IndexParameter: The parameter object for the index.
        """
        return self._index_param

    @index_param.setter
    def index_param(self, index_param: IndexParameter):
        """
        Sets the index parameter object.

        Args:
            index_param (IndexParameter): The parameter object for the index.
        """
        self._index_param = index_param
        return self

    @property
    def preset(self) -> str:
        """
        Returns the preset.

        Returns:
            ``str``: Preset for the index.
        """
        return self.context_param.preset_name

    @preset.setter
    def preset(self, preset: str):
        """
        Sets the preset.

        Args:
            preset (str): Preset for the index.
        """
        self.context_param = ContextParameter(preset=preset, dim=self.dim, eval_mode=self.eval_mode)
        return self

    @property
    def dim(self) -> int:
        """
        Returns the dimensionality of the index.

        Returns:
            ``int``: Dimensionality of the index.
        """
        return self.context_param.dim

    @dim.setter
    def dim(self, dim: int):
        """
        Sets the dimensionality of the index.

        Args:
            dim (int): Dimensionality of the index.
        """
        self.context_param = ContextParameter(preset=self.preset, dim=dim, eval_mode=self.context_param.eval_mode)
        return self

    @property
    def eval_mode(self) -> str:
        """
        Returns the evaluation mode.

        Returns:
            ``str``: Evaluation mode for the context.
        """
        return self.context_param.eval_mode_name

    @eval_mode.setter
    def eval_mode(self, eval_mode: str):
        """
        Sets the evaluation mode.

        Args:
            eval_mode (str): Evaluation mode for the context.
        """
        self.context_param = ContextParameter(preset=self.preset, dim=self.dim, eval_mode=eval_mode)
        return self

    @property
    def search_type(self) -> str:
        """
        Returns the search type.

        Returns:
            ``str``: Search type for the index.
        """
        return self.context_param.search_type

    @property
    def index_encryption(self) -> str:
        """
        Returns whether database encryption is enabled.

        Returns:
            ``str``: The encryption type for database, e.g. "plain", "cipher", "hybrid".
        """
        return self.index_param.index_encryption

    @index_encryption.setter
    def index_encryption(self, index_encryption: str):
        """
        Sets whether database encryption is enabled.

        Args:
            index_encryption (str): The encryption type for database, e.g. "plain", "cipher", "hybrid".
        """
        self.index_param = IndexParameter(
            index_encryption=index_encryption,
            query_encryption=self.query_encryption,
            index_params=self.index_params,
        )
        return self

    @property
    def query_encryption(self) -> str:
        """
        Returns whether query encryption is enabled.

        Returns:
            ``str``: The encryption type for query, e.g. "plain", "cipher", "hybrid".
        """
        return self.index_param.query_encryption

    @query_encryption.setter
    def query_encryption(self, query_encryption: str):
        """
        Sets whether query encryption is enabled.

        Args:
            query_encryption (str): The encryption type for query, e.g. "plain", "cipher", "hybrid".
        """
        self.index_param = IndexParameter(
            index_encryption=self.index_encryption,
            query_encryption=query_encryption,
            index_params=self.index_params,
        )
        return self

    @property
    def index_type(self) -> str:
        """
        Returns the index type.

        Returns:
            ``str``: Type of the index.
        """
        return self.index_param.index_type

    @index_type.setter
    def index_type(self, index_type: str):
        """
        Sets the index type.

        Args:
            index_type (str): Type of the index.
        """
        index_params = {"index_type": index_type}
        self.index_param = IndexParameter(
            index_encryption=self.index_encryption,
            query_encryption=self.query_encryption,
            index_params=index_params,
        )
        return self

    @property
    def index_params(self) -> dict:
        """
        Returns the index parameters.

        Returns:
            ``dict``: Parameters for the index.
        """
        return self.index_param.index_params

    @property
    def nlist(self):
        """
        Returns the nlist parameter for IVF indices.

        Returns:
            ``int``: Number of clusters (nlist) for IVF indices.
        """
        return self.index_param.nlist

    @property
    def default_nprobe(self):
        """
        Returns the default nprobe parameter for IVF indices.

        Returns:
            ``int``: Default number of probes (nprobe) for IVF indices.
        """
        return self.index_param.default_nprobe

    @property
    def centroids(self):
        """
        Returns the centroids for IVF indices.

        Returns:
            ``list[list[float]]``: Centroids for IVF indices.
        """
        return self.index_param.centroids

    @property
    def key_path(self) -> str:
        """
        Returns the key path.

        Returns:
            ``str``: Path to the key.
        """
        return self.key_param.key_path

    @key_path.setter
    def key_path(self, key_path: str):
        """
        Sets the key path.

        Args:
            key_path (str): Path to the key.
        """
        if self.key_path is not None:
            raise ValueError("Key path is already set. Please re-initialize the IndexConfig.")
        self.key_param.key_path = key_path
        return self

    @property
    def key_id(self) -> str:
        """
        Returns the key ID.

        Returns:
            ``str``: ID of the key.
        """
        return self.key_param.key_id

    @key_id.setter
    def key_id(self, key_id: str):
        """
        Sets the key ID.

        Args:
            key_id (str): ID of the key.
        """
        self.key_param.key_id = key_id
        return self

    @property
    def key_store(self) -> Optional[str]:
        return self.key_param.key_store

    @property
    def region_name(self) -> Optional[str]:
        return self.key_param.region_name

    @property
    def bucket_name(self) -> Optional[str]:
        return self.key_param.bucket_name

    @property
    def secret_prefix(self) -> Optional[str]:
        return self.key_param.secret_prefix

    @property
    def seal_info(self) -> SealInfo:
        """
        Returns the seal mode.

        Returns:
            ``str``: Seal mode for the keys.
        """
        return self.key_param.seal_info

    @property
    def seal_mode(self) -> str:
        """
        Returns the seal mode.

        Returns:
            ``str``: Seal mode for the keys.
        """
        return self.key_param.seal_mode_name

    @property
    def seal_kek_path(self) -> str:
        """
        Returns the seal KEK path.

        Returns:
            ``str``: Path to the seal KEK.
        """
        return self.key_param.seal_kek_path

    @property
    def eval_key_path(self) -> str:
        """
        Returns the evaluation key path.

        Returns:
            ``str``: Path to the evaluation key.
        """
        return self.key_param.eval_key_path

    @property
    def enc_key_path(self) -> str:
        """
        Returns the encryption key path.

        Returns:
            ``str``: Path to the encryption key.
        """
        return self.key_param.enc_key_path

    @property
    def sec_key_path(self) -> str:
        """
        Returns the secret key path.

        Returns:
            ``str``: Path to the secret key.
        """
        return self.key_param.sec_key_path

    @property
    def metadata_encryption(self) -> bool:
        return self.key_param.metadata_encryption

    @property
    def metadata_key_path(self) -> str:
        """
        Returns the metadata encryption key path.

        Returns:
            ``str``: Path to the metadata encryption key.
        """
        return self.key_param.metadata_key_path

    @property
    def key_dir(self) -> str:
        """
        Returns the directory where the keys are stored.

        Returns:
            ``str``: Directory for the keys.
        """
        return self.key_param.key_dir

    @property
    def need_cipher(self) -> bool:
        """
        Returns whether cipher operations are needed.

        Returns:
            ``bool``: True if cipher operations are needed, False otherwise.
        """
        return self.query_encryption in ["cipher", "hybrid"] or self.index_encryption in ["cipher", "hybrid"]

    @property
    def enc_key(self) -> Optional[bytes]:
        """
        Returns the encryption key.

        Returns:
            ``bytes``: Encryption key.
        """
        return self.key_param.enc_key

    @property
    def eval_key(self) -> Optional[bytes]:
        """
        Returns the evaluation key.

        Returns:
            ``bytes``: Evaluation key.
        """
        return self.key_param.eval_key

    @property
    def sec_key(self) -> Optional[bytes]:
        """
        Returns the secret key.

        Returns:
            ``bytes``: Secret key.
        """
        return self.key_param.sec_key

    @property
    def metadata_key(self) -> Optional[bytes]:
        """
        Returns the metadata encryption key.

        Returns:
            ``bytes``: Metadata encryption key.
        """
        return self.key_param.metadata_key

    @property
    def seal_kek(self) -> Optional[bytes]:
        """
        Returns the seal KEK.

        Returns:
            ``bytes``: Seal KEK.
        """
        return self.key_param.seal_kek

    @property
    def use_key_stream(self) -> bool:
        """
        Returns whether key stream is used.

        Returns:
            ``bool``: True if key stream is used, False otherwise.
        """
        return self.key_param.use_key_stream

    def deepcopy(
        self,
        index_name: Optional[str] = None,
        dim: Optional[int] = None,
        key_path: Optional[str] = None,
        key_id: Optional[str] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
        preset: Optional[str] = None,
        eval_mode: Optional[str] = None,
        query_encryption: Optional[str] = None,
        index_encryption: Optional[str] = None,
        index_params: Optional[dict] = None,
        metadata_encryption: Optional[bool] = None,
        description: Optional[str] = None,
        use_key_stream: Optional[bool] = None,
        enc_key: Optional[bytes] = None,
        eval_key: Optional[bytes] = None,
        sec_key: Optional[bytes] = None,
        metadata_key: Optional[bytes] = None,
        seal_kek: Optional[bytes] = None,
        key_store: Optional[str] = None,
        region_name: Optional[str] = None,
        bucket_name: Optional[str] = None,
        secret_prefix: Optional[str] = None,
    ) -> "IndexConfig":
        """
        Creates a deep copy of the index configuration.

        Returns:
            IndexConfig: A deep copy of the index configuration.
        """
        new_config = IndexConfig(
            index_name=self._index_name if index_name is None else index_name,
            dim=self.context_param.dim if dim is None else dim,
            key_path=self.key_param.key_path if key_path is None else key_path,
            key_id=self.key_param.key_id if key_id is None else key_id,
            seal_mode=self.key_param.seal_mode_name if seal_mode is None else seal_mode,
            seal_kek_path=self.key_param.seal_kek_path if seal_kek_path is None else seal_kek_path,
            preset=self.context_param.preset if preset is None else preset,
            eval_mode=self.context_param.eval_mode if eval_mode is None else eval_mode,
            query_encryption=self.index_param.query_encryption if query_encryption is None else query_encryption,
            index_encryption=self.index_param.index_encryption if index_encryption is None else index_encryption,
            index_params=self.index_param.index_params if index_params is None else index_params,
            metadata_encryption=(
                self.key_param.metadata_encryption if metadata_encryption is None else metadata_encryption
            ),
            description=self.description if description is None else description,
            use_key_stream=self.key_param.use_key_stream if use_key_stream is None else use_key_stream,
            enc_key=self.key_param.enc_key if enc_key is None else enc_key,
            eval_key=self.key_param.eval_key if eval_key is None else eval_key,
            sec_key=self.key_param.sec_key if sec_key is None else sec_key,
            metadata_key=self.key_param.metadata_key if metadata_key is None else metadata_key,
            seal_kek=seal_kek if seal_kek is not None else None,
            key_store=self.key_param.key_store if key_store is None else key_store,
            region_name=self.key_param.region_name if region_name is None else region_name,
            bucket_name=self.key_param.bucket_name if bucket_name is None else bucket_name,
            secret_prefix=self.key_param.secret_prefix if secret_prefix is None else secret_prefix,
        )
        return new_config

    def __repr__(self):
        return (
            "IndexConfig(\n"
            f"  index_name={self.index_name!r},\n"
            f"  dim={self.dim!r},\n"
            f"  key_path={self.key_path!r},\n"
            f"  key_id={self.key_id!r},\n"
            f"  index_type={self.index_type!r},\n"
            ")"
        )


class Index:
    """
    Class for managing index operations.

    Attributes
    ----------
    index_config : IndexConfig
        Configuration for the index.
    indexer : Indexer
        Indexer object for managing connections.
    num_entities : ``int``
        Number of entities in the index.
    cipher : Cipher
        Cipher object for encryption and decryption.

    Examples
    --------
    >>> from pyenvector.index import IndexConfig, Index
    >>> from pyenvector.api import Indexer
    >>> # Initialize index configuration
    >>> index_config = IndexConfig(
    ...   key_path="./keys",
    ...   key_id="example_key",
    ...   preset="ip",
    ...   query_encryption="plain",
    ...   index_encryption="cipher",
    ...   index_type="flat",
    ...   index_name="test_index",
    ...   dim=128
    ... )
    >>> # Connect to enVector
    >>> indexer = Indexer.connect(address="localhost:50050")
    >>> index = Index.create_index(indexer=indexer, index_config=index_config)
    >>> # Insert data into the index
    >>> data = [[0.001, 0.02, 0.03, ..., 0.127]]
    >>> metadata = ["example_metadata"]
    >>> index.insert(data=data, metadata=metadata)
    >>> # Encrypted Search in the index
    >>> query = [0.001, 0.02, 0.03, ..., 0.127]
    >>> results = index.search(query=query, top_k=3, output_fields=["metadata"])
    >>> print(results)
    """

    _default_key_path: Optional[str] = None
    _default_indexer: Optional[Indexer] = None
    _default_index_config: Optional[IndexConfig] = None

    def __init__(self, index_name: str, index_config: Optional[IndexConfig] = None):
        """
        Initializes the Index class.
        Check server connection and check if the index exists.

        Args:
            index_name (str): Name of the index.
            index_config (IndexConfig, optional): Configuration object to override defaults
                (such as key paths and encryption options). Falls back to ``Index._default_index_config``.
        """
        if Index._default_indexer is None:
            raise ValueError("Indexer not connected. Please call Index.init_connect() first.")
        index_config = index_config if index_config else Index._default_index_config
        if not index_config.use_key_stream and Index._default_key_path is None:
            raise ValueError("Key path not set. Please call Index.init_key_path() first.")
        indexer = Index._default_indexer
        if index_name not in indexer.get_index_list():
            raise ValueError(f"Index '{index_name}' does not exist. Please run create_index first.")
        metadata = indexer.get_index_info(index_name)
        self.indexer = indexer
        index_config.index_name = index_name
        index_config.dim = metadata["dim"]
        index_config.key_id = metadata["key_id"]
        index_config.index_encryption = metadata["index_encryption"]
        index_config.query_encryption = metadata["query_encryption"]
        index_config.index_type = metadata["index_type"]
        index_config.description = metadata.get("description")
        if index_config.index_type == "IVF_FLAT":
            index_config.index_param.nlist = metadata["ivf_detail"].nlist
            index_config.index_param.default_nprobe = metadata["ivf_detail"].default_nprobe
            index_config.index_param.centroids = np.array(
                list(map(lambda x: np.array(x.plain_vector.data), metadata["ivf_detail"].centroids))
            )
        self.index_config = index_config
        self.num_entities = metadata["row_count"]
        self.cipher = Cipher._create_from_index_config(self.index_config) if self.index_config.need_cipher else None
        self._is_loaded = metadata["is_loaded"]
        if not self.is_loaded:
            self.load()

    @classmethod
    def init_connect(
        cls,
        address: str,
        access_token: Optional[str] = None,
        secure: Optional[bool] = None,
    ) -> "Indexer":
        """
        Connects to the indexer.

        Args:
            address (``str``): Address of the indexer.
            access_token (``str``, optional): Access token for authentication.
            secure (``bool``, optional): Whether to use a secure connection. If None,
                (defaults to True when access_token is provided, otherwise False.)

        Returns:
            Indexer: Connected indexer object.
        """
        # Close any existing default indexer to avoid reusing previous gRPC channel
        # (e.g., previously secure channel persisting across re-initializations).
        if cls._default_indexer is not None:
            try:
                cls._default_indexer.disconnect()
            except Exception:
                pass
            finally:
                cls._default_indexer = None

        indexer = Indexer.connect(
            address=address,
            access_token=access_token,
            secure=secure,
        )
        cls._default_indexer = indexer
        logger.info(f"Connection created at {address}")
        return indexer

    @classmethod
    def init_key_path(cls, key_path: str):
        """
        Initializes the key path for the index.

        Args:
            key_path (``str``): Path to the key directory.
        """
        cls._default_key_path = key_path
        return key_path

    @classmethod
    def create_index(cls, index_config: IndexConfig, indexer: Optional[Indexer] = None) -> "Index":
        """
        Creates a new index.

        Parameters
        ----------
        index_config : IndexConfig
            Configuration for the index.
        indexer : Indexer, optional
            Indexer object for managing connections.

        Returns
        -------
        Index
            The created index.

        Examples
        --------
        >>> from pyenvector.index import IndexConfig, Index
        >>> from pyenvector.api import Indexer
        >>> index_config = IndexConfig(
        ...   key_path="./keys",
        ...   key_id="example_key",
        ...   preset="ip",
        ...   query_encryption="plain",
        ...   index_encryption="cipher",
        ...   index_type="flat",
        ...   index_name="test_index",
        ...   dim=128
        ... )
        >>> indexer = Indexer.connect(address="localhost:50050")
        >>> index = Index.create_index(indexer=indexer, index_config=index_config)
        """
        active_indexer = indexer or cls._default_indexer
        if not active_indexer:
            raise ValueError("Indexer not connected. Please call Index.init_connect() first.")

        if not index_config.index_name or not index_config.dim:
            raise ValueError("Index name and dimension must be set.")

        if cls._default_key_path != index_config.key_path:
            raise ValueError(
                f"Key path {index_config.key_path} does not match the default key path {cls._default_key_path}. "
                "Please reinitialize. pyenvector.init()"
            )
        key_list = active_indexer.get_key_list()
        if not key_list or index_config.key_id not in key_list:
            raise ValueError(f"Key ID '{index_config.key_id}' not found in Server. Please register key first.")
        if index_config.eval_mode == "MM" and index_config.query_encryption == "cipher":
            raise ValueError("Query encryption is not supported in MM mode.")
        active_indexer.create_index(
            index_name=index_config.index_name,
            key_id=index_config.key_id,
            dim=index_config.dim,
            search_type=index_config.search_type,
            index_encryption=index_config.index_encryption,
            query_encryption=index_config.query_encryption,
            metadata_encryption=index_config.metadata_encryption,
            index_params=index_config.index_params,
            description=index_config.description,
        )
        return cls(index_config.index_name, index_config)

    def insert(
        self,
        data: Union[List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
        metadata: List[Any] = None,
    ):
        """
        Inserts data into the index.

        Parameters
        ----------
        data : list of floats, list of np.ndarray, 2D np.ndarray, or list of CipherBlock
            Data to be inserted. It can be plaintext (list of lists, list of numpy arrays, or 2D numpy array) or
            ciphertext (CipherBlock).
            Currently, only a list of ``CipherBlock`` is supported for encrypted data.
        metadata : str
            Metadata for the data.

        Returns
        -------
        Index
            The index object after insertion.

        Examples
        --------
        >>> data = [[0.001, 0.02, ..., 0.127]]
        >>> metadata = ["example_metadata"]
        >>> index.insert(data=data, metadata=metadata)

        >>> import numpy as np
        >>> data = np.random.rand(100, 512)  # 2D numpy array
        >>> metadata = [f"item_{i}" for i in range(100)]
        >>> index.insert(data=data, metadata=metadata)
        """
        if not self.is_loaded:
            raise ValueError("Index not loaded. Please call Index.load() first.")
        # Handle 2D numpy array
        if isinstance(data, np.ndarray) and data.ndim == 2:
            if data.shape[1] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {data.shape[1]} does not match index dimension {self.index_config.dim}."
                )
        elif isinstance(data[0], CipherBlock):
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Index encryption must be enabled to insert CipherBlock data.")
        elif isinstance(data[0], list):
            if len(data[0]) != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {len(data[0])} does not match index dimension {self.index_config.dim}."
                )
        elif isinstance(data[0], np.ndarray):
            if data[0].shape[0] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {data[0].shape[0]} does not match index dimension {self.index_config.dim}."
                )
        else:
            raise ValueError("Data must be a list of lists, numpy arrays, 2D numpy array, or CipherBlock.")

        item_ids = self._insert_bulk(data, metadata=metadata)
        logger.debug("Data insertion completed successfully.")
        return item_ids

    def _encrypt_metadata_list(self, metadata: List[Any]) -> List[Any]:
        """Encrypts metadata if metadata encryption is enabled."""
        if self.index_config.metadata_encryption:
            key_source = self.index_config.metadata_key_path or self.index_config.metadata_key
            encrypted_metadata = [
                encrypt_metadata(m, key_source, kek=self.index_config.seal_kek_path) for m in metadata
            ]
            return encrypted_metadata
        return metadata

    def _decrypt_metadata(self, metadata: List[Any]):
        if metadata and self.index_config.metadata_encryption:
            key_source = self.index_config.metadata_key_path or self.index_config.metadata_key
            return decrypt_metadata(metadata, key_source, kek=self.index_config.seal_kek_path)
        else:
            return metadata

    def _prepare_metadata_for_chunk(self, metadata_chunk: List[Any], num_item_list: List[int]) -> List[List[str]]:
        """Ensures each ciphertext chunk sends ``count`` metadata strings."""

        def normalize_entry(entry: Any) -> List[str]:
            if entry is None:
                return []
            if isinstance(entry, bytes):
                return [entry.decode("utf-8", errors="ignore")]
            if isinstance(entry, str):
                return [entry]
            if isinstance(entry, (list, tuple)):
                return ["" if v is None else str(v) for v in entry]
            return [str(entry)]

        if not metadata_chunk:
            return [["" for _ in range(count)] for count in num_item_list]

        flattened: List[str] = []
        for entry in metadata_chunk:
            flattened.extend(normalize_entry(entry))

        prepared: List[List[str]] = []
        cursor = 0
        for count in num_item_list:
            slice_values = flattened[cursor : cursor + count]
            cursor += count
            if len(slice_values) < count:
                slice_values.extend(["" for _ in range(count - len(slice_values))])
            elif len(slice_values) > count:
                slice_values = slice_values[:count]
            prepared.append(["" if v is None else str(v) for v in slice_values])

        return prepared

    def _insert_chunk(self, data_chunk: CipherBlock, metadata: List[any] = None, centroid_idx: int = 0):
        """Inserts a single data chunk (CipherBlock) and its metadata into the indexer."""
        input_metadata = self._prepare_metadata_for_chunk(metadata, data_chunk.num_item_list)

        item_ids = self.indexer.insert_data_bulk(
            self.index_config.index_name, data_chunk.data, data_chunk.num_item_list, input_metadata, centroid_idx
        )
        self.num_entities += data_chunk.num_vectors

        return item_ids

    def _insert_ivf_bulk(self, data: Union[List[any], np.ndarray], metadata: List[any] = None):
        """
        Bulk inserts data into the index for IVF-FLAT.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        # Insert Bulk
        item_ids = []  # placeholder for return value

        if isinstance(data[0], CipherBlock):
            raise Exception("Encrypted data can not be insert with IVF Index")
        if self.index_config.index_encryption not in ["cipher", "hybrid"]:
            raise ValueError("Received unencrypted data, but index encryption is disabled.")

        close_idxs = self._knn(data, k=1)
        close_idxs = [
            idx[0] if isinstance(idx, (list, np.ndarray)) else (idx.item() if isinstance(idx, np.generic) else idx)
            for idx in close_idxs
        ]

        close_vector_idx = dict()
        for i, idx in enumerate(close_idxs):
            if idx not in close_vector_idx:
                close_vector_idx[idx] = []
            close_vector_idx[idx].append(i)

        for idx, vec_indices in tqdm(close_vector_idx.items(), desc="Insert IVF_FLAT", total=len(close_vector_idx)):
            logger.debug(f"Cluster {idx}: {len(vec_indices)} vectors")
            num_items = len(vec_indices)
            logger.debug(
                f"Bulk encrypting {num_items} entities for index '{self.index_config.index_name}'"
                f" to centroid {idx}."
            )
            for i in range(0, num_items, ENCRYPTION_BATCH_SIZE):
                raw_data_chunk = []
                metadata_chunk = [] if metadata else None
                for j in range(i, min(i + ENCRYPTION_BATCH_SIZE, num_items)):
                    raw_data_chunk.append(data[vec_indices[j]])
                    if metadata_chunk is not None:
                        metadata_chunk.append(metadata[vec_indices[j]])

                encrypted_chunk = self.cipher.encrypt_multiple(raw_data_chunk, encode_type="item")
                item_id_chunk = self._insert_chunk(encrypted_chunk, metadata_chunk, idx)
                if item_id_chunk:
                    if not item_ids or item_ids[-len(item_id_chunk) :] != item_id_chunk:
                        item_ids.extend(item_id_chunk)

        logger.debug("IVF_FLAT Data insertion completed successfully.")
        return item_ids

    def _insert_flat_bulk(self, data: Union[List[any], np.ndarray], metadata: List[any] = None):
        """
        Bulk inserts data into the index.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        # Insert Bulk
        item_ids = []  # placeholder for return value

        # Case 1: Data is not encrypted (raw data)
        # Handle 2D numpy array
        if isinstance(data, np.ndarray) and data.ndim == 2:
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Received unencrypted data, but index encryption is disabled.")

            num_items = data.shape[0]
            logger.debug(f"Bulk encrypting {num_items} entities for index '{self.index_config.index_name}'.")
            for i in tqdm(range(0, num_items, ENCRYPTION_BATCH_SIZE), desc="Encrypt and Insert"):
                raw_data_chunk = data[i : i + ENCRYPTION_BATCH_SIZE]
                # Convert numpy array chunk to list of 1D arrays for encryption
                raw_data_chunk_list = [raw_data_chunk[j] for j in range(raw_data_chunk.shape[0])]

                # Encrypt the data and convert it into a CipherBlock object
                encrypted_chunk = self.cipher.encrypt_multiple(raw_data_chunk_list, encode_type="item")

                metadata_chunk = metadata[i : i + ENCRYPTION_BATCH_SIZE] if metadata else None
                item_id_chunk = self._insert_chunk(encrypted_chunk, metadata_chunk)
                if item_id_chunk:
                    if not item_ids or item_ids[-len(item_id_chunk) :] != item_id_chunk:
                        item_ids.extend(item_id_chunk)

        elif not isinstance(data[0], CipherBlock):
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Received unencrypted data, but index encryption is disabled.")

            num_items = len(data)
            logger.debug(f"Bulk encrypting {num_items} entities for index '{self.index_config.index_name}'.")
            for i in tqdm(range(0, num_items, ENCRYPTION_BATCH_SIZE), desc="Encrypt and Insert"):
                raw_data_chunk = data[i : i + ENCRYPTION_BATCH_SIZE]

                # Encrypt the data and convert it into a CipherBlock object
                encrypted_chunk = self.cipher.encrypt_multiple(raw_data_chunk, encode_type="item")

                metadata_chunk = metadata[i : i + ENCRYPTION_BATCH_SIZE] if metadata else None
                item_id_chunk = self._insert_chunk(encrypted_chunk, metadata_chunk)
                if item_id_chunk:
                    if not item_ids or item_ids[-len(item_id_chunk) :] != item_id_chunk:
                        item_ids.extend(item_id_chunk)

        # Case 2: Data is already a list of CipherBlock objects
        else:
            num_total_vectors = sum(chunk.num_vectors for chunk in data)
            if metadata and num_total_vectors != len(metadata):
                raise ValueError("Metadata length does not match the total number of entities.")

            metadata_offset = 0
            for data_chunk in tqdm(data, desc="Insert CipherBlock Bulk"):
                if metadata:
                    num_chunk_entities = data_chunk.num_vectors
                    metadata_chunk = metadata[metadata_offset : metadata_offset + num_chunk_entities]
                    metadata_offset += num_chunk_entities
                else:
                    metadata_chunk = None

                item_id_chunk = self._insert_chunk(data_chunk, metadata_chunk)
                item_ids.extend(item_id_chunk)

        logger.debug("FLAT Data insertion completed successfully.")
        return item_ids

    def _insert_bulk(self, data: Union[List[any], np.ndarray], metadata: List[any] = None):
        """
        Bulk inserts data into the index.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        # Metadata Encryption if needed
        if metadata and self.index_config.metadata_encryption:
            metadata = self._encrypt_metadata_list(metadata)

        # Before insert get index info
        if self.index_config.index_type.upper() == "IVF_FLAT":
            return self._insert_ivf_bulk(data, metadata)
        elif self.index_config.index_type.upper() == "FLAT":
            return self._insert_flat_bulk(data, metadata)
        else:
            raise ValueError(f"Index type '{self.index_config.index_type}' not supported for insertion.")

    def search(
        self,
        query: Union[List[float], np.ndarray, List[List[float]], List[np.ndarray], List[CipherBlock]],
        top_k: int,
        output_fields: List[str] = None,
        search_params: dict = None,
    ):
        """
        Searches the index.

        Parameters
        ----------
        query : list of float or np.ndarray
            Query vector.
        top_k : int, optional
            Number of top results to return (default 3).
        output_fields : list of str, optional
            Fields to include in the output.

        Returns
        -------
        list of dict
            Search results.

        Examples
        --------
        >>> query = [0.001, 0.02, ..., 0.127]
        >>> results = index.search(query=query, top_k=3, output_fields=["metadata"])
        >>> print(results)
        """
        result_ctxt_list = self.scoring(query, search_params=search_params)
        result_list = [self.decrypt_score(result_ctxt) for result_ctxt in result_ctxt_list]
        output_result_list = self._multiquery_get_topk_metadata_results(result_list, top_k, output_fields)
        return output_result_list

    def scoring(
        self,
        query: Union[List[float], np.ndarray, CipherBlock, List[List[float]], List[np.ndarray], List[CipherBlock]],
        search_params: dict = None,
    ):
        """
        Computes the scores for a query against the index.
        Args:
            query (list): Query vector.
            search_params (dict, optional): Additional search-time parameters understood by the server.

        Returns:
            list of dict: Scores for the query.

        Raises:
            ValueError: If the index is not connected.

        Examples
        --------
        >>> query = [0.001, 0.02, 0.03, ..., 0.127]
        >>> result_ctxt = index.scoring(query=query)
        >>> print(result_ctxt)
        """
        if not self.is_loaded:
            raise ValueError("Index not loaded. Please call Index.load() first.")
        if (
            # Plain Query
            (isinstance(query, list) and isinstance(query[0], float))
            or isinstance(query, np.ndarray)
            # Cipher Query
            or isinstance(query, CipherBlock)
        ):
            query = [query]  # If single query, make it form of multi query
        # Check whether plain query has proper dimension or not
        if isinstance(query, list) and (
            (isinstance(query[0], list) and isinstance(query[0][0], float)) or isinstance(query[0], np.ndarray)
        ):
            for i in query:
                # i = np.array(i)
                if len(i) != self.index_config.dim:
                    raise ValueError(
                        f"Query dimension {len(i)} does not match index dimension {self.index_config.dim}."
                    )
        # Now, all query is form of multi query
        if self.index_config.index_type == "IVF_FLAT":
            if self.index_config.query_encryption in ["cipher"]:  # CC
                # Encrypt multiple queries for each, if query was plaintext
                if (
                    isinstance(query, List) and query and isinstance(query[0], List) and isinstance(query[0][0], float)
                ) or (isinstance(query, List) and isinstance(query[0], np.ndarray)):
                    nprobe = (
                        search_params.get("nprobe", self.index_config.index_param.default_nprobe)
                        if search_params
                        else self.index_config.index_param.default_nprobe
                    )
                    encrypted_query = [self.cipher.encrypt(i, encode_type="query") for i in query]

                    search_topk = self._knn(query, k=nprobe)

                else:
                    raise Exception("IVF_FLAT need to closet centriod info before encryption")

                assert nprobe == len(search_topk[0])
                logger.debug(f"Search on {nprobe} clusters by IVF-FLAT: {search_topk}")

                # Do search with encrypted queries
                result_ctxt = self.indexer.encrypted_search(self.index_config.index_name, encrypted_query, search_topk)

            else:  # PC
                # Do search with plain queries
                nprobe = (
                    search_params.get("nprobe", self.index_config.index_param.default_nprobe)
                    if search_params
                    else self.index_config.index_param.default_nprobe
                )

                search_topk = self._knn(query, k=nprobe)

                assert nprobe == len(search_topk[0])
                logger.debug(f"Search on {nprobe} clusters by IVF-FLAT: {search_topk}")

                result_ctxt = self.indexer.search(self.index_config.index_name, query, search_topk)

        else:
            if self.index_config.query_encryption in ["cipher"]:  # CC
                # Encrypt multiple queries for each, if query was plaintext
                if (
                    isinstance(query, List) and query and isinstance(query[0], List) and isinstance(query[0][0], float)
                ) or (isinstance(query, List) and isinstance(query[0], np.ndarray)):
                    encrypted_query = [self.cipher.encrypt(i, encode_type="query") for i in query]
                else:
                    encrypted_query = query
                # Do search with encrypted queries
                result_ctxt = self.indexer.encrypted_search(self.index_config.index_name, encrypted_query)
            else:  # PC
                # Do search with plain queries
                result_ctxt = self.indexer.search(self.index_config.index_name, query)
        result = [CipherBlock(result) for result in result_ctxt]
        logger.debug(f"Scoring completed successfully for {len(query)} queries. {result}")
        return result  # Return is always a list of CipherBlock

    def get_topk_metadata_results(self, result, top_k: int, output_fields: List[str] = None):
        """
        Get top-k metadata results from the search ciphertext result.

        Args:
            result (CipherBlock): The result context containing encrypted scores.
            top_k (int): Number of top results to return.
            output_fields (list of str, optional): Fields to include in the output.

        Returns:
            list of dict: List of dictionaries containing the top-k results with metadata.

        Raises:
            ValueError: If the indexer is not connected or if the result is empty.

        Examples
        --------
        >>> decrypted_scores = index.decrypt_score(result_ctxt, sec_key_path="./keys/SecKey.bin")
        >>> top_k_results = index.get_topk_metadata_results(result_ctxt, top_k=3, output_fields=["metadata"])
        >>> print(top_k_results)
        """
        result = self._multiquery_get_topk_metadata_results(results=[result], top_k=top_k, output_fields=output_fields)[
            0
        ]
        logger.debug(f"Top-{top_k} metadata retrieval completed successfully. result: {result}")
        return result

    def _multiquery_get_topk_metadata_results(self, results, top_k: int, output_fields: List[str] = None):
        topk_result_list = []
        topk_indices_list = []
        for result in results:
            topk_result, topk_indices = topk(result["score"], top_k)
            if result.get("shard_idx"):
                for i, v in enumerate(topk_indices):
                    topk_indices[i]["shard_idx"] = result["shard_idx"][v["shard_idx"]]
            topk_result_list.append(topk_result)
            topk_indices_list.extend(topk_indices)

        metadata_result = self.indexer.get_metadata(
            self.index_config.index_name, topk_indices_list, fields=output_fields
        )

        output_result_list = []
        offset = 0
        for topk_result in topk_result_list:
            n = len(topk_result)
            output_result = [
                {
                    "id": metadata_result[i + offset].id,
                    "score": topk_result[i][1],
                    "metadata": self._decrypt_metadata(metadata_result[i + offset].data),
                }
                for i in range(n)
            ]
            output_result_list.append(output_result)
            offset += n
        return output_result_list

    def decrypt_score(
        self,
        result_ctxt: CipherBlock,
        sec_key_path: Optional[str] = None,
        seal_mode: Optional[str] = None,
        seal_kek_path: Optional[str] = None,
    ):
        """
        Decrypts the scores from the result context.

        Args:
            result_ctxt (CipherBlock): The result context containing encrypted scores.
            sec_key_path (str, optional): Path to the secret key used for decryption.
            seal_mode (str, optional): Seal mode name for decrypting sealed keys.
            seal_kek_path (str or bytes, optional): Path, bytes to the KEK when unsealing the key.

        Returns:
            list of float: Decrypted scores.

        Examples
        --------
        >>> result_ctxt = index.scoring(query=query)
        >>> decrypted_scores = index.decrypt_score(result_ctxt, sec_key_path="./keys/SecKey.bin")
        >>> print(decrypted_scores)
        """
        if self.index_config.index_encryption not in ["cipher", "hybrid"]:
            raise ValueError("Index encryption is not enabled. Cannot decrypt scores.")
        result = self.cipher.decrypt_score(
            result_ctxt,
            sec_key_path=sec_key_path,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
        )
        logger.debug(f"Score decryption completed successfully. result: {len(result['score'])}...")
        return result

    def load(self):
        """
        Loads the index into memory.

        Returns
        -------
        Index
            The index object after loading it.

        Examples
        --------
        >>> index.load()
        """
        is_loaded = self.indexer.get_index_info(self.index_config.index_name)["is_loaded"]
        if is_loaded:
            logger.info("Index already loaded. No need to load.")
            if not self.is_loaded:
                self._is_loaded = True
            return self
        self.indexer.load_index(self.index_config.index_name)
        self._is_loaded = True
        return self

    def unload(self):
        """
        Unloads the index from memory.

        Returns
        -------
        Index
            The index object after unloading it.

        Examples
        --------
        >>> index.unload()
        """
        is_loaded = self.indexer.get_index_info(self.index_config.index_name)["is_loaded"]
        if not is_loaded:
            logger.info("Index already unloaded. No need to unload.")
            if self.is_loaded:
                self._is_loaded = False
            return self
        self.indexer.unload_index(self.index_config.index_name)
        self._is_loaded = False
        return self

    def drop(self):
        """
        Drops the index.

        Returns
        -------
        Index
            The index object after dropping it.

        Examples
        --------
        >>> index.drop()
        """
        if not self.is_connected:
            raise ValueError("Indexer not connected. Please call Index.init_connect() first.")
        self.indexer.delete_index(self.index_config.index_name)
        self.indexer = None
        self.index_config = None
        self.num_entities = 0
        return self

    def _knn(self, data: Union[List[List[float]], List[np.ndarray], np.ndarray], k: int = 1):
        """
        Find k-nearest neighbors for each vector in the index.
        """
        dim = self.index_config.centroids.shape[1]
        nearest_indices: List[np.ndarray] = []

        # batch inner product to find nearest centroids
        for i in range(0, len(data), KNN_BATCH_SIZE):
            data_matrix = np.asarray(data[i : i + KNN_BATCH_SIZE], dtype=np.float32)
            if data_matrix.shape[1] != dim:
                raise ValueError(f"Centroid dimension {dim} does not match data dimension {data_matrix.shape[1]}.")

            dist_matrix = data_matrix @ self.index_config.centroids.T

            # Efficiently get top-k indices for each row using np.argpartition
            search_topk = np.argpartition(dist_matrix, -k, axis=1)[:, -k:]

            nearest_indices.append(search_topk)

        if not nearest_indices:
            return []

        return np.concatenate(nearest_indices, axis=0).tolist()

    @property
    def is_connected(self) -> bool:
        """
        Checks if the indexer is connected.

        Returns:
            ``bool``: True if the indexer is connected, False otherwise.
        """
        return self.index_config.index_name in self.indexer.get_index_list() if self.indexer else False

    @property
    def is_loaded(self) -> bool:
        """
        Checks if the index is loaded in memory.

        Returns:
            ``bool``: True if the index is loaded, False otherwise.
        """
        return self._is_loaded

    @is_loaded.setter
    def is_loaded(self, value: bool):
        raise NotImplementedError("Setting is_loaded directly is not allowed.")

    def __repr__(self):
        return (
            "Index(\n"
            f"  {repr(self.index_config)},\n"
            f"  num_entities={self.num_entities},\n"
            f"  cipher={self.cipher if self.cipher else None}\n"
            ")"
        )
