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

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Union

import numpy as np
from tqdm import tqdm

from pyenvector.api import Indexer
from pyenvector.crypto.block import CipherBlock
from pyenvector.crypto.cipher import Cipher
from pyenvector.crypto.parameter import ContextParameter, IndexParameter, KeyParameter, SealInfo
from pyenvector.errors import EnvectorApplicationError
from pyenvector.proto_gen.v2.common import index_operation_message_pb2 as envector_op_pb2
from pyenvector.proto_gen.v2.common import type_pb2 as common_type_pb2
from pyenvector.utils.aes import decrypt_metadata, encrypt_metadata
from pyenvector.utils.logging_config import logger
from pyenvector.utils.utils import topk

ENCRYPTION_BATCH_SIZE = 4096
KNN_BATCH_SIZE = 4096
MAX_REQUEST_ID_LENGTH = 30
_IVF_INDEX_TYPES: frozenset = frozenset({"IVF_FLAT", "IVF_VCT"})
AccessTokenInput = Optional[Union[str, Callable[[], Optional[str]]]]


@dataclass
class _NormalizedInsertData:
    """Internal normalized representation for insert input."""

    kind: str  # "plain" or "cipher"
    data: Union[List[Any], np.ndarray]


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
        External key storage provider (e.g., ``"aws"``, ``"gcp"``).
    region_name : str, optional
        Region used by the external key store (AWS).
    bucket_name : str, optional
        Bucket name for external key storage.
    secret_prefix : str, optional
        Secret prefix for external key storage.

    Examples
    --------
    >>> from pyenvector.index import IndexConfig, Index
    >>> index_config = IndexConfig(
    ...   key_path="./keys",
    ...   key_id="example_key",
    ...   preset="ip1",
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
        vault_addr: Optional[str] = None,
        vault_mount: Optional[str] = None,
    ):
        """
        Initializes the IndexConfig class.
        """
        self.context_param = ContextParameter(preset=preset, dim=dim, eval_mode=eval_mode)
        self.index_name = index_name
        self.description = description
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
            vault_addr=vault_addr,
            vault_mount=vault_mount,
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
        level = self.context_param.level if self.context_param.level_is_explicit else None
        self.context_param = ContextParameter(preset=preset, dim=self.dim, eval_mode=self.eval_mode, level=level)
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
        level = self.context_param.level if self.context_param.level_is_explicit else None
        self.context_param = ContextParameter(
            preset=self.preset, dim=dim, eval_mode=self.context_param.eval_mode, level=level
        )
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
        level = self.context_param.level if self.context_param.level_is_explicit else None
        self.context_param = ContextParameter(preset=self.preset, dim=self.dim, eval_mode=eval_mode, level=level)
        return self

    @property
    def level(self) -> int:
        """
        Returns the level.

        Returns:
            ``int``: Level for the context.
        """
        return self.context_param.level

    @level.setter
    def level(self, level: int):
        """
        Sets the level.

        Args:
            level (int): Level for the context.
        """
        self.context_param = ContextParameter(preset=self.preset, dim=self.dim, eval_mode=self.eval_mode, level=level)
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
    def vault_addr(self) -> Optional[str]:
        return self.key_param.vault_addr

    @property
    def vault_mount(self) -> Optional[str]:
        return self.key_param.vault_mount

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
        vault_addr: Optional[str] = None,
        vault_mount: Optional[str] = None,
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
            vault_addr=self.key_param.vault_addr if vault_addr is None else vault_addr,
            vault_mount=self.key_param.vault_mount if vault_mount is None else vault_mount,
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
    ...   preset="ip1",
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
    _default_kms_client = None

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
        metadata = indexer.get_index_summary(index_name)
        self.indexer = indexer
        index_config.index_name = index_name
        index_config.dim = metadata["dim"]
        index_config.key_id = metadata["key_id"]
        index_config.index_encryption = metadata["index_encryption"]
        index_config.query_encryption = metadata["query_encryption"]
        index_config.index_type = metadata["index_type"]
        index_config.description = metadata.get("description")
        self.index_config = index_config
        self._ivf_runtime_metadata_loaded = index_config.index_type not in ("IVF_FLAT", "IVF_VCT")
        self._ivf_centroids_loaded = False
        self.num_entities = metadata["row_count"]
        self.kms_client = Index._default_kms_client
        self.cipher = Cipher._create_from_index_config(self.index_config) if self.index_config.need_cipher else None
        self._is_loaded = metadata["is_loaded"]

    def _ensure_ivf_runtime_metadata_loaded(self, require_centroids: bool = False) -> None:
        """Populate IVF runtime metadata lazily when an operation actually needs it."""
        index_type = self.index_config.index_type
        if index_type not in ("IVF_FLAT", "IVF_VCT"):
            return

        needs_runtime = not self._ivf_runtime_metadata_loaded
        needs_centroids = require_centroids and index_type == "IVF_FLAT" and not self._ivf_centroids_loaded
        if not needs_runtime and not needs_centroids:
            return

        metadata = self.indexer.get_index_info(self.index_config.index_name)
        ivf_detail = metadata.get("ivf_detail")
        if ivf_detail is None:
            raise ValueError(
                f"IVF metadata for index '{self.index_config.index_name}' is unavailable from get_index_info()."
            )

        self.index_config.index_param.nlist = ivf_detail.nlist
        self.index_config.index_param.default_nprobe = ivf_detail.default_nprobe
        self._ivf_runtime_metadata_loaded = True

        if index_type == "IVF_FLAT" or require_centroids:
            if not getattr(ivf_detail, "centroids", None):
                raise ValueError(
                    f"Centroids for IVF_FLAT index '{self.index_config.index_name}' are missing from index detail."
                )
            self.index_config.index_param.centroids = np.array(
                [np.array(centroid.plain_vector.data) for centroid in ivf_detail.centroids],
                dtype=np.float32,
            )
            self._ivf_centroids_loaded = True

    @classmethod
    def init_connect(
        cls,
        address: str,
        access_token: AccessTokenInput = None,
        secure: Optional[bool] = None,
        refresh_token: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> "Indexer":
        """
        Connects to the indexer.

        Args:
            address (``str``): Address of the indexer.
            access_token (``str`` or callable, optional): Access token for authentication, or a
                callable returning the current token for refreshable auth flows.
            secure (``bool``, optional): Whether to use a secure connection. If None,
                (defaults to True when access_token or refresh_token is provided, otherwise False.)
            refresh_token (``str``, optional): OIDC refresh token used by the SDK to renew bearer tokens.
            oidc_issuer (``str``, optional): OIDC issuer URL used to discover the token endpoint.
            token_endpoint (``str``, optional): Explicit token endpoint used for refresh token exchange.
            client_id (``str``, optional): OIDC client ID for refresh token exchange.
            client_secret (``str``, optional): OIDC client secret for refresh token exchange.
            scope (``str``, optional): Optional scope value included in refresh requests.

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
            refresh_token=refresh_token,
            oidc_issuer=oidc_issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
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
        ...   preset="ip1",
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

    def indexing(
        self,
        request_ids: Optional[List[str]] = None,
    ):
        self.indexer.async_merge_by_request_ids(
            self.index_config.index_name,
            request_ids,
        )

    def insert(
        self,
        data: Union[CipherBlock, List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
        metadata: List[Any] = None,
        request_ids: Optional[List[str]] = None,
        await_completion: bool = False,
        execute_until: str = "segmentation",
        load: bool = True,
        use_row_insert: bool = False,
        encryptor=None,
        **kwargs,
    ):
        """
        Inserts data into the index.

        enVector INSERT requests are asynchronous. ``Index.insert()`` always submits the split/persist
        RPCs first. ``execute_until="flush"`` stops there, while ``execute_until="segmentation"``
        additionally submits ``merge_by_request_ids`` for the captured split request IDs. For
        request-scoped completion tracking, pass an empty list as ``request_ids``. The server-generated
        split request IDs will be appended to it after each underlying async split RPC completes.

        Parameters
        ----------
        data : CipherBlock, list of floats, list of np.ndarray, 2D np.ndarray, or list of CipherBlock
            Data to be inserted. It can be plaintext (list of lists, list of numpy arrays, or 2D numpy array) or
            ciphertext (``CipherBlock`` or list of ``CipherBlock``).
        metadata : str
            Metadata for the data.
        request_ids : Optional[List[str]], optional
            Out list for server-generated request identifiers (from response ``header.id``).

            - If ``None`` (default), the client does not capture request identifiers and you cannot
              poll completion for this insert.
            - If provided, the list is cleared and filled with the server-generated request IDs
              (one per underlying async split request). These are the split request IDs; use
              them with :meth:`get_index_operation_status`, :meth:`wait_for_inserts_searchable`,
              or :meth:`async_merge_by_request_ids`.
        await_completion : bool, optional
            If ``True``, block until the selected server-side stage is reached. ``"flush"``
            waits for ``SPLIT_COMPLETED``; ``"segmentation"`` waits for ``MERGED_SAVED``.
            When ``load=True`` is also set, the SDK then calls :meth:`load` after that stage
            wait completes. The SDK does not perform an additional searchable wait
            automatically; use :meth:`wait_for_inserts_searchable` when callers need a
            ``done=true`` searchable guarantee.
        execute_until : str, optional
            Server-side completion stage for this insert. Supported values are:

            - ``"flush"``: stop after split/persist submission
            - ``"segmentation"``: submit ``merge_by_request_ids`` after split request IDs are captured
        load : bool, optional
            If ``True``, call :meth:`load` after submission, or after the selected stage wait
            when ``await_completion=True``. This triggers backend publication work but does not
            add an SDK-side searchable wait on its own. When invoked before merge completion,
            backend ``LoadIndex`` may expose raw fallback shards while request-scoped merge
            work is still unfinished.
        use_row_insert : bool, optional
            If ``True``, small plaintext chunks (fewer vectors than ``dim``) use the
            row-insert path instead of bulk insertion. Default: ``False``.
        encryptor : Encryptor or Cipher, optional
            Custom encryptor for this insert call. When provided, this encryptor
            is used instead of ``self.cipher`` for FHE encryption. This enables
            thread-safe parallel inserts by giving each thread its own encryptor
            with an independent PRNG state. Accepts either an ``Encryptor``
            instance or a ``Cipher`` instance (its internal encryptor is used).
            If ``None`` (default), ``self.cipher`` is used.

        Returns
        -------
        Index
            The index object after insertion.

        Examples
        --------
        >>> data = [[0.001, 0.02, ..., 0.127]]
        >>> metadata = ["example_metadata"]
        >>> index.insert(data=data, metadata=metadata)

        >>> # Parallel insert with independent encryptors
        >>> from pyenvector.crypto.cipher import Cipher
        >>> cipher = Cipher(dim=512, enc_key_path="keys/EncKey.json", preset="ip1", eval_mode="mm")
        >>> index.insert(data=data, metadata=metadata, encryptor=cipher)
        """
        normalized_data = self._normalize_insert_data(data)

        if normalized_data.kind == "cipher":
            available_shards = self.remaining_insertable_shards
            if len(normalized_data.data) > available_shards:
                raise ValueError(f"index is not insertable for {len(normalized_data.data)} ciphertexts, {available_shards} available")
            else:
                logger.info(f"Index is insertable for {len(normalized_data.data)} ciphertexts, {available_shards} available")
        else:
            available_vectors = self.remaining_insertable_vectors
            if len(normalized_data.data) > available_vectors:
                raise ValueError(f"Index is not insertable for {len(normalized_data.data)} vectors, {available_vectors} available")
            else:
                logger.info(f"Index is insertable for {len(normalized_data.data)} vectors, {available_vectors} available")

        # Resolve encryptor: Cipher → extract _encryptor, Encryptor → use directly
        resolved_encryptor = None
        if encryptor is not None:
            if isinstance(encryptor, Cipher):
                resolved_encryptor = encryptor._encryptor
            else:
                resolved_encryptor = encryptor

        stage_order = {"flush": 1, "segmentation": 2}
        if execute_until not in stage_order:
            raise ValueError("execute_until must be one of: 'flush', 'segmentation'")
        if await_completion is not None and not isinstance(await_completion, bool):
            raise TypeError("await_completion must be a bool when provided")
        if load is not None and not isinstance(load, bool):
            raise TypeError("load must be a bool")
        if not isinstance(use_row_insert, bool):
            raise TypeError("use_row_insert must be a bool")

        # Prepare out_request_ids list to capture server-generated request IDs
        out_request_ids = request_ids
        if out_request_ids is None and execute_until in ("flush", "segmentation"):
            out_request_ids = []

        if out_request_ids is not None:
            if not isinstance(out_request_ids, list):
                raise TypeError("request_ids must be a list[str]")
            out_request_ids.clear()

        item_ids = self._insert_bulk(
            normalized_data,
            metadata=metadata,
            use_row_insert=use_row_insert,
            out_request_ids=out_request_ids,
            encryptor=resolved_encryptor,
        )

        if execute_until in ("segmentation") and out_request_ids:
            self.indexer.async_merge_by_request_ids(
                self.index_config.index_name,
                out_request_ids,
            )

        if await_completion:
            timeout_s = kwargs.get("timeout_s", 86400.0)
            poll_interval_s = kwargs.get("poll_interval_s", 1.0)
            logger.debug(f"Async data insertion submitted. Waiting until '{execute_until}'.")
            if out_request_ids:
                self._wait_for_insert_stage(
                    request_ids=out_request_ids,
                    target_stage=execute_until,
                    timeout_s=timeout_s,
                    poll_interval_s=poll_interval_s,
                )
            else:
                logger.warning("await_completion requested but no request_ids were captured; skipping wait.")

        if load:
            self.load()
        self._refresh_loaded_state()
        logger.debug("Data insertion completed successfully.")
        return item_ids

    def delete(
        self,
        item_ids: List[int],
        await_completion: bool = True,
        timeout_s: float = 600.0,
        poll_interval_s: float = 1.0,
    ) -> str:
        """
        Deletes items from the index by item ID.

        The server rebuilds affected shards excluding the deleted items. This operation
        is asynchronous — by default the SDK polls until the shard rebuild is complete
        and the remaining data becomes searchable.

        Parameters
        ----------
        item_ids : List[int]
            List of item IDs to delete. These must be ``item_id`` values originally
            returned by ``Index.insert()`` or the low-level insert APIs
            (``Indexer.insert_data_bulk()``, ``Indexer.insert_data_rows_batch()``).
            Must be non-empty, contain only positive integers, and have no duplicates.
        await_completion : bool, optional
            If ``True`` (default), poll ``get_index_operation_status`` with
            ``operation_type=DELETE`` until the operation reaches SEARCHABLE state.
            If ``False``, return immediately after submitting the request.
        timeout_s : float, optional
            Maximum time to wait for completion (seconds). Only used when
            ``await_completion=True``. Default: 600s.
        poll_interval_s : float, optional
            Poll interval (seconds). Only used when ``await_completion=True``. Default: 1s.

        Returns
        -------
        str
            Server-generated ``request_id`` for tracking operation completion.

        Raises
        ------
        ValueError
            If the index is not loaded.
        EnvectorValidationError
            If ``item_ids`` is empty, contains duplicates, or contains non-positive values.
        EnvectorTimeoutError
            If ``await_completion=True`` and the operation does not complete within ``timeout_s``.

        Examples
        --------
        >>> # Insert data and capture item IDs
        >>> item_ids = index.insert(data=vectors, metadata=metadata)
        >>> # Delete specific items (waits for completion by default)
        >>> request_id = index.delete(item_ids=[item_ids[0], item_ids[2]])
        >>> # Delete without waiting
        >>> request_id = index.delete(item_ids=[item_ids[1]], await_completion=False)
        """
        if not self.is_loaded:
            raise ValueError("Index not loaded. Please call Index.load() first.")
        if not isinstance(await_completion, bool):
            raise TypeError("await_completion must be a bool")

        # item_ids: values returned by InsertData response (Index.insert() or Indexer.insert_data_bulk(), etc.)
        # Validation is performed inside indexer.delete_data()
        request_id = self.indexer.delete_data(
            index_name=self.index_config.index_name,
            item_ids=item_ids,
        )

        if await_completion:
            logger.debug(f"DeleteData submitted. Waiting for completion (timeout={timeout_s}s).")
            self.indexer.wait_for_delete_completion(
                index_name=self.index_config.index_name,
                request_id=request_id,
                timeout_s=timeout_s,
                poll_interval_s=poll_interval_s,
            )
            logger.debug("DeleteData completed successfully.")

        return request_id

    def _wait_for_insert_stage(
        self,
        request_ids: List[str],
        target_stage: str,
        timeout_s: float,
        poll_interval_s: float,
    ) -> None:
        target_state_map = {
            "flush": envector_op_pb2.SPLIT_COMPLETED,
            "segmentation": envector_op_pb2.MERGED_SAVED,
        }
        target_state = target_state_map[target_stage]

        _ = self.indexer.wait_for_index_operations_state(
            self.index_config.index_name,
            request_ids,
            target_state=target_state,
            timeout_s=timeout_s,
            poll_interval_s=poll_interval_s,
        )

    def _normalize_insert_data(
        self,
        data: Union[CipherBlock, List[float], List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
    ) -> _NormalizedInsertData:
        """Normalizes insert input into a single internal structure."""
        normalized = self._validate_insert_data(data)
        is_cipher_data = isinstance(normalized, list) and normalized and isinstance(normalized[0], CipherBlock)
        return _NormalizedInsertData(kind="cipher" if is_cipher_data else "plain", data=normalized)

    def _validate_insert_data(
        self,
        data: Union[CipherBlock, List[float], List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
    ) -> Union[np.ndarray, List[CipherBlock]]:
        """
        Validates and normalizes insert data format and dimension.

        Parameters
        ----------
        data : CipherBlock, list of floats, list of lists, list of np.ndarray, 2D np.ndarray, or list of CipherBlock
            Data to be validated. Single vectors (list of floats or 1D numpy array) are
            automatically wrapped into batch format.

        Returns
        -------
        Union[np.ndarray, List[CipherBlock]]
            Normalized data in batch format.
            Plain vectors are always returned as a 2D numpy array.
            Cipher vectors are always returned as list[CipherBlock].

        Raises
        ------
        ValueError
            If data is empty, has wrong dimension, mixes plain/cipher input, or is in an unsupported format.
        """
        # Handle single CipherBlock - wrap to list for unified downstream processing.
        if isinstance(data, CipherBlock):
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Index encryption must be enabled to insert CipherBlock data.")
            return [data]

        # Check for empty data
        if isinstance(data, np.ndarray):
            if data.size == 0:
                raise ValueError("Data cannot be empty.")
        elif not data:
            raise ValueError("Data cannot be empty.")

        # Handle 1D numpy array (single vector) - wrap it
        if isinstance(data, np.ndarray) and data.ndim == 1:
            if data.shape[0] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {data.shape[0]} does not match index dimension {self.index_config.dim}."
                )
            return data.reshape(1, -1)

        # Handle 2D numpy array
        if isinstance(data, np.ndarray) and data.ndim == 2:
            if data.shape[1] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {data.shape[1]} does not match index dimension {self.index_config.dim}."
                )
            return data

        if not isinstance(data, list):
            raise ValueError(
                "Data must be a CipherBlock, list of floats, list of lists, numpy arrays, 2D numpy array, or list of CipherBlock."
            )

        # Handle single vector as list of floats - wrap it
        if data and isinstance(data[0], (int, float, np.floating, np.integer)):
            if len(data) != self.index_config.dim:
                raise ValueError(f"Data dimension {len(data)} does not match index dimension {self.index_config.dim}.")
            return np.asarray(data).reshape(1, -1)

        has_cipherblock = any(isinstance(item, CipherBlock) for item in data)
        if has_cipherblock:
            if not all(isinstance(item, CipherBlock) for item in data):
                raise ValueError("Data cannot mix CipherBlock and plaintext vectors in a single insert call.")
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Index encryption must be enabled to insert CipherBlock data.")
            has_centroids_idx = [block.centroids_idx is not None for block in data]
            if any(has_centroids_idx) and not all(has_centroids_idx):
                raise ValueError("centroids_idx must be present on all CipherBlocks or none.")
            if all(has_centroids_idx):
                for block in data:
                    if block.num_vectors != len(block.centroids_idx):
                        raise ValueError("The length of centroids_idx must equal num_vectors.")
            return data

        # Handle list of list vectors
        if isinstance(data[0], list):
            arr = np.asarray(data)
            if arr.ndim != 2 or arr.shape[1] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {arr.shape[1] if arr.ndim == 2 else 'invalid'} does not match index dimension {self.index_config.dim}."
                )
            return arr

        # Handle list of numpy arrays
        if isinstance(data[0], np.ndarray):
            arr = np.asarray(data)
            if arr.ndim != 2 or arr.shape[1] != self.index_config.dim:
                raise ValueError(
                    f"Data dimension {arr.shape[1] if arr.ndim == 2 else 'invalid'} does not match index dimension {self.index_config.dim}."
                )
            return arr

        raise ValueError(
            "Data must be a CipherBlock, list of floats, list of lists, numpy arrays, 2D numpy array, or list of CipherBlock."
        )

    def _encrypt_metadata_list(self, metadata: List[Any]) -> List[Any]:
        """Encrypts metadata if metadata encryption is enabled."""
        if self.index_config.metadata_encryption:
            if self._is_kms_managed_mode():
                plaintext_metadata = [self._stringify_metadata_value(m) for m in metadata]
                encrypted_metadata = self.kms_client.encrypt_metadata(self.index_config.key_id, plaintext_metadata)
                return [base64.b64encode(item).decode("ascii") for item in encrypted_metadata]
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

    def _is_kms_managed_mode(self) -> bool:
        return self.kms_client is not None

    @staticmethod
    def _stringify_metadata_value(metadata: Any) -> str:
        if metadata is None:
            return ""
        if isinstance(metadata, bytes):
            return metadata.decode("utf-8", errors="ignore")
        if isinstance(metadata, (dict, list)):
            return json.dumps(metadata, ensure_ascii=False)
        return str(metadata)

    @staticmethod
    def _parse_kms_plaintext_metadata(metadata: str) -> Any:
        if metadata is None:
            return None
        try:
            return json.loads(metadata)
        except Exception:
            return metadata

    @staticmethod
    def _metadata_payload(entry: Any) -> Any:
        if hasattr(entry, "data"):
            return entry.data
        return getattr(entry, "infos", None)

    def _kms_topk(self, result_ctxt: CipherBlock, top_k: int):
        encrypted_scores = [
            common_type_pb2.EVCiphertext(degree=score.degree, data=score.data) for score in result_ctxt.data.ctxt_score
        ]
        shard_indices = list(getattr(result_ctxt.data, "shard_idx", []))
        return self.kms_client.topk(
            key_id=self.index_config.key_id,
            encrypted_scores=encrypted_scores,
            k=top_k,
            shard_indices=shard_indices or None,
        )

    def _multiquery_get_topk_metadata_results_via_kms(
        self, results: List[CipherBlock], top_k: int, output_fields: List[str] = None
    ):
        ranked_results_list = []
        topk_indices_list = []

        for result in results:
            ranked_results = self._kms_topk(result, top_k)
            ranked_results_list.append(ranked_results)
            for ranked in ranked_results:
                metadata_idx = ranked.metadata_idx
                topk_indices_list.append(
                    {
                        "shard_idx": metadata_idx.shard_idx,
                        "row_idx": metadata_idx.row_idx,
                    }
                )

        metadata_result = self.indexer.get_metadata(
            self.index_config.index_name, topk_indices_list, fields=output_fields
        )

        if len(metadata_result) != len(topk_indices_list):
            raise ValueError(
                f"Metadata count mismatch: requested {len(topk_indices_list)}, received {len(metadata_result)}"
            )

        decrypted_metadata = None
        if self.index_config.metadata_encryption:
            encrypted_metadata = []
            encrypted_positions = []
            for i, item in enumerate(metadata_result):
                payload = self._metadata_payload(item)
                if not payload:
                    continue
                encrypted_metadata.append(base64.b64decode(payload))
                encrypted_positions.append(i)

            decrypted_metadata = [None] * len(metadata_result)
            if encrypted_metadata:
                plaintext_metadata = self.kms_client.decrypt_metadata(self.index_config.key_id, encrypted_metadata)
                for i, plaintext in zip(encrypted_positions, plaintext_metadata):
                    decrypted_metadata[i] = self._parse_kms_plaintext_metadata(plaintext)

        output_result_list = []
        offset = 0
        for ranked_results in ranked_results_list:
            n = len(ranked_results)
            output_result = []
            for i in range(n):
                metadata_entry = metadata_result[i + offset]
                payload = self._metadata_payload(metadata_entry)
                metadata_value = payload
                if self.index_config.metadata_encryption:
                    metadata_value = decrypted_metadata[i + offset]
                output_result.append(
                    {
                        "id": metadata_entry.id,
                        "score": ranked_results[i].score,
                        "metadata": metadata_value,
                    }
                )
            output_result_list.append(output_result)
            offset += n

        ranked_results_list.clear()
        topk_indices_list.clear()
        if hasattr(metadata_result, "clear"):
            metadata_result.clear()
        del metadata_result

        return output_result_list

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

    @staticmethod
    def _extend_item_ids(item_ids: List[Any], item_id_chunk: Optional[List[Any]]) -> None:
        """Append chunk item IDs while preserving existing duplicate-guard behavior."""
        if item_id_chunk and (not item_ids or item_ids[-len(item_id_chunk) :] != item_id_chunk):
            item_ids.extend(item_id_chunk)

    def _insert_chunk(
        self,
        data_chunk: CipherBlock,
        metadata: List[any] = None,
        out_request_ids: Optional[List[str]] = None,
    ):
        """Inserts a single data chunk (CipherBlock) and its metadata into the indexer."""
        input_metadata = self._prepare_metadata_for_chunk(metadata, data_chunk.num_item_list)
        centroid_idx = data_chunk.centroids_idx
        if self.index_config.index_type.upper() in _IVF_INDEX_TYPES and centroid_idx is None:
            raise ValueError("IVF insert requires centroids_idx in CipherBlock.")

        item_ids = self.indexer.async_persist_data_bulk(
            self.index_config.index_name,
            data_chunk.data,
            data_chunk.num_item_list,
            input_metadata,
            centroid_idx,
            out_request_id=out_request_ids,
        )
        self.num_entities += data_chunk.num_vectors
        return item_ids

    def _insert_row(
        self,
        data_chunk: CipherBlock,
        metadata: List[any] = None,
        out_request_ids: Optional[List[str]] = None,
    ):
        """Inserts a single data chunk (CipherBlock) and its metadata into the indexer."""
        enc_vecs = data_chunk.data
        metadata_list = [metadata[i] if metadata and i < len(metadata) else "" for i in range(len(enc_vecs))]
        cluster_ids = data_chunk.centroids_idx
        if self.index_config.index_type.upper() in _IVF_INDEX_TYPES and cluster_ids is None:
            raise ValueError("IVF insert requires centroids_idx in CipherBlock.")
        result = self.indexer.async_persist_data_rows_batch(
            self.index_config.index_name,
            enc_vecs,
            metadata_list,
            cluster_ids,
            out_request_id=out_request_ids,
        )

        self.num_entities += len(enc_vecs)
        return result

    def _insert_ivf_bulk(
        self,
        normalized_data: _NormalizedInsertData,
        metadata: List[any] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
    ):
        """
        Bulk inserts data into the index for IVF-FLAT.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        data = normalized_data.data

        # Insert Bulk
        item_ids = []  # placeholder for return value

        if normalized_data.kind == "cipher":
            num_total_vectors = sum(chunk.num_vectors for chunk in data)
            if metadata and num_total_vectors != len(metadata):
                raise ValueError("Metadata length does not match the total number of entities.")

            metadata_offset = 0
            for data_chunk in tqdm(data, desc="Insert CipherBlock IVF Bulk"):
                if metadata:
                    num_chunk_entities = data_chunk.num_vectors
                    metadata_chunk = metadata[metadata_offset : metadata_offset + num_chunk_entities]
                    metadata_offset += num_chunk_entities
                else:
                    metadata_chunk = None

                item_id_chunk = self._insert_chunk(
                    data_chunk,
                    metadata_chunk,
                    out_request_ids=out_request_ids,
                )
                self._extend_item_ids(item_ids, item_id_chunk)

            logger.debug("IVF pre-encrypted data insertion completed successfully.")
            return item_ids
        if self.index_config.index_encryption not in ["cipher", "hybrid"]:
            raise ValueError("Received unencrypted data, but index encryption is disabled.")

        close_idxs = self._knn(data, k=1)
        close_idxs = [
            idx[0] if isinstance(idx, (list, np.ndarray)) else (idx.item() if isinstance(idx, np.generic) else idx)
            for idx in close_idxs
        ]

        num_items = len(data)
        for i in range(0, num_items, ENCRYPTION_BATCH_SIZE):
            batch_num = i // ENCRYPTION_BATCH_SIZE
            end_idx = min(i + ENCRYPTION_BATCH_SIZE, num_items)
            raw_data_chunk = list(data[i:end_idx])
            metadata_chunk = metadata[i:end_idx] if metadata else None
            centroid_idx_chunk = close_idxs[i:end_idx]
            try:
                item_id_chunk = self._encrypt_and_insert(
                    raw_data_chunk,
                    metadata_chunk,
                    centroid_idx=centroid_idx_chunk,
                    use_row_insert=use_row_insert,
                    out_request_ids=out_request_ids,
                    encryptor=encryptor,
                )
                self._extend_item_ids(item_ids, item_id_chunk)
            except Exception as e:
                raise RuntimeError(f"Batch {batch_num} insert failed: {e}") from e

        logger.debug("IVF Data insertion completed successfully.")
        return item_ids

    def _encrypt_and_insert(
        self,
        data_chunk: Union[List[any], np.ndarray],
        metadata_chunk: List[any] = None,
        centroid_idx: Optional[List[int]] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
    ):
        """Encrypts and inserts a data chunk into the indexer."""
        cipher = self.cipher if encryptor is None else None
        enc = encryptor or self.cipher._encryptor

        # check data chunk size
        if (isinstance(data_chunk, np.ndarray) and data_chunk.ndim == 1) or (
            isinstance(data_chunk, list) and isinstance(data_chunk[0], (int, float, np.floating, np.integer))
        ):
            num_data = 1
        else:
            num_data = len(data_chunk)
        # Encrypt data chunk in row
        if use_row_insert and num_data < self.index_config.dim:
            if cipher is not None:
                encrypted_chunk = cipher.encrypt_row(data_chunk, encode_type="item", centroids_idx=centroid_idx)
            else:
                encrypted_chunk = CipherBlock(
                    data=enc.encrypt_row(data_chunk, "item"),
                    enc_type="single",
                    centroids_idx=centroid_idx,
                )
            return self._insert_row(
                encrypted_chunk,
                metadata_chunk,
                out_request_ids=out_request_ids,
            )
        # Encrypt data chunk in bulk
        if cipher is not None:
            encrypted_chunk = cipher.encrypt_multiple(data_chunk, encode_type="item", centroids_idx=centroid_idx)
        else:
            encrypted_chunk = CipherBlock(
                data=enc.encrypt_multiple(data_chunk, "item"),
                enc_type="multiple",
                centroids_idx=centroid_idx,
            )
        return self._insert_chunk(
            encrypted_chunk,
            metadata_chunk,
            out_request_ids=out_request_ids,
        )

    def _insert_flat_bulk(
        self,
        normalized_data: _NormalizedInsertData,
        metadata: List[any] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
    ):
        """
        Bulk inserts data into the index.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        data = normalized_data.data

        # Insert Bulk
        item_ids = []  # placeholder for return value

        # Case 1: Data is not encrypted (raw data)
        if normalized_data.kind == "plain":
            if self.index_config.index_encryption not in ["cipher", "hybrid"]:
                raise ValueError("Received unencrypted data, but index encryption is disabled.")

            num_items = data.shape[0] if isinstance(data, np.ndarray) else len(data)
            logger.debug(f"Bulk encrypting {num_items} entities for index '{self.index_config.index_name}'.")
            for i in tqdm(range(0, num_items, ENCRYPTION_BATCH_SIZE), desc="Encrypt and Insert"):
                end_idx = min(i + ENCRYPTION_BATCH_SIZE, num_items)
                raw_data_chunk = list(data[i:end_idx]) if isinstance(data, np.ndarray) else data[i:end_idx]
                metadata_chunk = metadata[i:end_idx] if metadata else None
                item_id_chunk = self._encrypt_and_insert(
                    raw_data_chunk,
                    metadata_chunk,
                    use_row_insert=use_row_insert,
                    out_request_ids=out_request_ids,
                    encryptor=encryptor,
                )
                self._extend_item_ids(item_ids, item_id_chunk)

        # Case 2: Data is already a list of CipherBlock objects
        else:
            cipher_data = data if isinstance(data, list) else [data]
            num_total_vectors = sum(chunk.num_vectors for chunk in cipher_data)
            if metadata and num_total_vectors != len(metadata):
                raise ValueError("Metadata length does not match the total number of entities.")

            metadata_offset = 0
            for data_chunk in tqdm(cipher_data, desc="Insert CipherBlock Bulk"):
                if metadata:
                    num_chunk_entities = data_chunk.num_vectors
                    metadata_chunk = metadata[metadata_offset : metadata_offset + num_chunk_entities]
                    metadata_offset += num_chunk_entities
                else:
                    metadata_chunk = None

                item_id_chunk = self._insert_chunk(
                    data_chunk,
                    metadata_chunk,
                    out_request_ids=out_request_ids,
                )
                item_ids.extend(item_id_chunk)

        logger.debug("FLAT Data insertion completed successfully.")
        return item_ids

    def _insert_bulk(
        self,
        normalized_data: _NormalizedInsertData,
        metadata: List[any] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
    ):
        """
        Bulk inserts data into the index.
        If the data is not encrypted, it will be encrypted before insertion.
        """
        # Metadata Encryption if needed
        if metadata and self.index_config.metadata_encryption:
            metadata = self._encrypt_metadata_list(metadata)

        # Before insert get index info
        if self.index_config.index_type.upper() == "IVF_FLAT" or self.index_config.index_type.upper() == "IVF_VCT":
            return self._insert_ivf_bulk(
                normalized_data,
                metadata=metadata,
                use_row_insert=use_row_insert,
                out_request_ids=out_request_ids,
                encryptor=encryptor,
            )
        elif self.index_config.index_type.upper() == "FLAT":
            return self._insert_flat_bulk(
                normalized_data,
                metadata=metadata,
                use_row_insert=use_row_insert,
                out_request_ids=out_request_ids,
                encryptor=encryptor,
            )
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
        if len(result_ctxt_list) == 0:
            return []
        if self._is_kms_managed_mode():
            output_result_list = self._multiquery_get_topk_metadata_results_via_kms(
                result_ctxt_list, top_k, output_fields
            )
            result_ctxt_list.clear()
            del result_ctxt_list
            return output_result_list
        result_list = [self.decrypt_score(result_ctxt) for result_ctxt in result_ctxt_list]
        result_ctxt_list.clear()
        del result_ctxt_list

        output_result_list = self._multiquery_get_topk_metadata_results(result_list, top_k, output_fields)
        result_list.clear()
        del result_list
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
        plain_query_level = (
            0
            if str(self.index_config.eval_mode).upper() in ("MM", "MMS", "MM32", "MMS32")
            else self.index_config.level
        )
        if self.index_config.index_type == "IVF_FLAT":
            self._ensure_ivf_runtime_metadata_loaded(require_centroids=True)
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
                    encrypted_query = [self.cipher.encrypt_query(i) for i in query]

                    search_topk = self._knn(query, k=nprobe)

                else:
                    raise Exception("IVF_FLAT need to closet centriod info before encryption")

                # FIX: Replace assert with explicit validation (asserts can be disabled with -O flag)
                if nprobe != len(search_topk[0]):
                    raise ValueError(f"nprobe mismatch: expected {nprobe}, got {len(search_topk[0])}")
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

                # FIX: Replace assert with explicit validation (asserts can be disabled with -O flag)
                if nprobe != len(search_topk[0]):
                    raise ValueError(f"nprobe mismatch: expected {nprobe}, got {len(search_topk[0])}")
                logger.debug(f"Search on {nprobe} clusters by IVF-FLAT: {search_topk}")

                result_ctxt = self.indexer.search(
                    self.index_config.index_name,
                    query,
                    topk=search_topk,
                    nprobe=nprobe,
                    level=plain_query_level,
                )

        elif self.index_config.index_type == "IVF_VCT":
            self._ensure_ivf_runtime_metadata_loaded()
            if self.index_config.query_encryption in ["plain"]:  # PC
                nprobe = (
                    search_params.get("nprobe", self.index_config.index_param.default_nprobe)
                    if search_params
                    else self.index_config.index_param.default_nprobe
                )
                logger.debug(f"Search on {nprobe} clusters by IVF-VCT")
                result_ctxt = self.indexer.search(
                    self.index_config.index_name,
                    query,
                    nprobe=nprobe,
                    level=plain_query_level,
                )
            else:
                raise ValueError(f"Query encryption type '{self.index_config.query_encryption}' not supported.")

        else:
            if self.index_config.query_encryption in ["cipher"]:  # CC
                # Encrypt multiple queries for each, if query was plaintext
                if (
                    isinstance(query, List) and query and isinstance(query[0], List) and isinstance(query[0][0], float)
                ) or (isinstance(query, List) and isinstance(query[0], np.ndarray)):
                    encrypted_query = [self.cipher.encrypt_query(i) for i in query]
                else:
                    encrypted_query = query
                # Do search with encrypted queries
                result_ctxt = self.indexer.encrypted_search(self.index_config.index_name, encrypted_query)
            else:  # PC
                # Do search with plain queries
                result_ctxt = self.indexer.search(
                    self.index_config.index_name,
                    query,
                    level=plain_query_level,
                )
        result = [CipherBlock(result) for result in result_ctxt]
        if hasattr(result_ctxt, "clear"):
            result_ctxt.clear()
        del result_ctxt

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
        if self._is_kms_managed_mode() and isinstance(result, CipherBlock):
            result = self._multiquery_get_topk_metadata_results_via_kms(
                results=[result], top_k=top_k, output_fields=output_fields
            )[0]
        else:
            result = self._multiquery_get_topk_metadata_results(
                results=[result], top_k=top_k, output_fields=output_fields
            )[0]
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

        if len(metadata_result) != len(topk_indices_list):
            raise ValueError(
                f"Metadata count mismatch: requested {len(topk_indices_list)}, received {len(metadata_result)}"
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

        # Release intermediate containers before returning.
        topk_result_list.clear()
        topk_indices_list.clear()
        if hasattr(metadata_result, "clear"):
            metadata_result.clear()
        del metadata_result

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
        if self._is_kms_managed_mode():
            raise NotImplementedError(
                "Index.decrypt_score() is not supported in KMS-managed mode. "
                "Use Index.search(), Index.get_topk_metadata_results() with CipherBlock, or KMSClient.topk()."
            )
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

        This call is also used to publish pending merged shards for indexes that are
        already loaded. Backend ``load_index`` returns an "already loaded" error when
        there is nothing new to publish; that case is treated as a no-op here.

        Returns
        -------
        Index
            The index object after loading it.

        Examples
        --------
        >>> index.load()
        """
        try:
            self.indexer.load_index(self.index_config.index_name)
        except EnvectorApplicationError as exc:
            if not str(exc).startswith("Index already loaded:"):
                raise
            logger.info("Index already loaded with no pending shards. No additional load needed.")
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
        is_loaded = self.indexer.get_index_summary(self.index_config.index_name)["is_loaded"]
        if not is_loaded:
            logger.info("Index already unloaded. No need to unload.")
            if self.is_loaded:
                self._is_loaded = False
            return self
        self.indexer.unload_index(self.index_config.index_name)
        self._is_loaded = False
        return self

    def _refresh_loaded_state(self) -> bool:
        self._is_loaded = self.indexer.get_index_summary(self.index_config.index_name)["is_loaded"]
        return self._is_loaded

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
        self._ensure_ivf_runtime_metadata_loaded(require_centroids=True)
        # FIX: Add null check for centroids (was causing AttributeError instead of helpful message)
        if self.index_config.centroids is None or (
            hasattr(self.index_config.centroids, "size") and self.index_config.centroids.size == 0
        ):
            raise ValueError("Centroids not initialized. Load index metadata first.")
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

    def summary(self):
        """
        Returns a summary of the index.

        Returns
        -------
        Dict
            A dictionary containing the index summary. Capacity-related keys include:
            `can_load_now`,
            `remaining_insertable_shards`,
            `remaining_insertable_vectors_guaranteed`,
            `remaining_insertable_vectors_best_effort`.

        Examples
        --------
        >>> index.summary()
        """
        return self.indexer.get_index_summary(self.index_config.index_name)

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

    @property
    def remaining_insertable_vectors(self) -> int:
        """
        Returns the number of remaining insertable vectors in the index.

        Returns
        -------
        int
            The number of remaining insertable vectors.
        """
        summary = self.indexer.get_index_summary(self.index_config.index_name)
        return summary["remaining_insertable_vectors_guaranteed"]

    @property
    def remaining_insertable_shards(self) -> int:
        """
        Returns the number of remaining insertable shards in the index.

        Returns
        -------
        int
            The number of remaining insertable shards.
        """
        summary = self.indexer.get_index_summary(self.index_config.index_name)
        return summary["remaining_insertable_shards"]

    @property
    def loadable(self) -> bool:
        """
        Checks if the index is loadable.

        Returns
        -------
        bool
            True if the index is loadable, False otherwise.
        """
        summary = self.indexer.get_index_summary(self.index_config.index_name)
        return summary["can_load_now"]

    def __repr__(self):
        return (
            "Index(\n"
            f"  {repr(self.index_config)},\n"
            f"  num_entities={self.num_entities},\n"
            f"  cipher={self.cipher if self.cipher else None}\n"
            ")"
        )
