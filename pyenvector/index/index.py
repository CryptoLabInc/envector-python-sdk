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
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional, Union

import numpy as np
from threadpoolctl import threadpool_limits
from tqdm import tqdm

from pyenvector.api import Indexer
from pyenvector.crypto.block import CipherBlock
from pyenvector.crypto.cipher import Cipher
from pyenvector.crypto.parameter import ContextParameter, IndexParameter, KeyParameter, SealInfo
from pyenvector.errors import EnvectorApplicationError, EnvectorValidationError
from pyenvector.proto_gen.v2.common import index_operation_message_pb2 as envector_op_pb2
from pyenvector.proto_gen.v2.common import type_pb2 as common_type_pb2
from pyenvector.utils.aes import decrypt_metadata, encrypt_metadata, resolve_metadata_key
from pyenvector.utils.logging_config import logger
from pyenvector.utils.utils import topk

ENCRYPTION_BATCH_SIZE = 4096
KNN_BATCH_SIZE_MAX = 4096
# Caps the (batch, nlist) float32 score matrix in _knn; prevents OOM at large nlist (e.g., face-recognition ~60k).
KNN_DIST_MATRIX_BUDGET_BYTES = 32 * 1024 * 1024
MAX_REQUEST_ID_LENGTH = 30
_IVF_INDEX_TYPES: frozenset = frozenset({"IVF_FLAT", "IVF_VCT"})
AccessTokenInput = Optional[Union[str, Callable[[], Optional[str]]]]


@dataclass
class _NormalizedInsertData:
    """Internal normalized representation for insert input."""

    kind: str  # "plain" or "cipher"
    data: Union[List[Any], np.ndarray]


@dataclass
class SealedBlob:
    """AES pre-encrypted payload sealed to the server — opaque storage only.

    Wraps the output of AES encryption (e.g. ``KMSClient.encrypt_metadata`` or
    ``encrypt_metadata``) and signals ``Index.insert()`` to skip re-encryption.
    The server stores the ciphertext as-is; only the client can decrypt it.
    Contrast with ``CipherBlock`` / ``CipherText`` where the server can perform
    homomorphic computation on the ciphertext.

    Accepted forms:

    - ``KMSClient.encrypt_metadata`` → raw ``bytes``; the SDK Base64-wraps it
      to match the stored wire format.
    - ``encrypt_metadata`` → already a Base64 ``str``; stored as-is.

    Has no effect when ``metadata_encryption`` is disabled on the index.

    Examples
    --------
    >>> raw_cts = kms_client.encrypt_metadata(key_id, plaintext_metas)
    >>> index.insert(data, [SealedBlob(ct) for ct in raw_cts])
    """

    ciphertext: Union[str, bytes, bytearray]

    def __post_init__(self):
        if not isinstance(self.ciphertext, (str, bytes, bytearray)):
            raise TypeError(
                f"SealedBlob expects str/bytes/bytearray, got {type(self.ciphertext).__name__}"
            )


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
        # Carry existing params forward so a type swap doesn't drop IVF settings (nlist/nprobe).
        index_params = dict(self.index_params)
        index_params["index_type"] = index_type
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
        copied_use_key_stream = self.key_param.use_key_stream if use_key_stream is None else use_key_stream

        def copy_key_stream(explicit_value, key_attr: str):
            if explicit_value is not None:
                return explicit_value
            if not copied_use_key_stream:
                return None
            return getattr(self.key_param, key_attr, None)

        return IndexConfig(
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
            use_key_stream=copied_use_key_stream,
            enc_key=copy_key_stream(enc_key, "enc_key"),
            eval_key=copy_key_stream(eval_key, "eval_key"),
            sec_key=copy_key_stream(sec_key, "sec_key"),
            metadata_key=copy_key_stream(metadata_key, "metadata_key"),
            seal_kek=seal_kek if seal_kek is not None else None,
            key_store=self.key_param.key_store if key_store is None else key_store,
            region_name=self.key_param.region_name if region_name is None else region_name,
            bucket_name=self.key_param.bucket_name if bucket_name is None else bucket_name,
            secret_prefix=self.key_param.secret_prefix if secret_prefix is None else secret_prefix,
            vault_addr=self.key_param.vault_addr if vault_addr is None else vault_addr,
            vault_mount=self.key_param.vault_mount if vault_mount is None else vault_mount,
        )

    def __repr__(self):
        # Fields worth surfacing for a human reading the config. Each value is
        # resolved lazily so a property that raises does not break ``repr``.
        candidates = [
            ("index_name", lambda: self.index_name),
            ("dim", lambda: self.dim),
            ("preset", lambda: self.preset),
            ("eval_mode", lambda: self.eval_mode),
            ("index_type", lambda: self.index_type),
        ]

        # IVF-family indexes carry clustering params worth showing together.
        try:
            is_ivf = "IVF" in (self.index_type or "")
        except Exception:
            is_ivf = False
        if is_ivf:
            candidates += [
                ("nlist", lambda: self.nlist),
                ("default_nprobe", lambda: self.default_nprobe),
            ]

        candidates += [
            ("metadata_encryption", lambda: self.metadata_encryption),
            ("key_id", lambda: self.key_id),
            ("key_path", lambda: self.key_path),
            ("seal_mode", lambda: self.seal_mode),
            ("description", lambda: self.description),
        ]

        fields = []
        for name, getter in candidates:
            try:
                value = getter()
            except Exception:
                value = None
            # Skip unset/irrelevant fields to keep the output focused.
            if value is None:
                continue
            fields.append((name, value))

        if not fields:
            return "IndexConfig()"

        width = max(len(name) for name, _ in fields)
        body = "\n".join(f"    {name:<{width}} = {value!r}" for name, value in fields)
        return f"IndexConfig(\n{body}\n)"


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
        Open an existing index by name.

        Args:
            index_name (str): Name of the index.
            index_config (IndexConfig, optional): Supplies client-side settings (key paths,
                encryption keys, seal mode). Server-owned properties (dim, key_id, nlist, ...) are
                always read from the server; a configured value that differs is ignored with a
                warning. Falls back to ``Index._default_index_config``.
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
        index_config.description = metadata.get("description")
        # Restore metadata_encryption from the server (authoritative). It's a non-optional proto bool,
        # so None only when the generated stub predates the field; then keep config (setter coerces None->True).
        server_metadata_encryption = metadata.get("metadata_encryption")
        if server_metadata_encryption is not None:
            index_config.key_param.metadata_encryption = server_metadata_encryption
        # IVF nlist/default_nprobe are server-owned: take them from the summary when present, warn on
        # mismatch. If the summary omits them (older servers), the setter falls back to configured/default.
        index_params = {"index_type": metadata["index_type"]}
        for name in ("nlist", "default_nprobe"):
            server_val = metadata.get(name)
            configured = index_config.index_params.get(name)
            if server_val:
                index_params[name] = server_val
            if configured and server_val and configured != server_val:
                logger.warning(
                    "Configured %s (%s) for index '%s' differs from server (%s); using server value.",
                    name,
                    configured,
                    index_name,
                    server_val,
                )
        index_config.index_param.index_params = index_params
        # preset/eval_mode aren't in the summary; restore from the key (authoritative), best-effort, atomically.
        try:
            key_info = indexer.get_key_info(metadata["key_id"])
        except Exception:
            key_info = None
            logger.debug(
                "get_key_info failed for key_id=%s; keeping configured preset/eval_mode",
                metadata["key_id"],
            )
        if key_info:
            key_preset = key_info.get("preset")
            key_eval_mode = key_info.get("eval_mode")
            if isinstance(key_preset, str) and key_preset and isinstance(key_eval_mode, str) and key_eval_mode:
                ctx = index_config.context_param
                level = ctx.level if ctx.level_is_explicit else None
                index_config.context_param = ContextParameter(
                    preset=key_preset,
                    dim=index_config.dim,
                    eval_mode=key_eval_mode,
                    level=level,
                )
        self.index_config = index_config
        self._ivf_centroids_loaded = False
        self.num_entities = metadata["row_count"]
        # Guards num_entities accumulation when sends run on the parallel pool.
        self._num_entities_lock = threading.Lock()
        self.kms_client = Index._default_kms_client
        self.cipher = Cipher._create_from_index_config(self.index_config) if self.index_config.need_cipher else None
        self._is_loaded = metadata["is_loaded"]

    def _ensure_ivf_centroids_loaded(self, require_centroids: bool = False) -> None:
        """Load IVF centroids lazily on first use (nlist/default_nprobe come from the summary)."""
        index_type = self.index_config.index_type
        if index_type not in ("IVF_FLAT", "IVF_VCT"):
            return
        # Centroids are needed for IVF_FLAT, and for any IVF type when require_centroids is set
        # (e.g. _knn during an IVF_VCT insert).
        if self._ivf_centroids_loaded or not (index_type == "IVF_FLAT" or require_centroids):
            return

        metadata = self.indexer.get_index_info(self.index_config.index_name)
        ivf_detail = metadata.get("ivf_detail")
        if ivf_detail is None:
            raise ValueError(
                f"IVF metadata for index '{self.index_config.index_name}' is unavailable from get_index_info()."
            )
        if not getattr(ivf_detail, "centroids", None):
            raise ValueError(
                f"Centroids for {index_type} index '{self.index_config.index_name}' are missing from index detail."
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
        create_kwargs = dict(
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
        active_indexer.create_index(**create_kwargs)
        return cls(index_config.index_name, index_config)

    def indexing(
        self,
        request_ids: Optional[List[str]] = None,
    ):
        self.indexer.async_merge_by_request_ids(
            self.index_config.index_name,
            request_ids,
        )

    def create_partition(self, partition_name: str):
        """Create a named partition in this index.

        A partition is an isolated subset of the index; pass its name to
        ``insert(partition_name=...)`` to route data into it, and to
        ``search(partition_names=[...])`` to scope a query to it. The reserved
        ``_default`` partition is created automatically with the index.

        Parameters
        ----------
        partition_name : str
            Name of the partition to create. Must not be ``_default`` and must
            not already exist.
        """
        return self.indexer.create_partition(self.index_config.index_name, partition_name)

    def drop_partition(self, partition_name: str):
        """Drop a named partition from this index (its data is removed).

        ``_default`` cannot be dropped. Mirrors the module-level
        ``drop_partition`` / ``client`` API at the index-instance level.
        """
        return self.indexer.drop_partition(self.index_config.index_name, partition_name)

    def list_partitions(self):
        """List this index's partitions as dicts ``{name, status, num_vectors}``."""
        return self.indexer.list_partitions(self.index_config.index_name)

    def insert(
        self,
        data: Union[CipherBlock, List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
        metadata: Union[List[Any], List["SealedBlob"], None] = None,
        request_ids: Optional[List[str]] = None,
        await_completion: bool = False,
        execute_until: str = "segmentation",
        load: bool = True,
        use_row_insert: bool = False,
        encryptor=None,
        n_workers: int = 1,
        partition_name: Optional[str] = None,
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
        metadata : list of Any or list of SealedBlob, optional
            Metadata for the data. To insert pre-encrypted metadata without double encryption,
            wrap each ciphertext in :class:`SealedBlob`::

                raw_cts = kms_client.encrypt_metadata(key_id, plaintext_metas)
                index.insert(data, [SealedBlob(ct) for ct in raw_cts])

            ``SealedBlob`` accepts the direct output of ``KMSClient.encrypt_metadata``
            (raw ``bytes``, Base64-wrapped by the SDK) or ``encrypt_metadata`` (Base64 ``str``,
            stored as-is). The list must be all ``SealedBlob`` or all plain — mixing
            raises ``TypeError``. Has no effect when ``metadata_encryption`` is disabled.
        request_ids : Optional[List[str]], optional
            Out list for server-generated request identifiers (from response ``header.id``).

            - If ``None`` (default), the client does not capture request identifiers and you cannot
              poll completion for this insert.
            - If provided, the list is cleared and filled with the server-generated request IDs
              (one per underlying async split request). These are the split request IDs; use
              them with :meth:`get_index_operation_status` or :meth:`async_merge_by_request_ids`.
        await_completion : bool, optional
            If ``True``, block until the selected server-side stage is reached. ``"flush"``
            waits for ``SPLIT_COMPLETED``; ``"segmentation"`` waits for ``MERGED_SAVED``.
            When ``load=True`` is also set, the SDK then calls :meth:`load` after that stage
            wait completes. The SDK does not perform an additional searchable wait
            automatically; callers needing a ``MERGED_SAVED`` guarantee should pass
            ``await_completion=True``.
        execute_until : str, optional
            Server-side completion stage for this insert. Supported values are:

            - ``"flush"``: stop after split/persist submission
            - ``"segmentation"``: submit ``merge_by_request_ids`` after split request IDs are captured
        load : bool, optional
            If ``True``, call :meth:`load` after submission, or after the selected stage wait
            when ``await_completion=True``. This triggers backend publication work but does not
            add an SDK-side searchable wait on its own. When invoked before merge completion
            (``execute_until="flush"``), backend ``LoadIndex`` may expose raw fallback shards
            while request-scoped merge work is still unfinished.
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
        n_workers : int, optional
            Worker threads used for BOTH chunk encoding and chunk sending
            (results are still consumed in chunk order). Values >1 overlap the
            gRPC round-trips of multiple chunks. Default 1 overlaps one encode
            with one send; each stage holds at most ``n_workers+1`` chunks in
            memory.

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
        metadata = self._normalize_metadata(metadata)

        if self.indexer._is_safe_memory_mode():
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
            n_workers=n_workers,
            partition_name=partition_name,
        )

        if execute_until in ("segmentation") and out_request_ids:
            self.indexer.async_merge_by_request_ids(
                self.index_config.index_name,
                out_request_ids,
                partition_name=partition_name,
            )

        if await_completion:
            timeout_s = kwargs.get("timeout_s", 86400.0)
            poll_interval_s = kwargs.get("poll_interval_s", 1.0)
            logger.debug(f"Async data insertion submitted. Waiting until '{execute_until}'.")
            if out_request_ids:
                self.wait_for_insert_stage(
                    request_ids=out_request_ids,
                    target_stage=execute_until,
                    timeout_s=timeout_s,
                    poll_interval_s=poll_interval_s,
                    partition_name=partition_name,
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
        partition_name: Optional[str] = None,
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
            partition_name=partition_name,
        )

        if await_completion:
            logger.debug(f"DeleteData submitted. Waiting for completion (timeout={timeout_s}s).")
            self.indexer.wait_for_delete_completion(
                index_name=self.index_config.index_name,
                request_id=request_id,
                timeout_s=timeout_s,
                poll_interval_s=poll_interval_s,
                partition_name=partition_name,
            )
            logger.debug("DeleteData completed successfully.")

        return request_id

    def update_metadata(
        self,
        item_ids: List[int],
        metadata: List[Any],
        partition_name: Optional[str] = None,
    ) -> dict:
        """
        Replaces the metadata of existing items by item ID.

        Each item's stored metadata is overwritten WHOLESALE with the value given in
        ``metadata[i]`` — there is no read-modify-write merge. To change a single field
        you must supply the item's full new metadata; any field you omit is dropped. The
        server stores the value opaquely (whole-string replacement); the vector data and
        shards are untouched.

        Concurrency is LAST-WRITER-WINS: there is no optimistic locking, so concurrent
        writers to the same item simply clobber one another — the last write wins.

        Items that are missing or have been (soft-)deleted are skipped and reported,
        not raised (lenient).

        Parameters
        ----------
        item_ids : List[int]
            Item IDs to update (positive, unique). These are values returned by
            ``Index.insert()`` and surfaced as ``id`` in search results.
        metadata : List[Any]
            The full new metadata for each item_id (same order). Each entry replaces
            the item's stored metadata wholesale.

        Returns
        -------
        dict
            ``{"updated": List[int], "skipped": List[int]}`` — item IDs successfully
            updated, and those skipped because they were missing or soft-deleted.

        Raises
        ------
        ValueError
            If the index is not loaded.
        EnvectorValidationError
            If inputs are empty/mismatched, item_ids are non-positive/duplicated, or
            metadata_encryption is enabled but no key is configured.

        Examples
        --------
        >>> item_ids = index.insert(data=vectors, metadata=[{"label": "a", "v": 1}])
        >>> # Wholesale replace: stored metadata becomes exactly {"label": "a", "v": 2}.
        >>> report = index.update_metadata(item_ids=[item_ids[0]], metadata=[{"label": "a", "v": 2}])
        >>> report["updated"], report["skipped"]
        """
        if not self.is_loaded:
            raise ValueError("Index not loaded. Please call Index.load() first.")
        if not item_ids:
            raise EnvectorValidationError(message="item_ids must be non-empty")
        if not isinstance(metadata, (list, tuple)):
            raise EnvectorValidationError(message="metadata must be a list")
        if len(metadata) != len(item_ids):
            raise EnvectorValidationError(message="metadata length must match item_ids length")
        # Wholesale replacement: None would silently clobber the stored value to ""
        # (and behaves differently per mode), so reject it as ambiguous intent.
        if any(m is None for m in metadata):
            raise EnvectorValidationError(message="metadata entries must not be None")
        if not all(isinstance(i, int) and not isinstance(i, bool) for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only int values")
        if not all(i > 0 for i in item_ids):
            raise EnvectorValidationError(message="item_ids must contain only positive integers (> 0)")
        if len(set(item_ids)) != len(item_ids):
            raise EnvectorValidationError(message="item_ids must not contain duplicates")
        if self.index_config.metadata_encryption and not (
            self._is_kms_managed_mode()
            or self.index_config.metadata_key_path
            or self.index_config.metadata_key
        ):
            raise EnvectorValidationError(
                message="metadata_encryption is enabled but no metadata key is configured"
            )

        index_name = self.index_config.index_name
        write_item_ids = list(item_ids)
        write_data = [self._encode_metadata_for_wire(m) for m in metadata]

        resp = self.indexer.update_metadata(index_name, write_item_ids, write_data, partition_name=partition_name)
        server_not_found = set(resp.get("not_found_item_ids", []))
        updated = [iid for iid in write_item_ids if iid not in server_not_found]
        skipped = [iid for iid in write_item_ids if iid in server_not_found]
        return {"updated": updated, "skipped": skipped}

    def all_merged_saved(self, request_ids: List[str]) -> bool:
        """Return True iff every request_id has reached MERGED_SAVED. Non-blocking."""
        for rid in request_ids:
            resp = self.indexer.get_index_operation_status(
                self.index_config.index_name, rid, operation_type="INSERT"
            )
            if resp.state != envector_op_pb2.MERGED_SAVED:
                return False
        return True

    def wait_for_insert_stage(
        self,
        request_ids: List[str],
        target_stage: str,
        timeout_s: float,
        poll_interval_s: float,
        partition_name: Optional[str] = None,
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
            partition_name=partition_name,
        )

    def _normalize_insert_data(
        self,
        data: Union[CipherBlock, List[float], List[List[float]], List[np.ndarray], np.ndarray, List[CipherBlock]],
    ) -> _NormalizedInsertData:
        """Normalizes insert input into a single internal structure."""
        normalized = self._validate_insert_data(data)
        is_cipher_data = isinstance(normalized, list) and normalized and isinstance(normalized[0], CipherBlock)
        return _NormalizedInsertData(kind="cipher" if is_cipher_data else "plain", data=normalized)

    def _normalize_metadata(self, metadata: Optional[List[Any]]) -> Optional[List[Any]]:
        """Normalize metadata list to the stored wire format before insert.

        Items wrapped in ``SealedBlob`` are already encrypted — they are
        converted to the Base64 wire string without a second encryption pass.
        Plain items are encrypted when ``metadata_encryption`` is enabled.

        Raises ``TypeError`` if the list mixes ``SealedBlob`` and plain values,
        or if ``SealedBlob`` is used while ``metadata_encryption`` is disabled.
        """
        if not metadata:
            return metadata

        has_wrapped = any(isinstance(m, SealedBlob) for m in metadata)
        has_plain = any(not isinstance(m, SealedBlob) for m in metadata)

        if has_wrapped and has_plain:
            raise TypeError(
                "metadata list must be all SealedBlob or all plain values, not mixed"
            )

        if has_wrapped:
            if not self.index_config.metadata_encryption:
                raise ValueError(
                    "SealedBlob cannot be used when metadata_encryption is disabled"
                )
            return [
                base64.b64encode(bytes(m.ciphertext)).decode("ascii")
                if isinstance(m.ciphertext, (bytes, bytearray))
                else m.ciphertext
                for m in metadata
            ]

        if self.index_config.metadata_encryption:
            return self._encrypt_metadata_list(metadata)

        return metadata

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
            if not metadata:
                return metadata
            key_source = self.index_config.metadata_key_path or self.index_config.metadata_key
            # Resolve the metadata key once per call; passing the resolved bytes
            # (kek omitted) skips the file read + KeyManager unwrap that would
            # otherwise repeat for every item in the batch.
            key = resolve_metadata_key(key_source, kek=self.index_config.seal_kek_path)
            encrypted_metadata = [encrypt_metadata(m, key) for m in metadata]
            return encrypted_metadata
        return metadata

    def _decrypt_metadata(self, metadata: List[Any], key: Optional[bytes] = None):
        if metadata and self.index_config.metadata_encryption:
            if key is None:
                key_source = self.index_config.metadata_key_path or self.index_config.metadata_key
                key = resolve_metadata_key(key_source, kek=self.index_config.seal_kek_path)
            return decrypt_metadata(metadata, key)
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

    def _encode_metadata_for_wire(self, value: Any) -> str:
        """Serialize one metadata value to the stored wire string per mode
        (encrypted: EVI/KMS envelope; plaintext: str/bytes pass through, else str()).
        Unlike insert, plaintext list/tuple are NOT spread and dict uses repr (not JSON)."""
        if self.index_config.metadata_encryption:
            return self._encrypt_metadata_list([value])[0]
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        if isinstance(value, str):
            return value
        return str(value)

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
        self, results: List[CipherBlock], top_k: int, output_fields: List[str] = None, partition_name: Optional[str] = None
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
            self.index_config.index_name, topk_indices_list, fields=output_fields, partition_name=partition_name
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
                # Backend uses Metadata{Id:0} as a sentinel for slots whose
                # underlying item was soft-deleted between scoring and metadata
                # fetch (DeleteData Phase 1). Drop those positions so callers
                # see only live results — matches the user-visible contract of
                # "top_k may shrink when some hits were just deleted".
                if metadata_entry.id == 0:
                    continue
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
            # Drop id==0 sentinels (DeleteData soft-delete + post-cutover stale coords)
            # and dedup by id since partial-merge can score the same item via raw +
            # merged shards; keep the best score, preserving rank order.
            filtered = []
            seen = {}
            for entry in output_result:
                if entry["id"] == 0:
                    continue
                prev = seen.get(entry["id"])
                if prev is None:
                    seen[entry["id"]] = len(filtered)
                    filtered.append(entry)
                elif entry["score"] > filtered[prev]["score"]:
                    filtered[prev] = entry
            output_result_list.append(filtered)
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
        partition_name: Optional[str] = None,
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
            partition_name=partition_name,
        )
        with self._num_entities_lock:
            self.num_entities += data_chunk.num_vectors
        return item_ids

    def _insert_row(
        self,
        data_chunk: CipherBlock,
        metadata: List[any] = None,
        out_request_ids: Optional[List[str]] = None,
        partition_name: Optional[str] = None,
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
            partition_name=partition_name,
        )

        with self._num_entities_lock:
            self.num_entities += len(enc_vecs)
        return result

    def _insert_ivf_bulk(
        self,
        normalized_data: _NormalizedInsertData,
        metadata: List[any] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
        n_workers: int = 1,
        partition_name: Optional[str] = None,
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
                    partition_name=partition_name,
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

        def make_jobs():
            for i in range(0, num_items, ENCRYPTION_BATCH_SIZE):
                end_idx = min(i + ENCRYPTION_BATCH_SIZE, num_items)
                yield {
                    "data": list(data[i:end_idx]),
                    "metadata": metadata[i:end_idx] if metadata else None,
                    "centroid_idx": close_idxs[i:end_idx],
                    "use_row_insert": use_row_insert,
                    "encryptor": encryptor,
                    "partition_name": partition_name,
                }

        self._pipelined_encrypt_insert(
            make_jobs(),
            item_ids,
            n_workers,
            out_request_ids=out_request_ids,
            wrap_batch_errors=True,
        )

        logger.debug("IVF Data insertion completed successfully.")
        return item_ids

    def _encode_chunk(
        self,
        data_chunk: Union[List[any], np.ndarray],
        centroid_idx: Optional[List[int]] = None,
        use_row_insert: bool = False,
        encryptor=None,
    ):
        """Encodes one data chunk; returns (encrypted_chunk, is_row).
        Thread-safe: the encrypt methods use a fresh native encryptor per call."""
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
            return encrypted_chunk, True
        # Encrypt data chunk in bulk
        if cipher is not None:
            encrypted_chunk = cipher.encrypt_multiple(data_chunk, encode_type="item", centroids_idx=centroid_idx)
        else:
            encrypted_chunk = CipherBlock(
                data=enc.encrypt_multiple(data_chunk, "item"),
                enc_type="multiple",
                centroids_idx=centroid_idx,
            )
        return encrypted_chunk, False

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
        encrypted_chunk, is_row = self._encode_chunk(
            data_chunk,
            centroid_idx=centroid_idx,
            use_row_insert=use_row_insert,
            encryptor=encryptor,
        )
        if is_row:
            return self._insert_row(
                encrypted_chunk,
                metadata_chunk,
                out_request_ids=out_request_ids,
            )
        return self._insert_chunk(
            encrypted_chunk,
            metadata_chunk,
            out_request_ids=out_request_ids,
        )

    def _pipelined_encrypt_insert(
        self,
        jobs: Iterable[dict],
        item_ids: List[Any],
        n_workers: int = 1,
        out_request_ids: Optional[List[str]] = None,
        progress_desc: Optional[str] = None,
        wrap_batch_errors: bool = False,
        total_jobs: Optional[int] = None,
    ):
        """Encodes and sends chunks on two n_workers pools, consuming results in
        chunk order so item_id/request_id order is preserved. Each stage holds at
        most n_workers+1 chunks, bounding in-flight memory.
        """
        n_workers = max(1, n_workers)
        encode_pool = ThreadPoolExecutor(max_workers=n_workers)
        send_pool = ThreadPoolExecutor(max_workers=n_workers)
        encode_pending = deque()  # (idx, job, encode_future)
        send_pending = deque()  # (idx, send_future)
        max_inflight = n_workers + 1
        progress = tqdm(total=total_jobs, desc=progress_desc) if progress_desc else None
        job_iter = iter(enumerate(jobs))
        failed = False

        def fill_encode():
            while len(encode_pending) < max_inflight:
                nxt = next(job_iter, None)
                if nxt is None:
                    return
                idx, job = nxt
                encode_pending.append(
                    (
                        idx,
                        job,
                        encode_pool.submit(
                            self._encode_chunk,
                            job["data"],
                            centroid_idx=job.get("centroid_idx"),
                            use_row_insert=job.get("use_row_insert", False),
                            encryptor=job.get("encryptor"),
                        ),
                    )
                )

        def fail(idx, e):
            nonlocal failed
            failed = True
            if wrap_batch_errors:
                raise RuntimeError(f"Batch {idx} insert failed: {e}") from e
            raise e

        # Cap OpenMP per worker only when fanning out; the default
        # single-worker path keeps today's unrestricted-OpenMP behavior.
        omp_guard = threadpool_limits(limits=1, user_api="openmp") if n_workers > 1 else nullcontext()
        try:
            with omp_guard:
                fill_encode()
                while encode_pending or send_pending:
                    # Hand encoded chunks to the send pool in chunk order,
                    # without letting in-flight sends exceed the cap.
                    while encode_pending and len(send_pending) < max_inflight:
                        idx, job, encode_future = encode_pending.popleft()
                        try:
                            encrypted_chunk, is_row = encode_future.result()
                        except Exception as e:
                            fail(idx, e)
                        send = self._insert_row if is_row else self._insert_chunk
                        # Capture request IDs per chunk and merge them in chunk
                        # order below, so parallel sends stay ordered.
                        chunk_reqs = [] if out_request_ids is not None else None
                        send_pending.append(
                            (idx, chunk_reqs, send_pool.submit(send, encrypted_chunk, job.get("metadata"), out_request_ids=chunk_reqs, partition_name=job.get("partition_name")))
                        )
                        fill_encode()
                    # Collect one finished send in chunk order.
                    idx, chunk_reqs, send_future = send_pending.popleft()
                    try:
                        chunk_ids = send_future.result()
                    except Exception as e:
                        fail(idx, e)
                    self._extend_item_ids(item_ids, chunk_ids)
                    if chunk_reqs:
                        out_request_ids.extend(chunk_reqs)
                    if progress:
                        progress.update(1)
        finally:
            # On failure, don't block the raise on in-flight encodes/sends.
            encode_pool.shutdown(wait=not failed, cancel_futures=True)
            send_pool.shutdown(wait=not failed, cancel_futures=True)
            if progress:
                progress.close()

    def _insert_flat_bulk(
        self,
        normalized_data: _NormalizedInsertData,
        metadata: List[any] = None,
        use_row_insert: bool = False,
        out_request_ids: Optional[List[str]] = None,
        encryptor=None,
        n_workers: int = 1,
        partition_name: Optional[str] = None,
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

            def make_jobs():
                for i in range(0, num_items, ENCRYPTION_BATCH_SIZE):
                    end_idx = min(i + ENCRYPTION_BATCH_SIZE, num_items)
                    yield {
                        "data": list(data[i:end_idx]) if isinstance(data, np.ndarray) else data[i:end_idx],
                        "metadata": metadata[i:end_idx] if metadata else None,
                        "use_row_insert": use_row_insert,
                        "encryptor": encryptor,
                        "partition_name": partition_name,
                    }

            self._pipelined_encrypt_insert(
                make_jobs(),
                item_ids,
                n_workers,
                out_request_ids=out_request_ids,
                progress_desc="Encrypt and Insert",
                total_jobs=(num_items + ENCRYPTION_BATCH_SIZE - 1) // ENCRYPTION_BATCH_SIZE,
            )

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
                    partition_name=partition_name,
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
        n_workers: int = 1,
        partition_name: Optional[str] = None,
    ):
        """
        Bulk inserts data into the index.
        If the data is not encrypted, it will be encrypted before insertion.
        Metadata is expected to be already normalized to wire format by the caller.
        """
        # Partition routing is threaded as an explicit parameter to the send
        # sites (no shared instance state), so concurrent insert() calls on the
        # same Index cannot race on the partition target.
        if self.index_config.index_type.upper() == "IVF_FLAT" or self.index_config.index_type.upper() == "IVF_VCT":
            return self._insert_ivf_bulk(
                normalized_data,
                metadata=metadata,
                use_row_insert=use_row_insert,
                out_request_ids=out_request_ids,
                encryptor=encryptor,
                n_workers=n_workers,
                partition_name=partition_name,
            )
        elif self.index_config.index_type.upper() == "FLAT":
            return self._insert_flat_bulk(
                normalized_data,
                metadata=metadata,
                use_row_insert=use_row_insert,
                out_request_ids=out_request_ids,
                encryptor=encryptor,
                n_workers=n_workers,
                partition_name=partition_name,
            )
        else:
            raise ValueError(f"Index type '{self.index_config.index_type}' not supported for insertion.")

    def search(
        self,
        query: Union[List[float], np.ndarray, List[List[float]], List[np.ndarray], List[CipherBlock]],
        top_k: int,
        output_fields: List[str] = None,
        search_params: dict = None,
        partition_names: Optional[List[str]] = None,
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
        # Multi-partition search: each result must be scored and have its metadata
        # fetched from its own partition's physical index. Run one single-partition
        # search per partition (each already correct end-to-end) and merge the
        # per-partition top-k client-side. Items belong to exactly one partition,
        # so the union has no cross-partition duplicates.
        metadata_partition_name = None
        if partition_names:
            # De-duplicate (order-preserving): a repeated partition name would
            # otherwise be searched twice and double-count its hits in the merge.
            seen = set()
            partition_names = [n for n in partition_names if not (n in seen or seen.add(n))]
            if len(partition_names) > 1:
                return self._search_multi_partition(query, top_k, output_fields, search_params, partition_names)
            metadata_partition_name = partition_names[0]

        result_ctxt_list = self.scoring(query, search_params=search_params, partition_names=partition_names)
        if len(result_ctxt_list) == 0:
            return []
        if self._is_kms_managed_mode():
            output_result_list = self._multiquery_get_topk_metadata_results_via_kms(
                result_ctxt_list, top_k, output_fields, partition_name=metadata_partition_name
            )
            result_ctxt_list.clear()
            del result_ctxt_list
            self._tag_partition_name(output_result_list, metadata_partition_name)
            return output_result_list
        result_list = [self.decrypt_score(result_ctxt) for result_ctxt in result_ctxt_list]
        result_ctxt_list.clear()
        del result_ctxt_list

        output_result_list = self._multiquery_get_topk_metadata_results(
            result_list, top_k, output_fields, partition_name=metadata_partition_name
        )
        result_list.clear()
        del result_list
        self._tag_partition_name(output_result_list, metadata_partition_name)
        return output_result_list

    @staticmethod
    def _tag_partition_name(result_lists, partition_name):
        """Stamp every hit with its source partition so search() returns the same
        dict shape across single-, multi-, and no-partition queries (empty = default)."""
        name = partition_name or ""
        for q_list in result_lists:
            for r in q_list:
                r["partition_name"] = name

    def _search_multi_partition(self, query, top_k, output_fields, search_params, partition_names):
        """Search several partitions and merge their per-query top-k by score.

        Each partition is searched on its own (the verified single-partition path,
        with correct per-partition metadata, which already tags each hit's
        partition_name); the results are then merged. Returns the same shape as
        search(): one list of result dicts per query.
        """
        per_partition = [
            self.search(query, top_k, output_fields=output_fields, search_params=search_params, partition_names=[name])
            for name in partition_names
        ]
        num_queries = max((len(p) for p in per_partition), default=0)
        merged = []
        for q in range(num_queries):
            combined = []
            for p in per_partition:
                if q < len(p):
                    combined.extend(p[q])
            # Score desc; tie-break on (partition_name, id) so equal scores order deterministically.
            combined.sort(key=lambda r: (r.get("score", float("-inf")), r.get("partition_name", ""), r.get("id", 0)), reverse=True)
            merged.append(combined[:top_k])
        return merged

    def scoring(
        self,
        query: Union[List[float], np.ndarray, CipherBlock, List[List[float]], List[np.ndarray], List[CipherBlock]],
        search_params: dict = None,
        partition_names: Optional[List[str]] = None,
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
            self._ensure_ivf_centroids_loaded(require_centroids=True)
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
                result_ctxt = self.indexer.encrypted_search(
                    self.index_config.index_name, encrypted_query, search_topk, partition_names=partition_names
                )

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
                    partition_names=partition_names,
                )

        elif self.index_config.index_type == "IVF_VCT":
            # nlist/default_nprobe came from the summary at open; no centroids needed.
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
                    partition_names=partition_names,
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
                result_ctxt = self.indexer.encrypted_search(
                    self.index_config.index_name, encrypted_query, partition_names=partition_names
                )
            else:  # PC
                # Do search with plain queries
                result_ctxt = self.indexer.search(
                    self.index_config.index_name,
                    query,
                    level=plain_query_level,
                    partition_names=partition_names,
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

    def _multiquery_get_topk_metadata_results(
        self, results, top_k: int, output_fields: List[str] = None, partition_name: Optional[str] = None
    ):
        topk_result_list = []
        topk_indices_list = []
        for result in results:
            topk_result, topk_indices = topk(result["score"], top_k)
            if result.get("shard_idx"):
                for i, v in enumerate(topk_indices):
                    topk_indices[i]["shard_idx"] = result["shard_idx"][v["shard_idx"]]
            topk_result_list.append(topk_result)
            topk_indices_list.extend(topk_indices)

        # Fetch metadata from the scoped partition's physical index (None =
        # _default = the parent index).
        metadata_result = self.indexer.get_metadata(
            self.index_config.index_name, topk_indices_list, fields=output_fields, partition_name=partition_name
        )

        if len(metadata_result) != len(topk_indices_list):
            raise ValueError(
                f"Metadata count mismatch: requested {len(topk_indices_list)}, received {len(metadata_result)}"
            )

        # Resolve the metadata key once for the whole result set instead of
        # per item; _decrypt_metadata reuses these bytes without re-reading the
        # key file or rebuilding a KeyManager for each row. Guard on a non-empty
        # result so an empty search does not raise on a missing/misconfigured key.
        meta_key = None
        if self.index_config.metadata_encryption and len(metadata_result) > 0:
            key_source = self.index_config.metadata_key_path or self.index_config.metadata_key
            meta_key = resolve_metadata_key(key_source, kek=self.index_config.seal_kek_path)

        output_result_list = []
        offset = 0
        for topk_result in topk_result_list:
            n = len(topk_result)
            output_result = [
                {
                    "id": metadata_result[i + offset].id,
                    "score": topk_result[i][1],
                    "metadata": self._decrypt_metadata(metadata_result[i + offset].data, meta_key),
                }
                for i in range(n)
            ]
            # Drop id==0 sentinels (DeleteData soft-delete + post-cutover stale coords)
            # and dedup by id since partial-merge can score the same item via raw +
            # merged shards; keep the best score, preserving rank order.
            filtered = []
            seen = {}
            for entry in output_result:
                if entry["id"] == 0:
                    continue
                prev = seen.get(entry["id"])
                if prev is None:
                    seen[entry["id"]] = len(filtered)
                    filtered.append(entry)
                elif entry["score"] > filtered[prev]["score"]:
                    filtered[prev] = entry
            output_result_list.append(filtered)
            offset += n

        # Release intermediate containers before returning.
        topk_result_list.clear()
        topk_indices_list.clear()
        if hasattr(metadata_result, "clear"):
            metadata_result.clear()
        del metadata_result
        del meta_key

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
        self._ensure_ivf_centroids_loaded(require_centroids=True)
        # FIX: Add null check for centroids (was causing AttributeError instead of helpful message)
        if self.index_config.centroids is None or (
            hasattr(self.index_config.centroids, "size") and self.index_config.centroids.size == 0
        ):
            raise ValueError("Centroids not initialized. Load index metadata first.")
        nlist, dim = self.index_config.centroids.shape
        if not 1 <= k <= nlist:
            raise ValueError(f"k={k} is out of range; must satisfy 1 <= k <= nlist ({nlist}).")
        batch_size = max(1, min(KNN_BATCH_SIZE_MAX, KNN_DIST_MATRIX_BUDGET_BYTES // (nlist * 4)))
        nearest_indices: List[np.ndarray] = []

        # batch inner product to find nearest centroids
        for i in range(0, len(data), batch_size):
            data_matrix = np.asarray(data[i : i + batch_size], dtype=np.float32)
            if data_matrix.shape[1] != dim:
                raise ValueError(f"Centroid dimension {dim} does not match data dimension {data_matrix.shape[1]}.")

            dist_matrix = data_matrix @ self.index_config.centroids.T

            # Efficiently get top-k indices for each row using np.argpartition.
            # .copy() is required: the slice is a view into the full (batch_size, nlist)
            # argpartition result, so appending it would keep every batch's full base
            # array alive (O(num_vectors * nlist)) and OOM at large nlist.
            search_topk = np.argpartition(dist_matrix, -k, axis=1)[:, -k:].copy()

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
        # Indent the nested IndexConfig repr so it aligns under "Index(".
        config_repr = "\n".join(f"  {line}" for line in repr(self.index_config).splitlines())
        return (
            "Index(\n"
            f"  config       = {config_repr.lstrip()}\n"
            f"  num_entities = {self.num_entities!r}\n"
            f"  is_loaded    = {self.is_loaded!r}\n"
            ")"
        )
