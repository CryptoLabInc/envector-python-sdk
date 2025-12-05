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
PyEnvector client module

This module provides the EnvectorClient class (formerly ES2) and helpers for managing connections,
keys, and indexes against the enVector server.

Classes:
    EnvectorClient: Main class for managing enVector operations.

Functions:
    init_connect: Initializes the connection to the enVector server.
    init_index_config: Initializes the index configuration.
    create_index: Creates a new index.
    init: Initializes the PyEnvector client environment.
"""

import json
import os
import warnings
from typing import Optional

from pyenvector.api import Indexer
from pyenvector.crypto import KeyGenerator
from pyenvector.crypto.key_manager import KeyManager
from pyenvector.crypto.parameter import ContextParameter, KeyParameter
from pyenvector.index import Index, IndexConfig
from pyenvector.utils import utils
from pyenvector.utils.logging_config import logger


class _PrettyInfo(str):
    """String subclass whose repr renders without quotes for nicer REPL output."""

    def __repr__(self):
        return super().__str__()

    def __str__(self):
        # Ensure both direct calls and print() display the same text.
        return super().__str__()


class EnvectorClient:
    """
    Main class for managing enVector operations.

    Methods:
        init_connect(host, port, address, access_token): Initializes the connection to the enVector server.
        register_key(key_id, key_path): Registers a key with the enVector server.
        generate_and_register_key(key_id, key_path, preset): Generates and registers a key.
        init_index_config(key_path, key_id, preset, query_encryption, index_encryption, index_type):
            Initializes the index configuration.
        create_index(index_name, dim, index_encryption, index_type): Creates a new index.
        init(host, port, address, access_token, key_path, key_id, preset, query_encryption, \
            index_encryption, index_type, auto_key_setup):
            Initializes the EnvectorClient environment.
    """

    def __init__(self):
        """
        Initializes the EnvectorClient class.
        """
        self._indexer = None
        self._index_config = None

    @property
    def indexer(self):
        """
        Returns the indexer object.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        if not self._indexer:
            raise ValueError("Indexer is not initialized. Call init_connect first.")
        return self._indexer

    @indexer.setter
    def indexer(self, indexer: Indexer):
        """
        Sets the indexer object.

        Args:
            indexer (Indexer): The indexer object.

        Raises:
            ValueError: If the indexer is not an instance of Indexer.
        """
        if not isinstance(indexer, Indexer):
            raise ValueError("Indexer must be an instance of Indexer.")
        self._indexer = indexer
        return self

    @property
    def index_config(self):
        """
        Returns the index configuration.

        Raises:
            ValueError: If the index configuration is not initialized.
        """
        if not self._index_config:
            raise ValueError("Index config is not initialized. Call init_index_config first.")
        return self._index_config

    @index_config.setter
    def index_config(self, index_config: IndexConfig):
        """
        Sets the index configuration.

        Args:
            index_config (IndexConfig): The index configuration.

        Raises:
            ValueError: If the index configuration is not an instance of IndexConfig.
        """
        if not isinstance(index_config, IndexConfig):
            raise ValueError("Index config must be an instance of IndexConfig.")
        self._index_config = index_config
        return self

    @property
    def is_connected(self):
        """
        Checks if the EnvectorClient client is connected to the server.

        Returns:
            bool: True if connected, False otherwise.
        """
        return self.indexer.is_connected()

    def disconnect(self):
        """
        Disconnects the EnvectorClient client from the server.
        """
        if self.indexer:
            self.indexer.disconnect()
            logger.info("Disconnected from enVector server.")
        else:
            logger.warning("No active connection to disconnect.")

    def register_key(
        self,
        key_id: Optional[str] = None,
    ):
        """
        Registers and loads a key with the enVector server.

        Args:
            key_id (str, optional): The key ID. If omitted the ID from ``index_config`` is used.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        if key_id is None:
            key_id = self.index_config.key_id
        if key_id is not None:
            self.index_config.key_id = key_id
        if self.index_config.use_key_stream or self.index_config.key_param.check_key_dir():
            logger.info(
                f"Keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} "
                f"already exists. Checking for registered keys."
            )
            key_list = self.indexer.get_key_list()
            if key_list and self.index_config.key_id in key_list:
                logger.info(f"Key {self.index_config.key_id} already registered in {self.index_config.key_path}.")
            else:
                logger.info(f"Registering key {self.index_config.key_id} from {self.index_config.key_path}.")
                self.indexer.register_key(
                    self.index_config.key_id,
                    self.index_config.eval_key,
                    key_type="EvalKey",
                    preset=self.index_config.preset,
                    eval_mode=self.index_config.eval_mode,
                )
            return
        else:
            raise ValueError(
                f"Keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} do not exist. "
                "Please generate keys first."
            )

    def load_key(self, key_id: Optional[str] = None):
        """
        Loads a key with the enVector server.

        Args:
            key_id (str): The key ID.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        if key_id is None:
            key_id = self.index_config.key_id
        self.indexer.load_key(key_id=key_id)

    def unload_key(self, key_id: Optional[str] = None):
        """
        Unloads a key with the enVector server.

        Args:
            key_id (str): The key ID.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        if key_id is None:
            key_id = self.index_config.key_id
        self.indexer.unload_key(key_id=key_id)

    def get_key_list(self):
        """
        Retrieves the list of registered keys.

        Returns:
            list: A list of registered keys.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        return self.indexer.get_key_list()

    def get_key_info(self, key_id: Optional[str] = None):
        """
        Retrieves the information of the registered keys.

        Returns:
            dict: A dictionary containing key information.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        if key_id is None:
            key_id = self.index_config.key_id
        return self.indexer.get_key_info(key_id)

    def get_index_list(self):
        """
        Retrieves the list of registered index.

        Returns:
            list: A list of registered indexes.

        Raises:
            ValueError: If the indexer is not initialized.
        """
        return self.indexer.get_index_list()

    def generate_and_store_aws(self, key_id: Optional[str] = None):
        """
        Retrieves the key from AWS using KeyManager.

        Args:
            key_id (str, optional): Override for ``index_config.key_id`` when retrieving the key.
        """
        if key_id is not None:
            self.index_config.key_id = key_id
        km = KeyManager(
            key_id=self.index_config.key_id,
            key_store="aws",
            region_name=self.index_config.region_name,
            bucket_name=self.index_config.bucket_name,
            secret_prefix=self.index_config.secret_prefix,
        )
        if km.verify_key_id():
            raise ValueError(f"Key ID {self.index_config.key_id} already exists in AWS.")
        else:
            keygen = KeyGenerator._create_from_parameter(
                context_param=self.index_config.context_param, key_param=self.index_config.key_param
            )
            key_dict = keygen.generate_keys_stream()
            km.save(key_dict)
        return key_dict

    @staticmethod
    def _extract_key_streams(key_bundle: Optional[dict]):
        """
        Normalize key payload dictionaries (e.g., AWS blobs) into streams expected by IndexConfig.

        Args:
            key_bundle (dict, optional): Key payload containing ``*_blob`` or ``*_key`` entries.

        Returns:
            tuple: (enc_key, eval_key, sec_key, metadata_key)
        """
        if not key_bundle:
            return None, None, None, None

        def pick(*names):
            for name in names:
                if name in key_bundle and key_bundle[name] is not None:
                    return key_bundle[name]
            return None

        enc_key = pick("enc_blob", "enc_key")
        eval_key = pick("eval_blob", "eval_key")
        sec_key = pick("sec_blob", "sec_key")
        metadata_key = pick("metadata_blob", "metadata_key")
        return enc_key, eval_key, sec_key, metadata_key

    def generate_key(self, key_id: Optional[str] = None):
        """
        Generates a key using the KeyGenerator.

        Args:
            key_id (str, optional): Override for ``index_config.key_id`` when generating the key.

        Returns:
            KeyGenerator: The KeyGenerator instance used to generate the key.
        """
        if key_id is not None:
            self.index_config.key_id = key_id
        if self.index_config.key_param.check_key_dir() and not self.index_config.use_key_stream:
            logger.info(
                f"Keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} "
                f"already exists. Skipping key generation."
            )
            return
        else:
            logger.info(
                f"Generating keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} "
                f"using preset: {self.index_config.context_param}. "
            )
            keygen = KeyGenerator._create_from_parameter(
                context_param=self.index_config.context_param, key_param=self.index_config.key_param
            )
            keygen.generate_keys()
        return

    def generate_and_register_key(
        self,
    ):
        """
        Generates and registers a key.
        """
        if self.index_config.key_param.check_key_dir() or self.index_config.use_key_stream:
            logger.info(
                f"Keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} "
                f"already exists. Checking for existing keys."
            )
            key_list = self.indexer.get_key_list()
            if key_list and self.index_config.key_id in key_list:
                logger.info(f"Key {self.index_config.key_id} already registered in {self.index_config.key_path}.")
                return
            else:
                logger.info(f"Registering key {self.index_config.key_id} from {self.index_config.key_path}.")
                self.register_key()
            return

        else:
            logger.info(
                f"Generating keys in {self.index_config.key_path} with key_id: {self.index_config.key_id} "
                f"using preset: {self.index_config.context_param}. "
            )
            self.generate_key()
            self.register_key()

    @property
    def context_param(self) -> "ContextParameter":
        """
        Returns the context parameters.

        Returns:
            ContextParameter: The context parameters.
        """
        return self.index_config.context_param

    @property
    def key_param(self) -> "KeyParameter":
        """
        Returns the key parameters.

        Returns:
            KeyParameter: The key parameters.
        """
        return self.index_config.key_param

    def init_connect(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        address: Optional[str] = None,
        access_token: Optional[str] = None,
        secure: Optional[bool] = None,
    ):
        """
        Initializes the connection to the enVector server.

        Args:
            host (str, optional): The host address.
            port (int, optional): The port number.
            address (str, optional): The full address.
            access_token (str, optional): The access token.
            secure (bool, optional): Whether to use a secure connection. If None,
                (defaults to True when access_token is provided, otherwise False.)

        Returns:
            EnvectorClient: The initialized EnvectorClient object.

        Raises:
            ValueError: If neither host and port nor address are provided.

        Examples:
            Initialize EnvectorClient environment:
                >>> pyenvector_client = EnvectorClient()
                >>> es2_instance = pyenvector_client.init_connect(
                ...     host="localhost",
                ...     port=50050,
                ...     )
        """
        if host and port:
            address = f"{host}:{port}"
        elif not address:
            raise ValueError("Either host and port or address must be provided.")

        # Ensure any existing connection is closed before creating a new one
        if self._indexer is not None:
            try:
                self._indexer.disconnect()
            except Exception:
                pass
            finally:
                self._indexer = None

        indexer = Index.init_connect(
            address=address,
            access_token=access_token,
            secure=secure,
        )
        self.indexer = indexer

        # Optional: verify server version against SDK version using Indexer helper
        try:
            self.indexer.check_version_compat()
        except Exception:
            # let the caller handle strict-mode exception; do not swallow
            raise
        return self

    def init_index_config(
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
        auto_key_setup: Optional[bool] = None,
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
        Initializes the index configuration.

        Args:
            index_name (str, optional): The name of the index.
            dim (int, optional): The dimensionality of the index.
            key_path (str, optional): The path to the key. Defaults to None.
            key_id (str, optional): The key ID. Defaults to None.
            seal_mode (str, optional): The seal mode. Defaults to None.
            seal_kek_path (str, optional): The key encryption key (KEK) path. Defaults to None.
            preset (str, optional): The preset for the key. Defaults to None.
            eval_mode (str, optional): The evaluation mode. Defaults to None.
            query_encryption (str, optional): The encryption type for query,
            e.g. "plain", "cipher", "hybrid". Defaults to None.
            index_encryption (str, optional): The encryption type for database,
            e.g. "plain", "cipher", "hybrid". Defaults to None.
            index_params (dict, optional): The parameters for the index. Defaults to None.
            index_type (str, optional): The type of index.
            Currently, ``flat`` and ``ivf_flat`` index types are supported.
            metadata_encryption (bool, optional): The encryption type for metadata,
            e.g. True, False. Defaults to None.
            description (str, optional): A human-readable description for the index.
            auto_key_setup (bool, optional): When True, automatically generate/register the key material.
            use_key_stream (bool, optional): When True, expect in-memory key bytes instead of files.
            enc_key (bytes, optional): Encryption key bytes when ``use_key_stream`` is True.
            eval_key (bytes, optional): Evaluation key bytes for key-stream mode.
            sec_key (bytes, optional): Secret key bytes for key-stream mode.
            metadata_key (bytes, optional): Metadata key bytes for key-stream mode.
            seal_kek (bytes, optional): Raw KEK bytes overriding ``seal_kek_path``.

        Examples:
            Initialize EnvectorClient environment:
                >>> pyenvector_client = EnvectorClient()
                >>> pyenvector_client.init_index_config(
                ...     key_path="./keys",
                ...     key_id="example_key",
                ...     preset="ip",
                ...     query_encryption="plain",
                ...     index_encryption="cipher",
                ...     index_params={"index_type": "flat"}
                ...     metadata_encryption=True,
                ...     auto_key_setup=True
                ... )
        """
        auto_key_setup = True if auto_key_setup is None else auto_key_setup
        _generate_keys_stream_required = False
        if key_path is None:
            use_key_stream = True
            if key_store == "aws":
                if (
                    enc_key is None
                    or eval_key is None
                    or sec_key is None
                    or (metadata_encryption and metadata_key is None)
                ):
                    km = KeyManager(
                        key_id=key_id,
                        key_store=key_store,
                        region_name=region_name,
                        bucket_name=bucket_name,
                        secret_prefix=secret_prefix,
                    )
                    if not km.verify_key_id():
                        _generate_keys_stream_required = True
                    else:
                        key_dict = km.load_from_aws()
                        enc_key, eval_key, sec_key, metadata_key = self._extract_key_streams(key_dict)
            elif auto_key_setup:
                if enc_key is None:
                    if os.environ.get("ENVECTOR_ENC_KEY", None):
                        enc_key = utils.get_key_stream(os.environ["ENVECTOR_ENC_KEY"])
                    else:
                        warnings.warn(
                            "Encryption Key is not provided for using key stream. "
                            "Please provide the key if you are inserting data.",
                            stacklevel=2,
                        )
                if eval_key is None:
                    if os.environ.get("ENVECTOR_EVAL_KEY", None):
                        eval_key = utils.get_key_stream(os.environ["ENVECTOR_EVAL_KEY"])
                    elif eval_mode.lower() != "mm":
                        warnings.warn(
                            "Evaluation Key is not provided for using key stream. "
                            "Please provide the key if you are registering evaluation key.",
                            stacklevel=2,
                        )
                if sec_key is None:
                    if os.environ.get("ENVECTOR_SEC_KEY", None):
                        sec_key = utils.get_key_stream(os.environ["ENVECTOR_SEC_KEY"])
                    else:
                        warnings.warn(
                            "Secret Key is not provided for using key stream. "
                            "Please provide the key if you are searching data.",
                            stacklevel=2,
                        )
                if metadata_key is None:
                    if os.environ.get("ENVECTOR_METADATA_KEY", None):
                        metadata_key = utils.get_key_stream(os.environ["ENVECTOR_METADATA_KEY"])
                    elif metadata_encryption:
                        warnings.warn(
                            "Metadata Key is not provided for using key stream. "
                            "Please provide the key if you are using metadata encryption.",
                            stacklevel=2,
                        )
                if seal_kek is None:
                    if seal_kek_path:
                        seal_kek = seal_kek_path
                    elif os.environ.get("ENVECTOR_SEAL_KEK", None):
                        seal_kek = utils.get_key_stream(os.environ["ENVECTOR_SEAL_KEK"])
                    elif seal_mode is not None and seal_mode.lower() != "none":
                        warnings.warn(
                            "Seal KEK is not provided for using key stream. "
                            "Please provide the key if you are using secret key sealing.",
                            stacklevel=2,
                        )
            else:
                warnings.warn(
                    "Auto key setup is disabled. "
                    "Key streams are required for registering key, encryption, decryption, etc ...",
                    stacklevel=2,
                )
        else:
            if Index._default_key_path is None:
                Index.init_key_path(key_path)
            if Index._default_key_path and Index._default_key_path != key_path:
                raise ValueError(
                    f"Key path {key_path} does not match the default key path {Index._default_key_path}. "
                    "Please reinitialize. pyenvector.init()"
                )
        self.index_config = IndexConfig(
            index_name=index_name,
            dim=dim,
            key_path=key_path,
            key_id=key_id,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
            preset=preset,
            eval_mode=eval_mode,
            query_encryption=query_encryption,
            index_encryption=index_encryption,
            index_params=index_params,
            index_type=index_type,
            metadata_encryption=metadata_encryption,
            description=description,
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
        if auto_key_setup:
            if self.index_config.key_id is None:
                raise ValueError("Key ID must be provided to generate a key.")
            elif _generate_keys_stream_required:
                key_dict = self.generate_and_store_aws(key_id=self.index_config.key_id)
                enc_key, eval_key, sec_key, metadata_key = self._extract_key_streams(key_dict)
                self.index_config = self.index_config.deepcopy(
                    enc_key=enc_key,
                    eval_key=eval_key,
                    sec_key=sec_key,
                    metadata_key=metadata_key,
                )
            elif not use_key_stream:
                self.generate_key()
            self.register_key()
            key_list = self.indexer.get_key_list()
            for key in key_list:
                if key != key_id:
                    self.unload_key(key_id=key)
            # TODO FIX after append support
            self.load_key()

        Index._default_index_config = self.index_config

    def init(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        address: Optional[str] = None,
        access_token: Optional[str] = None,
        secure: Optional[bool] = None,
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
        auto_key_setup: Optional[bool] = True,
        use_key_stream: Optional[bool] = False,
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
        Initializes the EnvectorClient environment (connection, key, and index config).

        Parameters
        ----------
        host : str, optional
            The host address to connect to enVector server.
        port : int, optional
            The port number to connect to enVector server.
        address : str, optional
            The full address to connect to enVector server.
        access_token : str, optional
            The access token to connect to enVector server.
        secure : bool, optional
            Whether to use a secure connection. If None, defaults to True when access_token is
            provided, otherwise False.
        index_name : str, optional
            The name of the index.
        dim : int, optional
            The dimensionality of the index.
        key_path : str, optional
            The path to the key directory.
        key_id : str, optional
            The key ID.
        seal_mode : str, optional
            Seal mode such as ``AES_KEK`` when secret keys are sealed at rest.
        seal_kek_path : str, optional
            The path to the key encryption key for secret key sealing.
        seal_kek : bytes, optional
            In-memory KEK bytes that override ``seal_kek_path``.
        preset : str, optional
            The preset for the key.
        eval_mode : str, optional
            The evaluation mode.
        query_encryption : str, optional
            The encryption type for query, e.g. "plain", "cipher", "hybrid". Defaults to ``plain``.
        index_encryption : str, optional
            The encryption type for database, e.g. "plain", "cipher", "hybrid". Defaults to ``cipher``.
        index_params : dict, optional
            The parameters for the index. Defaults to {"index_type": "flat"}.
            Currently, ``flat`` and ``ivf_flat`` index types are supported.
        index_type : str, optional
            The type of index.
            Currently, ``flat`` and ``ivf_flat`` index types are supported.
        metadata_encryption : bool, optional
            The encryption type for metadata, e.g. True, False. Defaults to None.
        description : str, optional
            A human-readable description for the index.
        auto_key_setup : bool, optional
            Whether to automatically generate and register the key. Defaults to ``True``.
        use_key_stream : bool, optional
            Whether keys are supplied as in-memory byte streams rather than files. Defaults to ``False``.
        enc_key : bytes, optional
            Encryption key bytes when ``use_key_stream`` is enabled.
        eval_key : bytes, optional
            Evaluation key bytes when ``use_key_stream`` is enabled.
        sec_key : bytes, optional
            Secret key bytes when ``use_key_stream`` is enabled.
        metadata_key : bytes, optional
            Metadata encryption key bytes used when ``metadata_encryption`` is True and
            ``use_key_stream`` is enabled.

        Returns
        -------
        EnvectorClient
            The initialized EnvectorClient object.

        Examples
        --------
            >>> import pyenvector as ev
            >>> ev.init(
            ...     host="localhost",
            ...     port=50050,
            ...     key_path="./keys",
            ...     key_id="example_key",
            ...     auto_key_setup=True
            ... )

            >>> ev.init(
            ...     address="localhost:50050",
            ...     key_path="./keys",
            ...     auto_key_setup=False,
            ... )
        """
        if host is None and port is None and address is None:
            raise ValueError("Either host and port or address must be provided.")
        self.init_connect(
            host=host,
            port=port,
            address=address,
            access_token=access_token,
            secure=secure,
        )
        Index.init_key_path(key_path)
        self.init_index_config(
            index_name=index_name,
            dim=dim,
            key_path=key_path,
            key_id=key_id,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
            preset=preset,
            eval_mode=eval_mode,
            query_encryption=query_encryption,
            index_encryption=index_encryption,
            index_params=index_params,
            index_type=index_type,
            metadata_encryption=metadata_encryption,
            description=description,
            auto_key_setup=auto_key_setup,
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
        return self

    def create_index(
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
        Creates a new index.

        Args:
            index_name (str): The name of the index.
            dim (int): The dimensionality of the index.
            index_encryption (str, optional): The encryption type for database, e.g. "plain", "cipher", "hybrid".
            index_type (str, optional): The type of index.
            description (str, optional): A human-readable description for the index.
            key_path (str, optional): Directory containing keys. Required unless ``use_key_stream`` is True.
            key_id (str, optional): Identifier of the key bundle to load.
            seal_mode (str, optional): Seal mode name (for example ``AES_KEK``).
            seal_kek_path (str, optional): Path to the KEK when seal mode is enabled.
            preset (str, optional): Context preset.
            eval_mode (str, optional): Evaluation mode.
            query_encryption (str, optional): Query encryption configuration.
            index_encryption (str, optional): Database encryption configuration.
            index_params (dict, optional): Additional index build parameters.
            index_type (str, optional): Convenience alias for ``index_params['index_type']``.
            metadata_encryption (bool, optional): Whether metadata is encrypted.
            use_key_stream (bool, optional): When True, use in-memory key bytes instead of disk paths.
            enc_key (bytes, optional): Encryption key stream for key-stream mode.
            eval_key (bytes, optional): Evaluation key stream for key-stream mode.
            sec_key (bytes, optional): Secret key stream for key-stream mode.
            metadata_key (bytes, optional): Metadata key stream for key-stream mode.
            seal_kek (bytes, optional): Raw KEK bytes overriding ``seal_kek_path``.

        Returns:
            Index: The created index.

        Examples:
            Create Index:
                >>> pyenvector_client = EnvectorClient()
                >>> pyenvector_client.init(
                ...     host="localhost",
                ...     port=50050,
                ...     key_path="./keys",
                ...     key_id="example_key",
                ...     preset="ip",
                ...     query_encryption="plain",
                ...     index_encryption="cipher",
                ...     index_params={"index_type": "flat"}
                ... )
                >>> index = pyenvector_client.create_index(
                ...     index_name="test_index",
                ...     dim=128
                ... )
        """
        if index_type is not None and not index_params:
            index_params = {"index_type": index_type}
        index_config = self.index_config.deepcopy(
            index_name=index_name,
            dim=dim,
            key_path=key_path,
            key_id=key_id,
            seal_mode=seal_mode,
            seal_kek_path=seal_kek_path,
            preset=preset,
            eval_mode=eval_mode,
            query_encryption=query_encryption,
            index_encryption=index_encryption,
            index_params=index_params,
            metadata_encryption=metadata_encryption,
            description=description,
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

        return Index.create_index(indexer=self.indexer, index_config=index_config)

    def drop_index(self, index_name: str):
        """
        Drops the current index.

        Returns:
            Index: The current index after dropping it.

        Raises:
            ValueError: If the indexer is not connected.
        """
        if not self.indexer or not self.indexer.is_connected():
            raise ValueError("Indexer not connected. Please call Index.init_connect() first.")

        self.indexer.delete_index(index_name)
        return self

    def delete_key(self, key_id: str):
        """
        Delete the key with the given key_id.

        Args:
            key_id (str): The ID of the key to delete.

        Raises:
            ValueError: If the indexer is not connected.
        """
        if not self.indexer or not self.indexer.is_connected():
            raise ValueError("Indexer not connected. Please call Index.init_connect() first.")
        self.indexer.delete_key(key_id)
        logger.info(f"Key {key_id} deleted successfully.")
        return self

    @property
    def key_path(self):
        """
        Returns the path to the key directory.

        Returns:
            str: The path to the key directory.
        """
        return self.index_config.key_path

    def describe(self, verbose: bool = False):
        """
        Provide a snapshot of the current EnvectorClient client state.

        Args:
            verbose (bool, optional): When True, include the full list of keys and indexes.
                When False (default) only aggregated counts are returned.

        Returns:
            dict: Summary or detailed information depending on ``verbose``.
        """
        connection = self._connection_details()
        snapshot = {"connection": connection}
        # Only try remote queries when connection is available.
        if connection.get("connected"):
            snapshot["keys"] = self._keys_details()
            snapshot["indexes"] = self._indexes_details()
        else:
            snapshot["keys"] = self._keys_details(allow_remote=False)
            snapshot["indexes"] = self._indexes_details(allow_remote=False)
        local_config = self._local_index_config_details()
        if local_config:
            snapshot["local_index_config"] = local_config
        if verbose:
            return snapshot
        return self._summarize_snapshot(snapshot)

    def _summarize_snapshot(self, snapshot: dict) -> dict:
        connection = snapshot.get("connection", {}) or {}
        keys = snapshot.get("keys", {}) or {}
        indexes = snapshot.get("indexes", {}) or {}

        def _bool_from_count(value):
            if value is None:
                return None
            return value > 0

        summary = {
            "connection": {
                "connected": connection.get("connected"),
                "address": connection.get("address"),
                "secure": connection.get("secure"),
                "access_token_used": connection.get("access_token_used"),
                "server_version": connection.get("server_version"),
                "error": connection.get("error") or connection.get("server_version_error"),
            },
            "keys": {
                "registered": _bool_from_count(keys.get("registered_count")),
                "registered_count": keys.get("registered_count"),
                "loaded_count": keys.get("loaded_count"),
                "active_key_id": keys.get("active_key_id"),
                "error": keys.get("error"),
            },
            "indexes": {
                "registered_count": indexes.get("registered_count"),
                "loaded_count": indexes.get("loaded_count"),
                "key_loaded_count": indexes.get("key_loaded_count"),
                "active_index_name": indexes.get("active_index_name"),
                "total_items": self._calculate_total_items(indexes.get("registered")),
                "error": indexes.get("error"),
            },
        }
        if snapshot.get("local_index_config"):
            summary["local_index_config"] = snapshot["local_index_config"]
        return summary

    def _calculate_total_items(self, registered_indexes):
        total = 0
        has_value = False
        for entry in registered_indexes or []:
            if entry.get("error"):
                continue
            row_count = entry.get("row_count")
            if isinstance(row_count, bool):
                continue
            value = None
            if isinstance(row_count, (int, float)):
                value = int(row_count)
            else:
                try:
                    value = int(row_count)
                except (TypeError, ValueError):
                    continue
            total += value
            has_value = True
        return total if has_value else None

    def info(self, verbose: bool = False) -> str:
        """
        Provide a human-readable summary of the EnvectorClient client.

        Args:
            verbose (bool, optional): When True, include detailed per-resource information.
                Defaults to False which emits a short numeric summary.

        Returns:
            str: A formatted string representation of the EnvectorClient client state.
        """
        snapshot = self.describe(verbose=verbose)
        if verbose:
            return self._format_verbose_info(snapshot)
        return self._format_summary_info(snapshot)

    def _format_summary_info(self, snapshot: dict) -> str:
        connection = snapshot.get("connection", {}) or {}
        keys = snapshot.get("keys", {}) or {}
        indexes = snapshot.get("indexes", {}) or {}

        title = "EnvectorClient Summary"
        lines = [title, "-" * len(title)]

        status = "connected" if connection.get("connected") else "disconnected"
        conn_line = f"Connection : {status}"
        if connection.get("address"):
            conn_line += f" ({connection['address']})"
        if connection.get("secure") is not None:
            conn_line += f", secure={connection['secure']}"
        lines.append(conn_line)

        registered_state = keys.get("registered")
        if registered_state is True:
            key_state = "registered"
        elif registered_state is False:
            key_state = "not registered"
        else:
            key_state = "unknown"
        key_counts = []
        if keys.get("registered_count") is not None:
            key_counts.append(f"total={keys['registered_count']}")
        if keys.get("loaded_count") is not None:
            key_counts.append(f"loaded={keys['loaded_count']}")
        key_line = f"Keys       : {key_state}"
        if key_counts:
            key_line += f" ({', '.join(key_counts)})"
        if keys.get("active_key_id"):
            key_line += f", active={keys['active_key_id']}"
        lines.append(key_line)

        idx_count = indexes.get("registered_count")
        idx_line = "Indexes    : "
        idx_line += "-" if idx_count is None else str(idx_count)
        if indexes.get("loaded_count") is not None:
            idx_line += f" (loaded={indexes['loaded_count']})"
        if indexes.get("active_index_name"):
            idx_line += f", active={indexes['active_index_name']}"
        lines.append(idx_line)

        total_items = indexes.get("total_items")
        lines.append(f"Items      : {total_items if total_items is not None else '-'}")

        if connection.get("error"):
            lines.append(f"Connection error: {connection['error']}")
        if keys.get("error"):
            lines.append(f"Keys error: {keys['error']}")
        if indexes.get("error"):
            lines.append(f"Indexes error: {indexes['error']}")

        return _PrettyInfo("\n".join(lines))

    def _format_verbose_info(self, snapshot: dict) -> str:
        def format_kv(pairs):
            filtered = [(label, value) for label, value in pairs if value is not None]
            if not filtered:
                return "(none)"
            label_width = max(len(label) for label, _ in filtered)
            rendered = [f"{label:<{label_width}}: {value}" for label, value in filtered]
            return "\n".join(rendered)

        def format_table(headers, rows, row_separator: bool = False):
            if not rows:
                return "(none)"
            widths = [len(h) for h in headers]
            for row in rows:
                for idx, cell in enumerate(row):
                    longest_line = max(len(line) for line in str(cell).split("\n"))
                    widths[idx] = max(widths[idx], longest_line)

            def format_row(row):
                split_cells = [str(cell).split("\n") for cell in row]
                max_lines = max(len(lines) for lines in split_cells)
                sub_rows = []
                for line_idx in range(max_lines):
                    parts = []
                    for idx, lines in enumerate(split_cells):
                        text_line = lines[line_idx] if line_idx < len(lines) else ""
                        parts.append(text_line.ljust(widths[idx]))
                    sub_rows.append(" | ".join(parts))
                return "\n".join(sub_rows)

            lines = [
                format_row(headers),
                "-+-".join("-" * width for width in widths),
            ]
            for row in rows:
                lines.append(format_row(row))
                if row_separator:
                    lines.append("-+-".join("-" * width for width in widths))
            if row_separator and len(lines) > 2:
                lines.pop()
            return "\n".join(lines)

        def format_bool(value):
            if value is None:
                return "-"
            if isinstance(value, bool):
                return "True" if value else "False"
            return str(value)

        def format_box(title: str, content: str) -> str:
            if not content:
                content = "(none)"
            lines = content.split("\n")
            width = max(len(title), *(len(line) for line in lines))
            border = "+" + "-" * (width + 2) + "+"
            title_line = f"| {title.ljust(width)} |"
            body = [f"| {line.ljust(width)} |" for line in lines]
            return "\n".join([border, title_line, border, *body, border])

        sections = [
            format_box(
                "EnvectorClient Client Overview",
                "Snapshot of connection status, server resources, and local index defaults.",
            )
        ]

        connection = snapshot.get("connection", {}) or {}
        conn_pairs = [
            ("Status", "connected" if connection.get("connected") else "disconnected"),
            ("Address", connection.get("address")),
            ("Secure", connection.get("secure")),
            (
                "Access Token",
                "provided" if connection.get("access_token_used") else "not provided",
            ),
            ("Server Version", connection.get("server_version")),
            ("Version err", connection.get("server_version_error")),
            ("Error", connection.get("error")),
        ]
        sections.append("")
        sections.append(format_box("Connection", format_kv(conn_pairs)))

        keys = snapshot.get("keys", {}) or {}
        registered_keys = keys.get("registered") or []
        key_rows = []
        for key in registered_keys:
            if key.get("error"):
                key_rows.append(
                    [
                        key.get("key_id", "<unknown>"),
                        "-",
                        "-",
                        "-",
                        "-",
                        format_bool(key.get("is_loaded")),
                        key["error"],
                    ]
                )
            else:
                key_rows.append(
                    [
                        key.get("key_id", "<unknown>"),
                        key.get("key_type", "-"),
                        key.get("preset", "-"),
                        key.get("eval_mode", "-"),
                        ((key.get("sha256sum") or "-")[:8] + "...") if key.get("sha256sum") else "-",
                        format_bool(key.get("is_loaded")),
                        "",
                    ]
                )
        key_summary = (
            f"registered={keys.get('registered_count', len(registered_keys))}, loaded={keys.get('loaded_count')}"
        )
        sections.append("")
        sections.append(
            format_box(
                "Keys",
                f"{key_summary}\n\n"
                + format_table(
                    ["Key ID", "Type", "Preset", "Eval", "SHA256", "Loaded"],
                    [row[:6] for row in key_rows],
                ),
            )
        )
        if keys.get("error"):
            sections.append(f"Error: {keys['error']}")

        indexes = snapshot.get("indexes", {}) or {}
        registered_indexes = indexes.get("registered") or []

        def build_index_detail(entry: dict) -> str:
            parts = [
                f"index={entry.get('index_encryption', '-')}",
                f"query={entry.get('query_encryption', '-')}",
            ]
            if entry.get("metadata_encryption") is not None:
                parts.append(f"metadata={entry.get('metadata_encryption')}")
            return _wrap_table_text(", ".join(parts))

        def build_key_info(entry: dict) -> str:
            key_id = entry.get("key_id") or "-"
            is_loaded = entry.get("is_key_loaded")
            if is_loaded is True:
                suffix = "loaded"
            elif is_loaded is False:
                suffix = "not loaded"
            else:
                suffix = "unknown"
            return f"{key_id}\n({suffix})"

        def _wrap_table_text(text: str) -> str:
            parts = text.split(", ")
            if not parts:
                return text
            first, *rest = parts
            if not rest:
                return first
            return first + "\n" + "\n".join(rest)

        def build_index_description(entry: dict) -> str:
            desc = entry.get("description")
            if not desc:
                return "-"
            return _wrap_table_text(str(desc))

        def build_index_state(entry: dict) -> str:
            if entry.get("state"):
                return entry["state"]
            idx_loaded = entry.get("is_loaded")
            key_loaded = entry.get("is_key_loaded")
            if idx_loaded and key_loaded:
                return "insert/search"

            needs_index = idx_loaded is False
            needs_key = key_loaded is False
            if needs_index and needs_key:
                return "unavailable (load index and key)"
            if needs_index:
                return "unavailable (load index)"
            if needs_key:
                return "unavailable (load key)"
            return "unavailable"

        index_rows = []
        for index in registered_indexes:
            if index.get("error"):
                index_rows.append(
                    [
                        index.get("index_name", "<unknown>"),
                        "-",
                        "-",
                        "-",
                        format_bool(index.get("is_loaded")),
                        build_key_info(index),
                        build_index_state(index),
                        build_index_description(index),
                        build_index_detail(index),
                        str(index.get("created_time")),
                    ]
                )
                continue
            index_rows.append(
                [
                    index.get("index_name", "<unknown>"),
                    str(index.get("dim")),
                    str(index.get("row_count")),
                    index.get("index_type", "-"),
                    format_bool(index.get("is_loaded")),
                    build_key_info(index),
                    build_index_state(index),
                    build_index_description(index),
                    build_index_detail(index),
                    str(index.get("created_time")),
                ]
            )
        index_summary = (
            f"registered={indexes.get('registered_count', len(registered_indexes))}, "
            f"loaded={indexes.get('loaded_count')}, "
            f"key_loaded={indexes.get('key_loaded_count')}"
        )
        sections.append("")
        sections.append(
            format_box(
                "Indexes",
                f"{index_summary}\n\n"
                + format_table(
                    [
                        "Index",
                        "Dim",
                        "Rows",
                        "Type",
                        "Loaded",
                        "Key Info",
                        "State",
                        "Description",
                        "Encryption",
                        "Created",
                    ],
                    index_rows,
                    row_separator=True,
                )
                + "\n\nState legend: insert/search (index+key loaded), "
                "unavailable (index or key not loaded; instructions show which load command to run).",
            )
        )
        if indexes.get("error"):
            sections.append(f"Error: {indexes['error']}")

        local_config = snapshot.get("local_index_config")
        if local_config:
            config_pairs = []
            for key, value in local_config.items():
                if key == "index_params":
                    try:
                        value = json.dumps(value, sort_keys=True)
                    except TypeError:
                        value = str(value)
                config_pairs.append((key, value))
            local_config_table = format_table(
                ["Field", "Value"],
                [[key, str(value)] for key, value in config_pairs],
            )
            sections.append("")
            sections.append(
                format_box(
                    "Local Index Config (default parameters)",
                    local_config_table,
                )
            )

        return _PrettyInfo("\n".join(sections))

    def _connection_details(self):
        info = {"connected": False}
        if not self._indexer:
            info["error"] = "Indexer not initialized."
            return info
        is_connected = False
        try:
            is_connected = self._indexer.is_connected()
        except Exception as exc:
            info["error"] = str(exc)
        info["connected"] = is_connected
        connection = getattr(self._indexer, "connection", None)
        if connection:
            info["address"] = getattr(connection, "server_address", None)
            info["secure"] = getattr(connection, "secure", None)
        info["access_token_used"] = bool(getattr(self._indexer, "access_token", None))
        try:
            info["server_version"] = self._indexer.get_server_version()
        except Exception as exc:
            info["server_version_error"] = str(exc)
        return info

    def _keys_details(self, allow_remote: bool = True):
        info = {
            "active_key_id": self.index_config.key_param.key_id if self._index_config else None,
            "registered": [],
            "registered_count": None,
            "loaded_count": None,
        }
        if not self._indexer:
            info["error"] = "Indexer not initialized."
            return info
        if not allow_remote or not self._indexer.is_connected():
            info["error"] = "Indexer not connected."
            return info
        try:
            key_ids = self._indexer.get_key_list()
        except Exception as exc:
            info["error"] = str(exc)
            return info
        for key_id in key_ids or []:
            try:
                info["registered"].append(self._indexer.get_key_info(key_id))
            except Exception as exc:
                info["registered"].append({"key_id": key_id, "error": str(exc)})
        info["registered_count"] = len(info["registered"])
        info["loaded_count"] = sum(1 for key in info["registered"] if key.get("is_loaded"))
        return info

    def _indexes_details(self, allow_remote: bool = True):
        info = {
            "active_index_name": self.index_config.index_name if self._index_config else None,
            "registered": [],
            "registered_count": None,
            "loaded_count": None,
            "key_loaded_count": None,
        }
        if not self._indexer:
            info["error"] = "Indexer not initialized."
            return info
        if not allow_remote or not self._indexer.is_connected():
            info["error"] = "Indexer not connected."
            return info
        try:
            index_names = self._indexer.get_index_list()
        except Exception as exc:
            info["error"] = str(exc)
            return info
        for index_name in index_names or []:
            try:
                info["registered"].append(self._indexer.get_index_info(index_name))
            except Exception as exc:
                info["registered"].append({"index_name": index_name, "error": str(exc)})
        info["registered_count"] = len(info["registered"])
        info["loaded_count"] = sum(1 for index in info["registered"] if index.get("is_loaded"))
        info["key_loaded_count"] = sum(1 for index in info["registered"] if index.get("is_key_loaded"))
        return info

    def _local_index_config_details(self):
        if not self._index_config:
            return None
        cfg = self._index_config
        index_params = dict(cfg.index_param.index_params)
        if "centroids" in index_params:
            centroids = index_params["centroids"]
            shape = getattr(centroids, "shape", None)
            if shape:
                index_params["centroids"] = f"<array shape={shape}>"
            else:
                index_params["centroids"] = f"<{type(centroids).__name__}>"
        return {
            "index_name": cfg.index_name,
            "description": cfg.description,
            "dim": cfg.context_param.dim,
            "preset": cfg.context_param.preset_name,
            "eval_mode": cfg.context_param.eval_mode_name,
            "key_path": cfg.key_param.key_path,
            "key_id": cfg.key_param.key_id,
            "seal_mode": cfg.key_param.seal_mode_name,
            "metadata_encryption": cfg.key_param.metadata_encryption,
            "index_encryption": cfg.index_param.index_encryption,
            "query_encryption": cfg.index_param.query_encryption,
            "index_type": cfg.index_param.index_type,
            "index_params": index_params,
        }

    def reset(self):
        """
        Resets the EnvectorClient by deleting all index and registered key in Server.

        Returns:
            EnvectorClient: The reset EnvectorClient object.
        """
        index_list = self.indexer.get_index_list()
        key_list = self.indexer.get_key_list()
        if index_list:
            logger.info(f"Indexes {index_list} will be cleared.")
            for index_name in index_list:
                self.drop_index(index_name)
        if key_list:
            logger.info(f"Keys {key_list} will be deleted.")
            for key_id in key_list:
                self.delete_key(key_id)
        self._indexer = None
        self._index_config = None
        logger.info("EnvectorClient instance has been reset.")
        return self


pyenvector_client = EnvectorClient()
# Backward compatibility for older imports
ES2 = EnvectorClient
es2_client = pyenvector_client

"""
Functions:
    init_connect: Initializes the connection to the enVector server.
    init_index_config: Initializes the index configuration.
    create_index: Creates a new index.
    init: Initializes the EnvectorClient environment.
"""


def init_connect(*args, **kwargs):
    """
    Initialize the connection to the enVector server.

    Parameters
    ----------
    host : str, optional
        The host address to connect to enVector server.
    port : int, optional
        The port number to connect to enVector server.
    address : str, optional
        The full address (overrides host/port) to connect to enVector server.
    access_token : str, optional
        The access token to connect to enVector server.
    secure : bool, optional
        Whether to use a secure connection. If None, defaults to True when access_token is provided,
        otherwise False.

    Returns
    -------
    EnvectorClient
        The initialized EnvectorClient object.
    """
    return pyenvector_client.init_connect(*args, **kwargs)


def init_index_config(*args, **kwargs):
    """
    Initialize the index configuration.

    Parameters
    ----------
    index_name : str, optional
        The name of the index.
    dim : int, optional
        The dimensionality of the index.
    key_path : str, optional
        The path to the key directory.
    key_id : str, optional
        The key ID.
    seal_mode : str, optional
        The seal mode.
    seal_kek_path : str, optional
        Path or bytes for the KEK used during sealing.
    preset : str, optional
        The preset for the key.
    eval_mode : str, optional
        The evaluation mode.
    query_encryption : str, optional
        The encryption type for query, e.g. "plain", "cipher", "hybrid".
    index_encryption : str, optional
        The encryption type for database, e.g. "plain", "cipher", "hybrid".
    index_params : dict, optional
        The parameters for the index.
    description : str, optional
        A human-readable description for the index.
    index_type : str, optional
        Convenience alias for ``index_params['index_type']``.
    metadata_encryption : bool, optional
        Whether metadata encryption is enabled.
    auto_key_setup : bool, optional
        Whether to automatically generate/register the key (default True).
    use_key_stream : bool, optional
        Supply keys as in-memory byte streams instead of file paths.
    enc_key : bytes, optional
        Encryption key bytes when ``use_key_stream`` is enabled.
    eval_key : bytes, optional
        Evaluation key bytes when ``use_key_stream`` is enabled.
    sec_key : bytes, optional
        Secret key bytes when ``use_key_stream`` is enabled.
    metadata_key : bytes, optional
        Metadata key bytes when ``use_key_stream`` is enabled.
    seal_kek : bytes, optional
        In-memory KEK bytes overriding ``seal_kek_path``.

    Returns
    -------
    EnvectorClient
        The initialized EnvectorClient object.
    """
    return pyenvector_client.init_index_config(*args, **kwargs)


def create_index(*args, **kwargs):
    """
    Create a new index.

    Parameters
    ----------
    index_name : str, optional
        The name of the index.
    dim : int, optional
        The dimensionality of the index.
    key_path : str, optional
        The path to the key directory.
    key_id : str, optional
        The key ID.
    seal_mode : str, optional
        The seal mode.
    seal_kek_path : str, optional
        Path or bytes for the KEK used during sealing.
    preset : str, optional
        The preset for the key.
    eval_mode : str, optional
        The evaluation mode.
    query_encryption : str, optional
        The encryption type for query, e.g. "plain", "cipher", "hybrid".
    index_encryption : str, optional
        The encryption type for database, e.g. "plain", "cipher", "hybrid".
    index_params : dict, optional
        The parameters for the index.
    description : str, optional
        A human-readable description for the index.
    index_type : str, optional
        Convenience alias for ``index_params['index_type']``.
    metadata_encryption : bool, optional
        Whether metadata should be encrypted.
    use_key_stream : bool, optional
        Supply keys as in-memory byte streams instead of file paths.
    enc_key : bytes, optional
        Encryption key bytes when ``use_key_stream`` is enabled.
    eval_key : bytes, optional
        Evaluation key bytes when ``use_key_stream`` is enabled.
    sec_key : bytes, optional
        Secret key bytes when ``use_key_stream`` is enabled.
    metadata_key : bytes, optional
        Metadata key bytes when ``use_key_stream`` is enabled.
    seal_kek : bytes, optional
        In-memory KEK bytes overriding ``seal_kek_path``.

    Returns
    -------
    Index
        The created index object.
    """
    return pyenvector_client.create_index(*args, **kwargs)


def init(*args, **kwargs):
    """
    Initialize the EnvectorClient environment (connection, key, and index config).

    Parameters
    ----------
    host : str, optional
        The host address to connect to enVector server.
    port : int, optional
        The port number to connect to enVector server.
    address : str, optional
        The full address to connect to enVector server.
    access_token : str, optional
        The access token to connect to enVector server.
    secure : bool, optional
        Whether to use a secure connection. If None, defaults to True when access_token is provided,
        otherwise False.
    index_name : str, optional
        The name of the index.
    dim : int, optional
        The dimensionality of the index.
    key_path : str, optional
        The path to the key directory.
    key_id : str, optional
        The key ID.
    seal_mode : str, optional
        Seal mode such as ``AES_KEK`` when secret keys are sealed at rest.
    seal_kek_path : str, optional
        Path to the KEK used to unseal secret keys.
    seal_kek : bytes, optional
        In-memory KEK bytes overriding ``seal_kek_path``.
    preset : str, optional
        The preset for the key.
    eval_mode : str, optional
        The evaluation mode.
    query_encryption : str, optional
        The encryption type for query, e.g. "plain", "cipher", "hybrid". Defaults to ``plain``.
    index_encryption : str, optional
        The encryption type for database, e.g. "plain", "cipher", "hybrid". Defaults to ``cipher``.
    index_params : dict, optional
        The parameters for the index. Defaults to {"index_type": "flat"}.
    description : str, optional
        A human-readable description for the index.
    index_type : str, optional
        Convenience alias for ``index_params['index_type']``.
    metadata_encryption : bool, optional
        Whether metadata encryption is enabled.
    use_key_stream : bool, optional
        Whether to automatically read keys from in-memory byte streams.
    enc_key : bytes, optional
        Encryption key bytes when ``use_key_stream`` is enabled.
    eval_key : bytes, optional
        Evaluation key bytes when ``use_key_stream`` is enabled.
    sec_key : bytes, optional
        Secret key bytes when ``use_key_stream`` is enabled.
    metadata_key : bytes, optional
        Metadata key bytes when ``use_key_stream`` is enabled.
    auto_key_setup : bool, optional
        Whether to automatically generate and register the key. Defaults to ``True``.

    Returns
    -------
    EnvectorClient
        The initialized EnvectorClient object.

    Examples
    --------
    >>> import pyenvector as ev
    >>> ev.init(
    ...     host="localhost",
    ...     port=50050,
    ...     key_path="./keys",
    ...     key_id="example_key",
    ...     auto_key_setup=True
    ... )

    >>> import pyenvector as ev
    >>> ev.init(
    ...     address="localhost:50050",
    ...     key_path="./keys",
    ...     auto_key_setup=False,
    )
    """
    return pyenvector_client.init(*args, **kwargs)


def drop_index(index_name: str):
    """
    Drop the index with the given name.

    Parameters
    ----------
    index_name : str
        The name of the index to drop.

    Returns
    -------
    EnvectorClient
        The EnvectorClient object after dropping the index.
    """
    return pyenvector_client.drop_index(index_name)


def delete_key(key_id: str):
    """
    Delete the key with the given key_id.

    Parameters
    ----------
    key_id : str
        The ID of the key to delete.

    Returns
    -------
    EnvectorClient
        The EnvectorClient object after deleting the key.
    """
    return pyenvector_client.delete_key(key_id)


def generate_key(key_id: str):
    """
    Generate a key using the KeyGenerator.

    Parameters
    ----------
    key_id : str
        The ID of the key to generate.

    Returns
    -------
    None
    """
    return pyenvector_client.generate_key(key_id)


def register_key(key_id: str):
    """
    Register a key with the enVector server.

    Parameters
    ----------
    key_id : str
        The ID of the key to register.

    Returns
    -------
    None
    """
    return pyenvector_client.register_key(key_id)


def reset():
    """
    Reset the EnvectorClient by deleting all indexes and registered keys in the server.

    Returns
    -------
    EnvectorClient
        The reset EnvectorClient object.
    """
    return pyenvector_client.reset()


def is_connected():
    """
    Check if the EnvectorClient client is connected to the server.

    Returns
    -------
    bool
        True if connected, False otherwise.
    """
    return pyenvector_client.is_connected


def disconnect():
    """
    Disconnect the EnvectorClient client from the server.
    """
    return pyenvector_client.disconnect()


def describe(verbose: bool = False):
    """
    Return a snapshot of the EnvectorClient client state.

    Parameters
    ----------
    verbose : bool, optional
        When True, include detailed per-key and per-index information. Defaults to False for a
        concise summary.

    Returns
    -------
    dict
        Summary or detailed connection, key, and index information.
    """
    return pyenvector_client.describe(verbose=verbose)


def info(verbose: bool = False):
    """
    Return a formatted summary of the EnvectorClient client state.

    Parameters
    ----------
    verbose : bool, optional
        When True, include the detailed table view. Defaults to False for a minimal numeric summary.

    Returns
    -------
    str
        A human-readable description of the current client.
    """
    return pyenvector_client.info(verbose=verbose)


def get_key_list():
    """
    Retrieve the list of registered keys.

    Returns
    -------
    list
        A list of registered keys.
    """
    return pyenvector_client.get_key_list()


def get_key_info(key_id: str):
    """
    Retrieve the information of the registered key.

    Parameters
    ----------
    key_id : str
        The key ID.

    Returns
    -------
    dict
        A dictionary containing key information.
    """
    return pyenvector_client.get_key_info(key_id)


def get_index_list():
    """
    Retrieve the list of registered indexes.

    Returns
    -------
    list
        A list of registered indexes.
    """
    return pyenvector_client.get_index_list()


def get_index_info(index_name: str):
    """
    Retrieve the information of the registered index.

    Parameters
    ----------
    index_name : str
        The name of the index.

    Returns
    -------
    dict
        A dictionary containing index information.
    """
    return pyenvector_client.indexer.get_index_info(index_name)


def load_key(key_id: str):
    """
    Load a key with the enVector server.

    Parameters
    ----------
    key_id : str
        The ID of the key to load.

    Returns
    -------
    None
    """
    return pyenvector_client.load_key(key_id)


def unload_key(key_id: str):
    """
    Unload a key with the enVector server.

    Parameters
    ----------
    key_id : str
        The ID of the key to unload.

    Returns
    -------
    None
    """
    return pyenvector_client.unload_key(key_id)
