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

import contextlib
import os

# Suppress noisy gRPC core logs unless the app overrides them.
# This prevents lines like
#   I0000 ... ssl_transport_security.cc:1884 Handshake failed ... WRONG_VERSION_NUMBER
# from printing when a TLS handshake is attempted against a non-TLS endpoint.
if "GRPC_VERBOSITY" not in os.environ:
    os.environ["GRPC_VERBOSITY"] = "ERROR"
if "GRPC_TRACE" not in os.environ:
    os.environ["GRPC_TRACE"] = ""


import grpc

###################################
# Connection Class
###################################

MAX_MESSAGE_LENGTH = 1024 * 1024 * 100  # 10 MB


@contextlib.contextmanager
def _suppress_c_core_stderr():
    """
    Temporarily redirect process stderr (FD 2) to /dev/null.

    This suppresses gRPC C-core handshake logs like WRONG_VERSION_NUMBER that are
    emitted directly to stderr and not controllable via Python logging.
    """
    try:
        orig_fd = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        os.close(devnull)
        yield
    finally:
        try:
            os.dup2(orig_fd, 2)
        finally:
            os.close(orig_fd)


class Connection:
    def __init__(
        self,
        server_address: str,
        secure: bool = False,
    ):
        opts = [
            ("grpc.max_receive_message_length", MAX_MESSAGE_LENGTH),
            ("grpc.max_send_message_length", MAX_MESSAGE_LENGTH),
        ]
        self.server_address = server_address
        # Expose whether this channel was created with TLS for downstream diagnostics.
        self.secure = bool(secure)
        with _suppress_c_core_stderr():
            if secure:
                creds = grpc.ssl_channel_credentials()
                self.channel = grpc.secure_channel(server_address, creds, options=opts)
            else:
                self.channel = grpc.insecure_channel(server_address, options=opts)
            try:
                grpc.channel_ready_future(self.channel).result(timeout=3)
                self._connected = True
            except grpc.FutureTimeoutError:
                self._connected = False
                try:
                    self.channel.close()
                except Exception:
                    pass

    def is_connected(self) -> bool:
        return self._connected

    def get_channel(self):
        return self.channel

    def close(self):
        self.channel.close()
        self._connected = False
