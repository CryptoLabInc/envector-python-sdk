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

from typing import Optional

import evi

from pyenvector.crypto.parameter import ContextParameter
from pyenvector.utils.utils import validate_preset_evalmode

###################################
# Context Class
###################################


class Context:
    """
    Context encapsulates the context needed for homomorphic encryption operations.
    This object manages encryption parameters and state shared across encryption and decryption.

    Parameters
    ----------
    preset : str
        The parameter preset to use for the context. Supported: "ip1"/"ip2"
        (mm/mms), "ip3" (mm32/mms32).
    dim : int
        The dimension of the context, which should be a power of 2 (e.g., 32, 64, ..., 4096).
    eval_mode : str, optional
        The evaluation mode for the context. Defaults to "MM".

    Example
    --------
    >>> context = Context("ip1", dim=128)
    """

    def __init__(self, preset: str, dim: int, eval_mode: Optional[str] = None):
        if eval_mode is not None:
            validate_preset_evalmode(preset, eval_mode)
        self._parameter: ContextParameter = ContextParameter(preset, dim, eval_mode)
        self._context = evi.Context(
            self.parameter.preset, self.parameter.device_type, self.parameter.dim, self.parameter.eval_mode
        )

    @classmethod
    def _create_from_parameter(cls, parameter: ContextParameter):
        """
        Creates a Context instance from an existing ContextParameter object.

        Parameters
        ------------
        parameter : ContextParameter
            The ContextParameter object containing the preset, dimension, and device type.

        Returns
        ---------
        Context
            A new Context instance initialized with the provided ContextParameter.
        """
        return cls(parameter.preset, parameter.dim, parameter.eval_mode)

    @property
    def parameter(self) -> ContextParameter:
        """
        Returns the ContextParameter object associated with this context.

        Returns:
            ContextParameter: The parameter object for this context.
        """
        return self._parameter

    @property
    def preset(self) -> str:
        """
        Returns the name of the preset configuration.

        Returns:
            str: The name of the preset.
        """
        return self.parameter.preset

    @property
    def device_type(self) -> str:
        """
        Returns the name of the device type.

        Returns:
            str: The name of the device type, either "CPU" or "GPU".
        """
        return self.parameter.device_type_name

    @property
    def dim(self) -> int:
        """
        Returns the dimension of the context.

        Returns:
            int: The dimension of the context.
        """
        return self.parameter.dim

    @property
    def eval_mode(self) -> str:
        """
        Returns the evaluation mode for the context.

        Returns:
            str: The evaluation mode, e.g., RMP or MM.
        """
        return self.parameter.eval_mode

    @property
    def is_ip(self) -> bool:
        """
        Checks if the preset is of type "IP".

        Returns:
            bool: True if the preset is "IP", False otherwise.
        """
        return self.parameter.is_ip

    @property
    def is_qf(self) -> bool:
        """
        Checks if the preset is of type "QF".

        Returns:
            bool: True if the preset is "QF", False otherwise.
        """
        return self.parameter.is_qf

    @property
    def search_type(self) -> str:
        """
        Returns the search type based on the preset.

        Returns:
            str: The search type, either "IP" or "QF".
        """
        return self.parameter.search_type

    def __repr__(self):
        """
        Returns a string representation of the Context object.
        """
        return f"Context(\n  preset={self.preset.name},\n  dim={self.dim},\n  eval_mode={self.eval_mode.name},\n)"
