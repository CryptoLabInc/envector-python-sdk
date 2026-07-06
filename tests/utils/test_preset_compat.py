# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
# ========================================================================================

"""Tests for pyenvector.utils.utils.validate_preset_evalmode.

Mirrors services/internal/utils/preset_test.go on the Go side. Pure Python,
no evi dependency, so this runs without the native extension built.
"""

import pytest

from pyenvector.utils.utils import validate_preset_evalmode


@pytest.mark.parametrize(
    "preset, eval_mode",
    [
        # Empty short-circuits.
        ("", ""),
        ("", "mm32"),
        ("ip2", ""),
        # mm / mms pair with ip1 or ip2 (u64 path). IP2 was demoted from the
        # u32 path to u64 (companion to evi PR #698), so it is valid here.
        ("ip1", "mm"),
        ("ip1", "mms"),
        ("ip2", "mm"),
        ("ip2", "mms"),
        # mm32 / mms32 accept ip3 only (u32 path).
        ("ip3", "mm32"),
        ("ip3", "mms32"),
        # Case-insensitive.
        ("IP3", "MMS32"),
        ("Ip2", "Mm"),
        # Passthrough eval modes.
        ("ip1", "rmp"),
        ("ip3", "rmp"),
        ("ip2", "flat"),
        ("ip2", "future_mode"),
    ],
)
def test_validate_preset_evalmode_accepts(preset, eval_mode):
    validate_preset_evalmode(preset, eval_mode)


@pytest.mark.parametrize(
    "preset, eval_mode",
    [
        # ip2 no longer pairs with the u32 modes after the u64 demotion.
        ("ip2", "mm32"),
        ("ip2", "mms32"),
        ("ip3", "mm"),
        ("ip3", "mms"),
        ("ip1", "mm32"),
        ("ip1", "mms32"),
        ("IP1", "MM32"),
        ("IP2", "MMS32"),
    ],
)
def test_validate_preset_evalmode_rejects(preset, eval_mode):
    with pytest.raises(ValueError, match="not compatible"):
        validate_preset_evalmode(preset, eval_mode)


def test_validate_preset_evalmode_accepts_enum_inputs():
    """Context._create_from_parameter passes evi.ParameterPreset / evi.EvalMode
    enums (not strings) through this validator. Both code paths must handle
    objects exposing ``.name`` without calling string methods directly.
    """

    class _Enum:
        def __init__(self, name):
            self.name = name

    validate_preset_evalmode(_Enum("IP1"), _Enum("MM"))
    validate_preset_evalmode(_Enum("IP3"), _Enum("MMS32"))
    with pytest.raises(ValueError, match="not compatible"):
        validate_preset_evalmode(_Enum("IP3"), _Enum("MM"))
