import pytest

from pyenvector.crypto.context import Context
from pyenvector.crypto.parameter import ContextParameter


@pytest.mark.parametrize(
    "preset, dim, eval_mode, expected_preset, expected_search_type",
    [
        ("IP1", 32, "MM", "IP1", "IP"),
        ("IP1", 64, "MM", "IP1", "IP"),
        ("IP1", 128, "MM", "IP1", "IP"),
        ("IP1", 256, "MM", "IP1", "IP"),
    ],
)
def test_context_initialization(preset, dim, eval_mode, expected_preset, expected_search_type):
    context = Context(preset=preset, dim=dim, eval_mode=eval_mode)
    assert context.preset.name == expected_preset
    assert context.dim == dim
    assert context.eval_mode.name == eval_mode
    assert context.search_type == expected_search_type


def test_context_from_parameter():
    parameter = ContextParameter(preset="IP1", dim=128, eval_mode="MM")
    context = Context._create_from_parameter(parameter)
    assert context.preset == parameter.preset
    assert context.dim == parameter.dim
    assert context.eval_mode == parameter.eval_mode
    assert context.search_type == parameter.search_type


def test_context_invalid_preset():
    with pytest.raises(ValueError):
        Context(preset="INVALID", dim=128)


def test_context_invalid_eval_mode():
    with pytest.raises(ValueError):
        Context(preset="IP1", dim=123, eval_mode="NONE")
