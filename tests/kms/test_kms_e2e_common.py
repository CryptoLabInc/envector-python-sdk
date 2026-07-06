import sys
import types
from pathlib import Path


_STUBBED_MODULES = {}


def _stub_module(name, **attrs):
    if name not in _STUBBED_MODULES:
        _STUBBED_MODULES[name] = sys.modules.get(name)
    module = types.ModuleType(name)
    for attr_name, attr_value in attrs.items():
        setattr(module, attr_name, attr_value)
    sys.modules[name] = module
    return module


class _StubClient:
    pass


_stub_module("pyenvector", __path__=[])
_stub_module("pyenvector.client", __path__=[])
_stub_module("pyenvector.client.client", EnvectorClient=_StubClient)
_stub_module("pyenvector.kms", __path__=[])
_stub_module("pyenvector.kms.client", KMSClient=_StubClient)
_stub_module("pyenvector.proto_gen", __path__=[])
_stub_module("pyenvector.proto_gen.v2", __path__=[])
_stub_module("pyenvector.proto_gen.v2.common", __path__=[])
_stub_module("pyenvector.proto_gen.v2.common.type_pb2")

_KMS_EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "example" / "client_and_server" / "kms"
if str(_KMS_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_KMS_EXAMPLE_DIR))

from _kms_e2e_common import configure_local_kms_tls_roots

for _module_name, _previous_module in _STUBBED_MODULES.items():
    if _previous_module is None:
        sys.modules.pop(_module_name, None)
    else:
        sys.modules[_module_name] = _previous_module


def test_configure_local_kms_tls_roots_uses_integration_ca(monkeypatch, tmp_path):
    ca_path = tmp_path / "root_ca.crt"
    ca_path.write_text("test-ca", encoding="utf-8")
    monkeypatch.setenv("KMS_INTEGRATION_CACERT", str(ca_path))

    assert configure_local_kms_tls_roots("localhost:50060", secure=True) == str(ca_path)


def test_configure_local_kms_tls_roots_ignores_ca_for_nonlocal_kms(monkeypatch, tmp_path):
    ca_path = tmp_path / "root_ca.crt"
    ca_path.write_text("test-ca", encoding="utf-8")
    monkeypatch.setenv("KMS_INTEGRATION_CACERT", str(ca_path))

    assert configure_local_kms_tls_roots("kms.example.com:50060", secure=True) is None


def test_configure_local_kms_tls_roots_disabled_for_plaintext(monkeypatch, tmp_path):
    ca_path = tmp_path / "root_ca.crt"
    ca_path.write_text("test-ca", encoding="utf-8")
    monkeypatch.setenv("KMS_INTEGRATION_CACERT", str(ca_path))

    assert configure_local_kms_tls_roots("localhost:50060", secure=False) is None
