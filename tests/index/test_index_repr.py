"""Tests for the human-readable ``__repr__`` of ``IndexConfig`` and ``Index``.

These lock in the formatting contract introduced to make REPL/debug output
readable: pretty aligned ``key = value`` lines, omission of unset (``None``)
fields, IVF-only clustering params, and a nested-but-indented Index repr.
"""

from pyenvector.index.index import Index, IndexConfig


def _flat_config():
    return IndexConfig(
        index_name="test_index",
        dim=32,
        key_path="./keys",
        key_id="test_key",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "flat"},
    )


def _ivf_config():
    return IndexConfig(
        index_name="efr_mm32",
        dim=512,
        key_path="./keys",
        key_id="efr_key_mm32",
        preset="ip1",
        query_encryption="plain",
        index_encryption="cipher",
        index_params={"index_type": "ivf_vct", "nlist": 1024, "default_nprobe": 8},
    )


def test_index_config_repr_is_pretty_and_shows_core_fields():
    r = repr(_flat_config())

    assert r.startswith("IndexConfig(\n")
    assert r.endswith("\n)")
    # Core fields are surfaced...
    assert "index_name" in r
    assert "'test_index'" in r
    assert "index_type" in r
    assert "FLAT" in r  # index_type is normalized to upper-case
    assert "key_id" in r
    # ...as aligned ``key = value`` lines.
    assert " = " in r


def test_index_config_repr_omits_unset_fields():
    r = repr(_flat_config())

    # description was never set -> not rendered at all.
    assert "description" not in r
    # Unset fields are dropped entirely, so no bare ``None`` noise leaks in.
    assert "None" not in r


def test_index_config_repr_excludes_encryption_and_cipher_fields():
    r = repr(_flat_config())

    # Encryption modes were intentionally dropped from the representation.
    assert "index_encryption" not in r
    assert "query_encryption" not in r


def test_index_config_repr_flat_hides_ivf_params():
    r = repr(_flat_config())

    # nlist / default_nprobe are meaningless for a FLAT index.
    assert "nlist" not in r
    assert "default_nprobe" not in r


def test_index_config_repr_ivf_shows_clustering_params():
    r = repr(_ivf_config())

    assert "IVF_VCT" in r
    assert "nlist" in r
    assert "1024" in r
    assert "default_nprobe" in r
    assert "8" in r


def test_index_repr_indents_config_omits_cipher():
    # repr only reads ``index_config`` and ``num_entities``; build a bare
    # instance to avoid the indexer connection / cipher setup that __init__ does.
    index = object.__new__(Index)
    index.index_config = _ivf_config()
    index.num_entities = 0
    index._is_loaded = False

    r = repr(index)

    assert r.startswith("Index(\n")
    assert "config" in r
    assert "IndexConfig(" in r  # nested config is embedded
    assert "num_entities = 0" in r
    assert "is_loaded" in r
    assert "= False" in r
    # cipher was intentionally removed from the Index representation.
    assert "cipher" not in r
