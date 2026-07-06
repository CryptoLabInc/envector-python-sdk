"""Live e2e for named partitions. Covers:
  - management API (create/list/drop)
  - insert routing + single-partition search isolation (FLAT)
  - (a) multi-partition search merge
  - (b) IVF_VCT named partitions

    cd sdk/python && pipenv run python example/client_and_server/partition/partition_e2e.py --port <port>
"""

import argparse
import numpy as np

import pyenvector as ev
from pyenvector.utils.utils import resolve_preset


def vecs(rng, n, dim):
    v = rng.uniform(-1, 1, (n, dim))
    return v / np.linalg.norm(v, axis=1, keepdims=True)


def run_case(a, index_type):
    preset = resolve_preset(a.preset, a.eval_mode)
    key_id = a.key_id or f"part-key-{a.eval_mode}-{preset}"
    ev.init(address=f"{a.host}:{a.port}", key_path="./keys", key_id=key_id, eval_mode=a.eval_mode, preset=preset)

    name = f"{a.index_name}_{index_type.lower()}"
    if name in ev.get_index_list():
        ev.drop_index(name)

    dim = a.dim
    if index_type == "FLAT":
        params = {"index_type": "FLAT"}
        sp = None
    else:  # IVF_VCT
        params = {"index_type": "IVF_VCT", "nlist": a.nlist, "default_nprobe": a.nlist}
        sp = {"nprobe": a.nlist}

    index = ev.create_index(name, dim, index_params=params)
    ev.create_partition(name, "prod")
    assert sorted(p["name"] for p in ev.list_partitions(name)) == ["_default", "prod"]

    rng = np.random.default_rng(7)
    dflt = vecs(rng, a.num, dim)
    prod = vecs(rng, a.num, dim)
    index.insert(dflt, metadata=[f"default-{i}" for i in range(a.num)], execute_until="segmentation", await_completion=True, load=True)
    index.insert(prod, metadata=[f"prod-{i}" for i in range(a.num)], partition_name="prod", execute_until="segmentation", await_completion=True, load=True)
    counts = {p["name"]: p["num_vectors"] for p in ev.list_partitions(name)}
    print(f"[{index_type}] num_vectors: {counts}")
    index.load()

    prod_hits = index.search(prod[0], top_k=5, output_fields=["metadata"], search_params=sp, partition_names=["prod"])
    dflt_hits = index.search(dflt[0], top_k=5, output_fields=["metadata"], search_params=sp, partition_names=["_default"])
    # search() returns a bare [] when a query scores nothing, so guard the [0].
    prod_top = prod_hits[0] if prod_hits else []
    dflt_top = dflt_hits[0] if dflt_hits else []
    prod_ok = prod_top and all(str(h.get("metadata")).startswith("prod-") for h in prod_top)
    dflt_ok = dflt_top and all(str(h.get("metadata")).startswith("default-") for h in dflt_top)
    print(f"[{index_type}] single-partition isolation: prod_only={prod_ok} default_only={dflt_ok}")

    # (a) multi-partition search: union across both partitions, merged top-k.
    both = index.search(prod[0], top_k=10, output_fields=["metadata"], search_params=sp, partition_names=["prod", "_default"])
    metas = [str(h.get("metadata")) for h in (both[0] if both else [])]
    has_prod = any(m.startswith("prod-") for m in metas)
    has_dflt = any(m.startswith("default-") for m in metas)
    # prod[0] is a prod vector, so its own best match should rank #1 from prod.
    print(f"[{index_type}] multi-partition merge: results={len(metas)} has_prod={has_prod} has_default={has_dflt} top={metas[0] if metas else None}")
    assert prod_ok and dflt_ok and has_prod and has_dflt, f"[{index_type}] FAIL"

    ev.drop_partition(name, "prod")
    assert "prod" not in [p["name"] for p in ev.list_partitions(name)]
    ev.drop_index(name)
    print(f"[{index_type}] OK")


def main(a):
    run_case(a, "FLAT")
    run_case(a, "IVF_VCT")
    print("ALL PARTITION E2E CASES PASSED")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=50050)
    p.add_argument("--dim", type=int, default=128)
    p.add_argument("--num", type=int, default=50)
    p.add_argument("--nlist", type=int, default=8)
    p.add_argument("--eval-mode", default="mm32", choices=["mm", "mms", "mm32", "mms32"])
    p.add_argument("--preset", default=None)
    p.add_argument("--key-id", default=None)
    p.add_argument("--index-name", default="partidx")
    main(p.parse_args())
