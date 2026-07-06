"""
enVector QA: Index.num_entities consistency (row_count regression check)

Background
----------
`Index.num_entities` is sourced from `indexes.row_count` on the backend. A bug
in the merge cutover paths (applyMergeUpdate / applyMergeBatchWithRawCutover)
was double-counting items that had already been counted at raw-shard publish,
causing `row_count` to diverge from `SUM(shards.num_vectors)` (observed ~4x
inflation in production). The same fix also defers raw-shard delete targets to
the cutover late-binding path so IVF_VCT deletes do not fail on missing
shard_nodemap snapshots.

This QA runs both FLAT and IVF_VCT in one invocation (distinct index names) so
both code paths are exercised. For each scenario:
  Phase 1: insert in batches → forces raw-shard publish + cutover.
  Phase 2: settle merges.
  Phase 3: assert `num_entities == total_inserted` (regression of the
           row_count double-count would 2x-4x this).
  Phase 4: delete K items, assert `num_entities == total - K` immediately.
           GetIndexInfo surfaces a live count from shard_map
           (deprecated=FALSE on SEARCHABLE shards), so the value reflects the
           deletion as soon as DeleteData Phase 1 commits — even for
           raw-shard targets whose physical expunge is still pending.

How to run
----------
    python ./example/client_and_server/e2e/num_entities_consistency.py \
        --reset \
        --types flat,vct \
        --num-batches 6 \
        --batch-size 32

Manual cross-check (requires DB access, optional)
-------------------------------------------------
    SELECT row_count FROM indexes WHERE index_name = '<index>';
    SELECT COALESCE(SUM(num_vectors), 0) FROM shards WHERE index_name = '<index>';
    -- Both values must match the SDK-reported num_entities.
"""

import argparse
import time
from typing import List

import numpy as np

import pyenvector as ev
from pyenvector.utils.utils import resolve_preset

BASE_VECTOR_SEED = 42


def get_random_vector(dim: int, seed: int) -> List[float]:
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")
    np.random.seed(seed)
    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


def insert_batch_and_wait(
    index,
    vectors: List[List[float]],
    metadata: List[str],
    timeout_s: float,
    poll_interval_s: float,
) -> List[int]:
    """Insert a batch, wait until searchable, return the item_ids assigned."""
    if index.cipher is None:
        raise RuntimeError("Cipher is not initialized. Ensure index encryption is enabled.")

    is_ivf = index.index_config.index_type.upper() in ("IVF_FLAT", "IVF_VCT")
    if is_ivf:
        nlist = max(1, index.index_config.index_param.nlist)
        centroids = [i % nlist for i in range(len(vectors))]
    else:
        centroids = None

    encrypted = index.cipher.encrypt_multiple(vectors, encode_type="item", centroids_idx=centroids)
    metadata_for_insert = index._encrypt_metadata_list(metadata)
    prepared_metadata = index._prepare_metadata_for_chunk(metadata_for_insert, encrypted.num_item_list)

    out_request_id: List[str] = []
    item_ids = index.indexer.insert_data_bulk(
        index_name=index.index_config.index_name,
        enc_vec=encrypted.data,
        numitems=encrypted.num_item_list,
        metadata=prepared_metadata,
        centroid_idx=centroids,
        out_request_id=out_request_id,
    )
    assert len(out_request_id) == 1, f"Expected 1 request_id, got {len(out_request_id)}"

    status = index.indexer.wait_for_insert_searchable(
        index_name=index.index_config.index_name,
        request_id=out_request_id[0],
        timeout_s=timeout_s,
        poll_interval_s=poll_interval_s,
    )
    assert status.done, "wait_for_insert_searchable returned done=false"
    return list(item_ids)


def assert_eq(name: str, got, expected):
    if got != expected:
        raise AssertionError(f"FAIL {name}: got={got} expected={expected}")
    print(f"  OK   {name}: {got}")


def make_index_params(index_type: str, nlist: int, nprobe: int):
    t = index_type.lower()
    if t == "flat":
        return {"index_type": "FLAT"}
    if t == "ivf":
        return {"index_type": "IVF_FLAT", "nlist": nlist, "default_nprobe": nprobe}
    if t == "vct":
        return {"index_type": "IVF_VCT", "nlist": nlist, "default_nprobe": nprobe}
    raise ValueError(f"unknown index type: {index_type}")


def run_scenario(type_label: str, index_name: str, args: argparse.Namespace) -> None:
    """Run the full Phase 1..4 cycle for one index type. Raises on assertion failure."""
    print(f"\n{'#' * 70}\n# Scenario: type={type_label}, index_name={index_name}\n{'#' * 70}")

    index_params = make_index_params(type_label, args.nlist, args.nprobe)
    index = ev.create_index(index_name, args.dim, index_params=index_params)
    print(f"Index '{index_name}' created (dim={args.dim}, type={index_params['index_type']}).")

    all_item_ids: List[int] = []
    seed_cursor = 0

    print("\n=== Phase 1: insert in batches (forces multiple raw shards + merges) ===")
    for batch_idx in range(args.num_batches):
        vectors = [
            get_random_vector(args.dim, seed=BASE_VECTOR_SEED + seed_cursor + i)
            for i in range(args.batch_size)
        ]
        metadata = [f"b{batch_idx}-i{i}" for i in range(args.batch_size)]
        seed_cursor += args.batch_size
        item_ids = insert_batch_and_wait(
            index,
            vectors,
            metadata,
            timeout_s=args.timeout_s,
            poll_interval_s=args.poll_interval_s,
        )
        all_item_ids.extend(item_ids)
        print(f"  batch={batch_idx} inserted={len(item_ids)} cumulative={len(all_item_ids)}")

    print("\n=== Phase 2: wait for merge cutovers to settle ===")
    print(f"  sleeping {args.merge_settle_s}s for background merges...")
    time.sleep(args.merge_settle_s)

    print("\n=== Phase 3: fresh handle re-reads server-side row_count ===")
    fresh = ev.Index(index_name)
    expected_total = len(all_item_ids)
    print(f"  fresh.num_entities={fresh.num_entities} expected={expected_total}")
    assert_eq("num_entities after inserts", fresh.num_entities, expected_total)

    if args.delete_count > 0:
        print("\n=== Phase 4: delete K items, assert num_entities == N-K immediately ===")
        if args.delete_count > len(all_item_ids):
            raise ValueError(
                f"--delete-count={args.delete_count} exceeds inserted={len(all_item_ids)}"
            )
        to_delete = all_item_ids[: args.delete_count]
        print(f"  deleting {len(to_delete)} item_ids (sample={to_delete[:5]}...)")
        # The low-level insert_data_bulk path used in Phase 1 does not refresh
        # the client-side _is_loaded flag (only Index.insert() does). Force a
        # load here so Index.delete()'s is_loaded gate passes (idempotent).
        index.load()
        # await_completion=True (default) polls until DELETE reaches SEARCHABLE.
        index.delete(to_delete)

        # GetIndexInfo returns a live count from shard_map (deprecated=FALSE
        # joined onto SEARCHABLE shards), so num_entities should already
        # reflect the deletion — no waiting for cutover + forced merge.
        refetched = ev.Index(index_name)
        expected_after = expected_total - len(to_delete)
        print(f"  refetched.num_entities={refetched.num_entities} expected={expected_after}")
        assert_eq("num_entities after delete", refetched.num_entities, expected_after)

    print(f"\n  Scenario '{type_label}' PASSED  (inserted={expected_total}, batches={args.num_batches} × {args.batch_size})")

    if not args.skip_cleanup:
        ev.drop_index(index_name)
        print(f"  Cleanup: dropped '{index_name}'.")


def main(args: argparse.Namespace) -> None:
    address = f"{args.host}:{args.port}"

    if args.reset:
        ev.init_connect(address=address)
        ev.reset()

    # Match the convention used by other e2e scripts (delete_data.py, e2e.py):
    # --preset and --key-id are optional overrides supplied by the CI runner.
    # When absent, derive them from --eval-mode.
    preset = resolve_preset(args.preset, args.eval_mode)
    key_id = args.key_id or f"test-key-{args.eval_mode}-{preset}"
    ev.init(
        address=address,
        key_path="./keys",
        key_id=key_id,
        eval_mode=args.eval_mode,
        preset=preset,
    )

    types = [t.strip() for t in args.types.split(",") if t.strip()]
    if not types:
        raise ValueError("--types is empty")

    results = {}
    for type_label in types:
        index_name = f"{args.index_name_prefix}_{type_label}"
        try:
            run_scenario(type_label, index_name, args)
            results[type_label] = "PASS"
        except Exception as exc:
            results[type_label] = f"FAIL: {exc}"
            # Try to cleanup on failure so the next scenario starts clean.
            if not args.skip_cleanup:
                try:
                    ev.drop_index(index_name)
                except Exception:
                    pass
            raise
        finally:
            print(f"\n  → {type_label}: {results[type_label]}")

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    for type_label, outcome in results.items():
        print(f"  {type_label}: {outcome}")
    if all(v == "PASS" for v in results.values()):
        print("\nnum_entities consistency: ALL SCENARIOS PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="num_entities row_count consistency QA")
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=50050)
    parser.add_argument("--dim", type=int, default=512)
    parser.add_argument(
        "--types",
        type=str,
        default="flat,vct",
        help="Comma-separated index types to test sequentially. Choices: flat, ivf, vct.",
    )
    parser.add_argument(
        "--num-batches",
        type=int,
        default=4,
        help="Number of insert batches (multiple batches force raw-shard publishes + merges)",
    )
    parser.add_argument("--batch-size", type=int, default=32, help="Vectors per batch")
    parser.add_argument(
        "--delete-count",
        type=int,
        default=2,
        help="Items to delete in Phase 4 (set 0 to skip the delete check)",
    )
    parser.add_argument("--nlist", type=int, default=8, help="Number of clusters (nlist) for IVF/VCT")
    parser.add_argument("--nprobe", type=int, default=4, help="Number of probes (nprobe) for IVF/VCT")
    parser.add_argument(
        "--index-name-prefix",
        type=str,
        default="num_entities_qa",
        help="Index name prefix; per-scenario index will be '<prefix>_<type>'",
    )
    parser.add_argument(
        "--eval-mode",
        type=str,
        default="mm32",
        choices=["mm", "mm32", "mms", "mms32"],
        help="Evaluation mode",
    )
    parser.add_argument(
        "--key-id",
        type=str,
        default=None,
        help="Key id override (default: derived from eval_mode + preset)",
    )
    parser.add_argument(
        "--preset",
        type=str,
        choices=["ip1", "ip2", "ip3"],
        default=None,
        help="Preset override. Default: ip1 for mm/mms, ip3 for mm32/mms32.",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=60.0,
        help="Per-batch wait_for_insert_searchable timeout",
    )
    parser.add_argument("--poll-interval-s", type=float, default=1.0)
    parser.add_argument(
        "--merge-settle-s",
        type=float,
        default=5.0,
        help="Sleep between Phase 1 and Phase 3 to let merge cutovers run",
    )
    parser.add_argument("--reset", action="store_true", default=False)
    parser.add_argument("--skip-cleanup", action="store_true", default=False)
    main(parser.parse_args())
