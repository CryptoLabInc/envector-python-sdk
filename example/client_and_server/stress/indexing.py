"""
Load test: insert / unload / (load → search → unload)* until MERGED_SAVED

Per iteration the script:
  1. Inserts N vectors with ``await_completion=False`` (default N=5)
  2. Unloads the index
  3. Repeats {load → search all (or up to --search-limit) → unload} until
     every just-issued request_id has reached MERGED_SAVED. The search loop
     itself is the polling mechanism — there is no separate sleep/wait stage.

The cycle repeats ``--iterations`` times. Each cycle's per-stage wall times
are printed and a final summary aggregates totals. Useful for shaking out
load/unload + merge persistence interactions under sustained churn.
"""

import argparse
import time
from typing import List, Optional

import numpy as np

import pyenvector as ev

BASE_VECTOR_SEED = 42


def get_random_vector(dim: int, seed: int) -> np.ndarray:
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")
    rng = np.random.default_rng(seed)
    vec = rng.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec


def build_index_params(index_type: str, nlist: int, nprobe: int, centroids: Optional[np.ndarray]) -> dict:
    if index_type == "ivf":
        return {"index_type": "IVF_FLAT", "nlist": nlist, "default_nprobe": nprobe, "centroids": centroids}
    if index_type == "vct":
        return {"index_type": "IVF_VCT", "nlist": nlist, "default_nprobe": nprobe, "centroids": centroids}
    return {"index_type": "FLAT"}


def submit_inserts(
    index: "ev.Index",
    vectors: List[np.ndarray],
    centroids_idx: Optional[List[int]],
    base_metadata_id: int,
) -> List[str]:
    collected: List[str] = []
    for j, vec in enumerate(vectors):
        if centroids_idx is not None:
            cipher = index.cipher.encrypt(vec, centroids_idx=centroids_idx[j])
        else:
            cipher = index.cipher.encrypt(vec)
        rids: List[str] = []
        index.insert(
            cipher,
            metadata=[f"Item {base_metadata_id + j}"],
            request_ids=rids,
            await_completion=False,
            load=False,
        )
        collected.extend(rids)
    return collected


def main(args: argparse.Namespace) -> None:
    address = f"{args.host}:{args.port}"
    ev.init(
        address=address,
        key_path=args.key_path,
        key_id=args.key_id,
        eval_mode=args.eval_mode,
        preset=args.preset,
    )
    if not ev.is_connected():
        raise RuntimeError("Failed to connect to Indexer.")

    use_vct = args.index_type in ("ivf", "vct")
    search_params = {"nprobe": args.nprobe} if use_vct else {}

    if args.reset and args.index_name in ev.get_index_list():
        ev.drop_index(args.index_name)

    # Bootstrap: create index. For IVF/VCT we need centroids up front, so we fit
    # KMeans on a one-shot pool of vectors used only for centroid fitting.
    centroids = None
    if use_vct:
        from sklearn.cluster import KMeans

        pool = np.stack(
            [get_random_vector(args.dim, seed=BASE_VECTOR_SEED + i) for i in range(max(args.nlist * 4, 64))]
        )
        centroids = KMeans(n_clusters=args.nlist, random_state=BASE_VECTOR_SEED).fit(pool).cluster_centers_

    index_params = build_index_params(args.index_type, args.nlist, args.nprobe, centroids)
    index = ev.create_index(args.index_name, args.dim, index_params=index_params)

    print(
        f"[config] address={address} index={args.index_name} index_type={args.index_type} "
        f"dim={args.dim} iterations={args.iterations} insert/iter={args.num_vectors}"
    )

    totals = {"insert": 0.0, "unload_initial": 0.0, "search_loop": 0.0}
    totals_counts = {"search_rounds": 0, "search_calls": 0, "reload_search_calls": 0}
    seed_offset = 0
    metadata_offset = 1

    # Fixed pool of query vectors reused across every search round/iteration.
    # We only need *some* well-formed queries; their identity does not matter
    # for the stress test, and regenerating per-call wastes CPU.
    query_pool = [
        get_random_vector(args.dim, seed=BASE_VECTOR_SEED + i).tolist()
        for i in range(max(args.search_limit, args.num_vectors * args.iterations, 1))
    ]

    for it in range(1, args.iterations + 1):
        print(f"\n[iter {it}/{args.iterations}]")

        # 1) insert N vectors
        vectors = [get_random_vector(args.dim, seed=BASE_VECTOR_SEED + seed_offset + i) for i in range(args.num_vectors)]
        seed_offset += args.num_vectors

        centroids_idx = None
        if use_vct:
            from sklearn.metrics import pairwise_distances_argmin

            centroids_idx = pairwise_distances_argmin(np.stack(vectors), centroids).tolist()

        t0 = time.perf_counter()
        rids = submit_inserts(index, vectors, centroids_idx, base_metadata_id=metadata_offset)
        insert_s = time.perf_counter() - t0
        metadata_offset += args.num_vectors
        print(f"  insert {len(rids)} vectors: {insert_s:.3f}s")

        # 2) unload
        t0 = time.perf_counter()
        if index.is_loaded:
            index.unload()
        unload_initial_s = time.perf_counter() - t0
        print(f"  unload (initial):       {unload_initial_s:.3f}s")

        # 3) load → search → unload, repeated until all rids reach MERGED_SAVED.
        #    The search loop itself is the polling — no separate wait stage.
        round_idx = 0
        loop_start = time.perf_counter()
        search_calls_this_iter = 0
        while True:
            round_idx += 1
            t_load = time.perf_counter()
            index.load()
            load_s = time.perf_counter() - t_load

            total_rows = index.num_entities
            search_n = min(total_rows, args.search_limit) if args.search_limit > 0 else total_rows
            t_search = time.perf_counter()
            for i in range(search_n):
                results = index.search(
                    query_pool[i % len(query_pool)],
                    top_k=min(args.top_k, max(total_rows, 1)),
                    output_fields=["metadata"],
                    search_params=search_params,
                )
                assert results and results[0], "Expected at least one search hit"
                # The query was generated from the same seed as one of the
                # already-inserted vectors, so the top-1 score must be ~1.0.
                top_score = results[0][0]["score"]
                assert abs(top_score - 1.0) < args.score_tol, (
                    f"[iter? round {round_idx} query {i}] top-1 score {top_score:.4f} "
                    f"not within {args.score_tol} of 1.0"
                )
            search_s = time.perf_counter() - t_search
            search_calls_this_iter += search_n

            merged = index.all_merged_saved(rids)

            t_unload = time.perf_counter()
            index.unload()
            unload_s = time.perf_counter() - t_unload

            print(
                f"  round {round_idx:>3d}: load={load_s:.3f}s "
                f"search {search_n}/{total_rows}={search_s:.3f}s "
                f"unload={unload_s:.3f}s merged_saved={merged}"
            )

            if merged:
                break
            if args.round_interval > 0:
                time.sleep(args.round_interval)

        # 4) After MERGED_SAVED, run extra load/search/unload cycles to
        #    exercise the merged index under repeated reload churn. Tracked with
        #    its own counter/label so the two phases stay comparable.
        reload_search_calls_this_iter = 0
        for reload_idx in range(args.reload_cycles):
            t_load = time.perf_counter()
            index.load()
            load_s = time.perf_counter() - t_load

            total_rows = index.num_entities
            search_n = min(total_rows, args.search_limit) if args.search_limit > 0 else total_rows
            t_search = time.perf_counter()
            for i in range(search_n):
                results = index.search(
                    query_pool[i % len(query_pool)],
                    top_k=min(args.top_k, max(total_rows, 1)),
                    output_fields=["metadata"],
                    search_params=search_params,
                )
                assert results and results[0], "Expected at least one search hit"
                # The query was generated from the same seed as one of the
                # already-inserted vectors, so the top-1 score must be ~1.0.
                top_score = results[0][0]["score"]
                assert abs(top_score - 1.0) < args.score_tol, (
                    f"[reload {reload_idx} query {i}] top-1 score {top_score:.4f} "
                    f"not within {args.score_tol} of 1.0"
                )
            search_s = time.perf_counter() - t_search
            reload_search_calls_this_iter += search_n

            t_unload = time.perf_counter()
            index.unload()
            unload_s = time.perf_counter() - t_unload

            print(
                f"  reload {reload_idx:>3d}: load={load_s:.3f}s "
                f"search {search_n}/{total_rows}={search_s:.3f}s "
                f"unload={unload_s:.3f}s"
            )

            # Same knob semantics as the polling loop above: optional settling
            # time between cycles (GC / system stabilization observation).
            if args.reload_interval > 0:
                time.sleep(args.reload_interval)

        loop_s = time.perf_counter() - loop_start
        print(
            f"  search-loop total:      {loop_s:.3f}s over {round_idx} polling rounds + "
            f"{args.reload_cycles} reload cycles "
            f"({search_calls_this_iter} polling / {reload_search_calls_this_iter} reload searches)"
        )

        totals["insert"] += insert_s
        totals["unload_initial"] += unload_initial_s
        totals["search_loop"] += loop_s
        totals_counts["search_rounds"] += round_idx
        totals_counts["search_calls"] += search_calls_this_iter
        totals_counts["reload_search_calls"] += reload_search_calls_this_iter

    print("\n[summary totals]")
    for k, v in totals.items():
        print(f"  {k:<16s}{v:.3f}s")
    print(f"  {'wall total':<16s}{sum(totals.values()):.3f}s")
    print(f"  {'search rounds':<16s}{totals_counts['search_rounds']}")
    print(f"  {'search calls':<16s}{totals_counts['search_calls']}")
    print(f"  {'reload searches':<16s}{totals_counts['reload_search_calls']}")

    if not args.skip_cleanup:
        ev.drop_index(args.index_name)
        ev.unload_key(args.key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Repeating insert/load/search/unload load test")
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=50050)
    parser.add_argument("--key-path", type=str, default="./keys")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3")
    parser.add_argument("--eval-mode", type=str, choices=["mm", "mms", "mm32", "mms32"], default="mm32")
    parser.add_argument("--preset", type=str, default="ip3")
    parser.add_argument("--index-type", type=str, choices=["flat", "ivf", "vct"], default="flat")
    parser.add_argument("--index-name", type=str, default="stress_indexing")
    parser.add_argument("--iterations", type=int, default=1, help="How many full cycles to run")
    parser.add_argument("--num-vectors", type=int, default=5, help="Vectors inserted per iteration")
    parser.add_argument("--dim", type=int, default=1024)
    parser.add_argument("--nlist", type=int, default=4, help="nlist for ivf/vct")
    parser.add_argument("--nprobe", type=int, default=4, help="nprobe for ivf/vct search")
    parser.add_argument("--top-k", type=int, default=10, help="top_k for search calls")
    parser.add_argument(
        "--score-tol",
        type=float,
        default=1e-3,
        help="Tolerance for top-1 score check (top-1 should be ~1.0 since each query matches an inserted vector)",
    )
    parser.add_argument(
        "--search-limit",
        type=int,
        default=0,
        help="Cap on number of vectors searched per iteration (0 = all vectors currently in index)",
    )
    parser.add_argument(
        "--round-interval",
        type=float,
        default=0.0,
        help="Optional sleep between load/search/unload rounds while waiting for MERGED_SAVED (0 = no sleep)",
    )
    parser.add_argument(
        "--reload-cycles",
        type=int,
        default=20,
        help="Extra load/search/unload cycles after MERGED_SAVED (0 = skip)",
    )
    parser.add_argument(
        "--reload-interval",
        type=float,
        default=0.0,
        help="Optional sleep between post-MERGED_SAVED reload cycles (0 = no sleep)",
    )
    parser.add_argument("--reset", action="store_true", default=False, help="Drop pre-existing index before run")
    parser.add_argument("--skip-cleanup", action="store_true", default=False, help="Do not drop index after run")
    main(parser.parse_args())
