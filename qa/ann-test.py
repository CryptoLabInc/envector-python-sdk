import argparse
import csv
import os
import time
from typing import Dict, List, Optional

import numpy as np

import pyenvector as ev


# 1. 데이터 생성
def create_data(num_vectors, dim, seed, cache_path=None):
    print("[Step 1] Generating data...")
    if cache_path and os.path.exists(cache_path):
        print(f"Loading vectors from {cache_path}...")
        vectors = np.load(cache_path)
    else:
        np.random.seed(seed)
        vectors = np.random.rand(num_vectors, dim).astype(np.float32)
        vectors = vectors / np.linalg.norm(vectors, axis=1, keepdims=True)
    if cache_path:
        print(f"Saving vectors to {cache_path}...")
        np.save(cache_path, vectors)
    return vectors


# 2. Centroids 생성 (cuml KMeans)
def create_centroids(vectors, n_lists, seed, cache_path=None):
    try:
        from cuml.cluster import KMeans
    except ImportError:
        from sklearn.cluster import KMeans

    print("[Step 2] Preparing centroids...")
    if cache_path and os.path.exists(cache_path):
        print(f"Loading centroids from {cache_path}...")
        centroids = np.load(cache_path)
    else:
        print("Fitting KMeans for centroids...")
        kmeans = KMeans(n_clusters=n_lists, random_state=seed, n_init=1, verbose=1)
        kmeans.fit(vectors)
        centroids = kmeans.cluster_centers_.copy()
        if cache_path:
            print(f"Saving centroids to {cache_path}...")
            np.save(cache_path, centroids)
    return centroids


# 3. ES2 인덱스 생성
def create_index(index_name, dim, centroids, n_lists, n_probes, eval_mode):
    print("[Step 3] Creating index...")
    index_params = {
        "index_type": "IVF_FLAT",
        "nlist": n_lists,
        "default_nprobe": n_probes,
    }
    if centroids is not None:
        index_params["centroids"] = centroids
    print("Creating index...")
    ev.create_index(index_name, dim, eval_mode=eval_mode, index_params=index_params)


# 4. 데이터 삽입 (메모리 100% 로드 가정)
def insert_data(index_name, vectors):
    index = ev.Index(index_name)
    metadata = [f"{i + 1}" for i in range(vectors.shape[0])]
    index.insert(vectors, metadata=metadata)


# 5. 단일 쿼리 테스트용 쿼리 벡터 생성
def create_query_vectors(num_queries, dim, source_vectors=None):
    print("[Step 5] Generating query vectors...")
    if source_vectors is not None:
        # Sample queries directly from the inserted vectors
        idx = np.random.choice(source_vectors.shape[0], num_queries, replace=False)
        query_vectors = source_vectors[idx]
    else:
        query_vectors = np.random.rand(num_queries, dim).astype(np.float32)
        query_vectors = query_vectors / np.linalg.norm(query_vectors, axis=1, keepdims=True)
    return query_vectors


# 6. Latency/QPS 측정
def evaluate_index(
    index_name: str,
    query_vectors: np.ndarray,
    top_k: int,
    search_params: Optional[Dict[str, int]] = None,
) -> Dict[str, object]:
    """Run queries against an index and collect latency/QPS and result IDs."""

    index = ev.Index(index_name)
    latencies: List[float] = []
    results: List[List[str]] = []

    print(f"[Step 6] Running queries on index '{index_name}'...")
    for qv in query_vectors:
        start = time.time()
        search_output = index.search(query=qv, top_k=top_k, search_params=search_params, output_fields=["metadata"])
        latencies.append(time.time() - start)
        print(f"Search output: {search_output}")

        hits = search_output[0] if search_output else []
        result_ids = [hit.get("metadata") for hit in hits if "metadata" in hit]
        results.append(result_ids)

    if not latencies:
        return {"latency_ms": 0.0, "qps": 0.0, "results": results}

    avg_latency = float(np.mean(latencies))
    qps = float(len(query_vectors) / np.sum(latencies)) if np.sum(latencies) > 0 else 0.0

    print(f"Tested {len(query_vectors)} queries")
    print(f"Average latency: {avg_latency * 1000:.2f} ms")
    print(f"QPS: {qps:.2f}")

    return {"latency_ms": avg_latency * 1000, "qps": qps, "results": results}


def compute_recall(
    baseline: Optional[List[List[str]]],
    candidates: List[List[str]],
    top_k: int,
) -> Optional[float]:
    if not baseline:
        return None

    recalls: List[float] = []
    for base_ids, cand_ids in zip(baseline, candidates):
        if not base_ids:
            continue
        base_top = base_ids[:top_k]
        cand_top = cand_ids[:top_k]
        if not base_top:
            continue
        overlap = len(set(base_top) & set(cand_top))
        recalls.append(overlap / len(base_top))

    if not recalls:
        return None
    return float(np.mean(recalls))


# 7. Cleanup
def clean_up():
    print("[Step 7] Cleaning up: Deleting index and releasing resources...")
    ev.reset()
    print("Cleanup completed.")


def parse_args():
    parser = argparse.ArgumentParser(description="ES2 IVF-FLAT ANN Benchmark")
    parser.add_argument("--num_vectors", type=int, default=1_000_000, help="Number of vectors in dataset")
    parser.add_argument("--dim", type=int, default=1536, help="Dimension of each vector")
    parser.add_argument("--n_lists", type=int, default=250, help="Number of IVF clusters (nlist)")
    parser.add_argument("--n_probes", type=int, default=6, help="Number of probes for search")
    parser.add_argument("--num_queries", type=int, default=100, help="Number of queries for QPS/latency test")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--index_name", type=str, default="test_ann", help="Index name")
    parser.add_argument("--top_k", type=int, default=10, help="Top K for search")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="ES2 server host")
    parser.add_argument("--port", type=int, default=50050, help="ES2 server port")
    parser.add_argument("--random_centroid", action="store_true", help="Let server create centroids randomly")
    parser.add_argument("--eval_mode", type=str, default="RMP", help="Evaluation mode for index creation")
    parser.add_argument("--compare_flat", action="store_true", help="Compare IVF_FLAT and FLAT index performance")
    parser.add_argument(
        "--nprobe_values",
        type=str,
        default=None,
        help="Comma-separated list of nprobe values to evaluate for IVF index",
    )
    parser.add_argument(
        "--output_csv",
        type=str,
        default="ann_results.csv",
        help="Path to save the aggregated metrics as CSV",
    )
    parser.add_argument(
        "--output_txt",
        type=str,
        default=None,
        help="Optional path to save a human-readable summary of results",
    )
    parser.add_argument(
        "--target_recalls",
        type=str,
        default="0.99,0.95",
        help="Comma-separated recall targets to highlight best (nlist, nprobe) configs",
    )
    return parser.parse_args()


def save_results_to_csv(records: List[Dict[str, object]], csv_path: str) -> None:
    if not records:
        print("No records to save.")
        return

    fieldnames = [
        "index_type",
        "nlist",
        "nprobe",
        "eval_mode",
        "num_vectors",
        "num_queries",
        "top_k",
        "latency_ms",
        "qps",
        "recall",
    ]

    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key) for key in fieldnames})

    print(f"Results saved to {csv_path}")


def save_results_to_txt(records: List[Dict[str, object]], txt_path: str) -> None:
    if not records:
        return

    lines = ["IndexType,Nlist,Nprobe,EvalMode,NumVectors,NumQueries,TopK,Latency(ms),QPS,Recall"]
    for record in records:
        line = ",".join(
            [
                str(record.get("index_type")),
                str(record.get("nlist")),
                str(record.get("nprobe")),
                str(record.get("eval_mode")),
                str(record.get("num_vectors")),
                str(record.get("num_queries")),
                str(record.get("top_k")),
                f"{record.get('latency_ms', 0.0):.4f}",
                f"{record.get('qps', 0.0):.4f}",
                "" if record.get("recall") is None else f"{record['recall']:.4f}",
            ]
        )
        lines.append(line)

    with open(txt_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Summary saved to {txt_path}")


def summarize_target_recalls(records: List[Dict[str, object]], targets: List[float]) -> None:
    print("Summary of best (nlist, nprobe) for target recalls:")
    print("==============================================")
    print("Records: ,", records)
    ivf_records = [r for r in records if r.get("index_type") == "IVF_FLAT" and r.get("recall") is not None]
    if not ivf_records:
        return

    for target in targets:
        candidates = [r for r in ivf_records if r["recall"] >= target]
        if not candidates:
            print(f"No IVF setting reached recall >= {target:.3f}")
            continue
        best = min(candidates, key=lambda r: (r["latency_ms"], -r["qps"]))
        print(
            f"Recall >= {target:.3f}: nlist={best['nlist']} nprobe={best['nprobe']} "
            f"latency={best['latency_ms']:.2f} ms qps={best['qps']:.2f}"
        )


def main(args):
    start_total = time.time()
    cache_vectors = None
    cache_centroids = None
    if args.num_vectors == 1000000 and args.dim == 1536:
        if args.n_lists == 250:
            cache_centroids = "centroids_cache.npy"
        cache_vectors = "vectors_cache.npy"
    try:
        start = time.time()
        vectors = create_data(args.num_vectors, args.dim, args.seed, cache_path=cache_vectors)
        print(f"[Step 1] Done: {time.time() - start:.2f} sec")

        if args.random_centroid:
            print("[Step 2] Skipping centroid creation (server will generate centroids randomly)")
            centroids = None
        else:
            print("[Step 2] Creating centroids...")
            start = time.time()
            centroids = create_centroids(vectors, args.n_lists, args.seed, cache_path=cache_centroids)
            print(f"[Step 2] Done: {time.time() - start:.2f} sec")

        records: List[Dict[str, object]] = []
        baseline_results: Optional[List[List[str]]] = None
        query_vectors: Optional[np.ndarray] = None

        print("[Setup] Initializing ES2 connection...")
        ev.init(address=f"{args.host}:{args.port}", key_path="./keys", key_id="ann-test")

        if args.compare_flat:
            flat_index_name = f"{args.index_name}_flat"
            print(f"[Step 3] Creating FLAT index '{flat_index_name}'...")
            ev.create_index(
                flat_index_name,
                args.dim,
                eval_mode=args.eval_mode,
                index_params={"index_type": "FLAT"},
            )
            print(f"[Step 4] Inserting vectors into '{flat_index_name}'...")
            insert_data(flat_index_name, vectors)
            if query_vectors is None:
                query_vectors = create_query_vectors(args.num_queries, args.dim, source_vectors=vectors)
            print(f"[Step 6] Evaluating index '{flat_index_name}'...")
            flat_metrics = evaluate_index(flat_index_name, query_vectors, args.top_k, search_params=None)
            records.append(
                {
                    "index_type": "FLAT",
                    "nlist": None,
                    "nprobe": None,
                    "eval_mode": args.eval_mode,
                    "num_vectors": len(vectors),
                    "num_queries": len(query_vectors),
                    "top_k": args.top_k,
                    "latency_ms": flat_metrics["latency_ms"],
                    "qps": flat_metrics["qps"],
                    "recall": 1.0,
                }
            )
            baseline_results = flat_metrics["results"]
            ev.drop_index(flat_index_name)

        ivf_index_name = f"{args.index_name}_ivf"
        print(f"[Step 3] Creating IVF index '{ivf_index_name}'...")
        create_index(
            ivf_index_name,
            args.dim,
            centroids,
            args.n_lists,
            args.n_probes,
            args.eval_mode,
        )
        print(f"[Step 4] Inserting vectors into '{ivf_index_name}'...")
        insert_data(ivf_index_name, vectors)
        if query_vectors is None:
            query_vectors = create_query_vectors(args.num_queries, args.dim, source_vectors=vectors)

        if args.nprobe_values:
            nprobe_values = [int(v.strip()) for v in args.nprobe_values.split(",") if v.strip()]
        else:
            nprobe_values = [args.n_probes]

        for nprobe in nprobe_values:
            print(f"[Step 6] Evaluating index '{ivf_index_name}' with nprobe={nprobe}...")
            metrics = evaluate_index(ivf_index_name, query_vectors, args.top_k, search_params={"nprobe": nprobe})
            recall = compute_recall(baseline_results, metrics["results"], args.top_k)
            records.append(
                {
                    "index_type": "IVF_FLAT",
                    "nlist": args.n_lists,
                    "nprobe": nprobe,
                    "eval_mode": args.eval_mode,
                    "num_vectors": len(vectors),
                    "num_queries": len(query_vectors),
                    "top_k": args.top_k,
                    "latency_ms": metrics["latency_ms"],
                    "qps": metrics["qps"],
                    "recall": recall,
                }
            )

        save_results_to_csv(records, args.output_csv)
        if args.output_txt:
            save_results_to_txt(records, args.output_txt)

        target_recalls = []
        if args.target_recalls:
            try:
                target_recalls = [float(v.strip()) for v in args.target_recalls.split(",") if v.strip()]
            except ValueError:
                print("Failed to parse target_recalls; skipping summary.")

        if target_recalls:
            summarize_target_recalls(records, target_recalls)

        print(f"[Total] All steps: {time.time() - start_total:.2f} sec")
    finally:
        clean_up()


if __name__ == "__main__":
    args = parse_args()
    main(args)
