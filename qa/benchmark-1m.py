"""
enVector FLAT Index Benchmark

Measures insert throughput and search performance (QPS, latency percentiles)
for a configurable number of random vectors on a FLAT index.

Usage:
    python benchmark-1m.py --host 192.168.60.105 --port 50049 \
        --num_vectors 1000000 --dim 768 --batch_size 50000 \
        --num_search_users 50 --search_duration 120

"""

import argparse
import asyncio
import csv
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import numpy as np

import pyenvector as ev

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _humanize_count(n):
    """Convert large numbers to short suffixes: 1000000 -> 1M, 50000 -> 50K."""
    for threshold, suffix in [(1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")]:
        if n >= threshold and n % threshold == 0:
            return f"{n // threshold}{suffix}"
    return str(n)


# ---------------------------------------------------------------------------
# Data generation (pattern from ann-test.py)
# ---------------------------------------------------------------------------


def generate_vectors(num_vectors, dim, seed=42):
    """Generate L2-normalized random vectors as a float32 numpy array."""
    np.random.seed(seed)
    vectors = np.random.rand(num_vectors, dim).astype(np.float32)
    norm = np.linalg.norm(vectors, axis=1, keepdims=True)
    vectors /= np.maximum(norm, 1e-10)
    return vectors


# ---------------------------------------------------------------------------
# Batch insert
# ---------------------------------------------------------------------------


def batch_insert(index, vectors, batch_size):
    """Insert *vectors* into *index* in batches. Returns total wall-clock seconds."""
    total = vectors.shape[0]
    total_time = 0.0

    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        batch = vectors[start:end]
        metadata = [f"{i + 1}" for i in range(start, end)]

        t0 = time.time()
        index.insert(batch, metadata=metadata)
        elapsed = time.time() - t0
        total_time += elapsed

        print(f"  Inserted {end}/{total} ({elapsed:.1f}s)")

    return total_time


# ---------------------------------------------------------------------------
# Async search workers (pattern from load-test.py)
# ---------------------------------------------------------------------------

_executor: ThreadPoolExecutor | None = None


async def _search_worker(index, query_pool, top_k, results_queue, end_time):
    """Single async search worker that runs queries until *end_time*."""
    loop = asyncio.get_event_loop()
    while time.time() < end_time:
        query = random.choice(query_pool)
        t0 = time.perf_counter()
        try:
            await loop.run_in_executor(_executor, index.search, query, top_k, "metadata")
            latency = time.perf_counter() - t0
            await results_queue.put(("success", latency))
        except Exception as e:
            print(f"  Search error: {e}")
            await results_queue.put(("failure", 0.0))


async def run_search_benchmark(index, vectors, num_users, duration_sec, top_k):
    """Run concurrent search benchmark and return a metrics dict."""
    global _executor
    _executor = ThreadPoolExecutor(max_workers=num_users)

    num_queries = min(vectors.shape[0], 1000)
    indices = np.random.choice(vectors.shape[0], num_queries, replace=False)
    query_pool = [vectors[i] for i in indices]

    results_queue = asyncio.Queue()
    end_time = time.time() + duration_sec

    workers = [
        asyncio.create_task(_search_worker(index, query_pool, top_k, results_queue, end_time)) for _ in range(num_users)
    ]

    # Print intermediate QPS every 30 seconds
    monitor = asyncio.create_task(_monitor(results_queue, end_time))
    await asyncio.gather(*workers)
    monitor.cancel()
    _executor.shutdown(wait=False)

    latencies = []
    failures = 0
    while not results_queue.empty():
        status, lat = await results_queue.get()
        if status == "success":
            latencies.append(lat)
        else:
            failures += 1

    if not latencies:
        return {
            "total_queries": 0,
            "failures": failures,
            "qps": 0.0,
            "avg_latency_ms": 0.0,
            "p50_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "p99_latency_ms": 0.0,
        }

    return {
        "total_queries": len(latencies),
        "failures": failures,
        "qps": len(latencies) / duration_sec,
        "avg_latency_ms": statistics.mean(latencies) * 1000,
        "p50_latency_ms": float(np.percentile(latencies, 50)) * 1000,
        "p95_latency_ms": float(np.percentile(latencies, 95)) * 1000,
        "p99_latency_ms": float(np.percentile(latencies, 99)) * 1000,
    }


async def _monitor(results_queue, end_time):
    """Print intermediate QPS reports."""
    last_count = 0
    interval = 30
    try:
        while time.time() < end_time:
            await asyncio.sleep(interval)
            current = results_queue.qsize()
            delta = current - last_count
            if delta > 0:
                print(f"  [Intermediate] QPS: {delta / interval:.1f}")
            last_count = current
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="enVector FLAT Index Benchmark")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="enVector endpoint host")
    parser.add_argument("--port", type=int, default=50050, help="enVector endpoint port")
    parser.add_argument("--num_vectors", type=int, default=1_000_000, help="Number of vectors to insert")
    parser.add_argument("--dim", type=int, default=768, help="Vector dimension")
    parser.add_argument("--batch_size", type=int, default=50_000, help="Insert batch size")
    parser.add_argument("--num_search_users", type=int, default=50, help="Concurrent search workers")
    parser.add_argument("--search_duration", type=int, default=120, help="Search benchmark duration (seconds)")
    parser.add_argument("--top_k", type=int, default=10, help="Top-K for search")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--result_file", type=str, default="benchmark_results.csv", help="Output CSV path")
    args = parser.parse_args()

    index_name = f"bench_flat_{args.dim}d_{_humanize_count(args.num_vectors)}"

    print(f"Connecting to {args.host}:{args.port}")
    ev.init(
        address=f"{args.host}:{args.port}",
        key_path="./keys",
        key_id="benchmark",
    )

    try:
        # Step 1: Generate vectors
        print(f"[1/4] Generating {args.num_vectors:,} vectors (dim={args.dim})...")
        t0 = time.time()
        vectors = generate_vectors(args.num_vectors, args.dim, args.seed)
        gen_time = time.time() - t0
        mem_gb = vectors.nbytes / (1024**3)
        print(f"  Done in {gen_time:.1f}s ({mem_gb:.2f} GB)")

        # Step 2: Create FLAT index
        print(f"[2/4] Creating FLAT index '{index_name}'...")
        ev.create_index(index_name, args.dim)
        print("  Done")

        # Step 3: Batch insert
        print(f"[3/4] Inserting {args.num_vectors:,} vectors (batch_size={args.batch_size:,})...")
        index = ev.Index(index_name)
        insert_time = batch_insert(index, vectors, args.batch_size)
        insert_throughput = args.num_vectors / insert_time
        print(f"  Total insert: {insert_time:.1f}s ({insert_throughput:,.0f} vec/s)")

        # Step 4: Search benchmark
        print(f"[4/4] Search benchmark ({args.num_search_users} users, {args.search_duration}s, top_k={args.top_k})...")
        search_metrics = asyncio.run(
            run_search_benchmark(index, vectors, args.num_search_users, args.search_duration, args.top_k)
        )

        # Report
        print("\n" + "=" * 50)
        print("BENCHMARK RESULTS")
        print("=" * 50)
        print(f"Vectors:    {args.num_vectors:,}")
        print(f"Dimension:  {args.dim}")
        print("Index:      FLAT")
        print(f"Insert:     {insert_time:.1f}s ({insert_throughput:,.0f} vec/s)")
        for key, val in search_metrics.items():
            print(f"  {key}: {val:,.2f}")
        print("=" * 50)

        # Save CSV
        fieldnames = [
            "num_vectors",
            "dim",
            "index_type",
            "batch_size",
            "insert_time_sec",
            "insert_throughput_vec_s",
        ] + list(search_metrics.keys())

        row = {
            "num_vectors": args.num_vectors,
            "dim": args.dim,
            "index_type": "FLAT",
            "batch_size": args.batch_size,
            "insert_time_sec": f"{insert_time:.1f}",
            "insert_throughput_vec_s": f"{insert_throughput:.0f}",
        }
        row.update({k: f"{v:.2f}" for k, v in search_metrics.items()})

        with open(args.result_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(row)
        print(f"Results saved to {args.result_file}")

    finally:
        print("Cleaning up...")
        ev.reset()
        print("Done")


if __name__ == "__main__":
    main()
