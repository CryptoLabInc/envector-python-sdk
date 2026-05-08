"""
Benchmark: pyenvector.Encryptor.encrypt_row(n_workers=N) via threadpoolctl

Compares:
  A) n_workers=1  (single-threaded baseline)
  B) n_workers=N  without threadpool_limits  (raw Python threads, OMP default)
  C) n_workers=N  with threadpool_limits(1)  (SDK's actual implementation)

Usage:
  python bench_parallel_encrypt.py [--dim 512] [--rows 400] [--threads 1,2,4,8]
"""

import argparse
import math
import os
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import evi
from threadpoolctl import threadpool_limits

KEY_DIR = os.path.join(tempfile.gettempdir(), "sdk_bench_keys")


def setup_keys(dim):
    shutil.rmtree(KEY_DIR, ignore_errors=True)
    os.makedirs(KEY_DIR, exist_ok=True)
    ctx = evi.Context(evi.ParameterPreset.IP1, evi.DeviceType.CPU, dim, evi.EvalMode.MM, None)
    kg = evi.MultiKeyGenerator([ctx], KEY_DIR, evi.SealInfo(evi.SealMode.NONE))
    kg.generate_keys()
    return ctx


def setup_sdk_encryptor(ctx, dim):
    """Bootstrap the SDK Encryptor with the given evi.Context."""
    from pyenvector.crypto.encryptor import Encryptor

    # Inject a pre-built context so SDK skips its own construction path
    class _FakeContext:
        _context = ctx

        class parameter:
            pass

    _FakeContext.parameter.dim = dim
    Encryptor._context = _FakeContext()
    return Encryptor(KEY_DIR + "/EncKey.bin")


def raw_worker(ctx, enc_key, data_chunk, encode_type, level):
    """Worker without threadpool_limits (baseline for comparison)."""
    enc = evi.Encryptor(ctx)
    return enc.encrypt_row(data_chunk, enc_key, encode_type, level)


def run_raw_parallel(ctx, enc_key, data, n_workers, level):
    """N Python threads, no OMP capping."""
    chunk_size = math.ceil(len(data) / n_workers)
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    encode_type = evi.EncodeType.ITEM
    results = []
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        for partial in pool.map(lambda c: raw_worker(ctx, enc_key, c, encode_type, level), chunks):
            results.extend(partial)
    return time.perf_counter() - t0, len(results)


def run_sdk(enc, data, n_workers):
    """SDK path: uses threadpool_limits internally."""
    t0 = time.perf_counter()
    results = enc.encrypt_row(data, "item", n_workers=n_workers)
    return time.perf_counter() - t0, len(results)


def print_table(title, rows, baseline):
    print(f"\n=== {title} ===")
    print(f"{'workers':>8} {'time(s)':>10} {'rows/s':>10} {'speedup':>10}")
    print("-" * 45)
    for n, elapsed, total in rows:
        rps = total / elapsed
        speedup = baseline / elapsed
        print(f"{n:>8} {elapsed:>10.3f} {rps:>10.1f} {speedup:>10.2f}x")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dim", type=int, default=512)
    parser.add_argument("--rows", type=int, default=400)
    parser.add_argument("--threads", type=str, default="1,2,4,8")
    args = parser.parse_args()

    thread_counts = [int(x) for x in args.threads.split(",")]

    print(f"Setup: dim={args.dim}, rows={args.rows}, preset=IP1, eval_mode=MM")
    print("Generating keys...", end=" ", flush=True)
    ctx = setup_keys(args.dim)
    print("done")

    enc_key = evi.KeyPack(ctx)
    enc_key.load_enc_key_file(KEY_DIR + "/EncKey.bin")
    data = [[float(j) * 0.001 for j in range(args.dim)] for _ in range(args.rows)]

    # warmup
    warmup_enc = evi.Encryptor(ctx)
    warmup_enc.encrypt_row(data[:2], enc_key, evi.EncodeType.ITEM)

    print("Setting up SDK Encryptor...", end=" ", flush=True)
    try:
        sdk_enc = setup_sdk_encryptor(ctx, args.dim)
        sdk_available = True
        print("done")
    except Exception as e:
        sdk_available = False
        print(f"skipped ({e})")

    # --- A: raw parallel (no OMP cap) ---
    raw_rows = []
    for n in thread_counts:
        if n == 1:
            t0 = time.perf_counter()
            e = evi.Encryptor(ctx)
            r = e.encrypt_row(data, enc_key, evi.EncodeType.ITEM)
            elapsed = time.perf_counter() - t0
            raw_rows.append((n, elapsed, len(r)))
        else:
            elapsed, total = run_raw_parallel(ctx, enc_key, data, n, level=0)
            raw_rows.append((n, elapsed, total))

    baseline_raw = raw_rows[0][1]
    print_table("A: raw Python threads (no OMP cap)", raw_rows, baseline_raw)

    # --- B: threadpoolctl cap (manually applied) ---
    capped_rows = []
    for n in thread_counts:
        if n == 1:
            capped_rows.append(raw_rows[0])
        else:
            chunk_size = math.ceil(len(data) / n)
            chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
            encode_type = evi.EncodeType.ITEM
            results = []
            t0 = time.perf_counter()
            with threadpool_limits(limits=1, user_api="openmp"):
                with ThreadPoolExecutor(max_workers=n) as pool:
                    for partial in pool.map(lambda c: raw_worker(ctx, enc_key, c, encode_type, 0), chunks):
                        results.extend(partial)
            elapsed = time.perf_counter() - t0
            capped_rows.append((n, elapsed, len(results)))

    baseline_capped = capped_rows[0][1]
    print_table("B: threadpool_limits(1) applied (our SDK impl)", capped_rows, baseline_capped)

    # --- C: via SDK Encryptor.encrypt_row ---
    if sdk_available:
        sdk_rows = []
        for n in thread_counts:
            elapsed, total = run_sdk(sdk_enc, data, n)
            sdk_rows.append((n, elapsed, total))
        baseline_sdk = sdk_rows[0][1]
        print_table("C: pyenvector.Encryptor.encrypt_row(n_workers=N)", sdk_rows, baseline_sdk)

    print()


if __name__ == "__main__":
    main()
