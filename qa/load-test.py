import argparse
import asyncio
import random
import statistics
import sys
import time

import numpy as np
import pandas as pd
import utils

# Assuming pyenvector and utils modules exist.
# ev.py and utils.py should be in the same directory as this script.
import pyenvector as ev


async def search_worker(worker_id, index, query_pool, top_k, results_queue, end_time):
    """
    Asynchronous function that simulates the behavior of an individual virtual user.
    """
    while time.time() < end_time:
        try:
            query_vector = random.choice(query_pool)
            start_req_time = time.perf_counter()

            await utils.async_search(index, query_vector["vector"])

            latency = time.perf_counter() - start_req_time
            await results_queue.put(("success", latency))
        except Exception as e:
            print(f"[Worker {worker_id}] Error occurred: {e}")
            await results_queue.put(("failure", 0.0))
            sys.exit(1)


async def monitor_task(start_time, results_queue, test_duration, interval_seconds=60):
    """
    Asynchronous function that prints intermediate performance reports at specified intervals.
    """
    last_checked_count = 0
    while True:
        await asyncio.sleep(interval_seconds)
        elapsed_time = time.time() - start_time
        if elapsed_time >= test_duration:
            break
        current_total_count = results_queue.qsize()
        processed_in_interval = current_total_count - last_checked_count
        if processed_in_interval > 0:
            qps_interval = processed_in_interval / interval_seconds
            print(f"--- [Intermediate Report | {int(elapsed_time)}s] QPS: {qps_interval:.2f} ---")
        else:
            print(f"--- [Intermediate Report | {int(elapsed_time)}s] No requests processed ---")
        last_checked_count = current_total_count


async def run_search_phase(
    index, db_vectors, num_concurrent_users, test_duration_seconds, top_k, result_file_path, current_total_data
):
    """
    Function to run a search load test for one cycle and report the results.
    """
    print(f"\n[SEARCH PHASE] Starting search test for {current_total_data} total items...")
    print(f"  - Concurrent Users: {num_concurrent_users}")
    print(f"  - Test Duration: {test_duration_seconds} seconds")

    num_query_pool = min(len(db_vectors), 1000)
    query_indices = np.random.choice(len(db_vectors), num_query_pool, replace=False)
    query_pool = [{"id": i + 1, "vector": db_vectors[i]} for i in query_indices]
    print(f"-> Created a test query pool with {num_query_pool} queries.")

    results_queue = asyncio.Queue()
    end_time = time.time() + test_duration_seconds

    worker_tasks = [
        asyncio.create_task(search_worker(i + 1, index, query_pool, top_k, results_queue, end_time))
        for i in range(num_concurrent_users)
    ]

    monitoring = asyncio.create_task(monitor_task(time.time(), results_queue, test_duration_seconds))
    await asyncio.gather(*worker_tasks)
    monitoring.cancel()
    print("-> Search test execution complete.")

    all_results = [await results_queue.get() for _ in range(results_queue.qsize())]
    if not all_results:
        print("No requests were made.")
        return

    df = pd.DataFrame(all_results, columns=["status", "latency_sec"])
    success_results = df[df["status"] == "success"]
    success_count = len(success_results)
    total_requests = len(df)
    failure_count = total_requests - success_count

    print("\n--- Search Phase Results Report ---")
    if success_count > 0:
        latencies = success_results["latency_sec"].tolist()
        qps = success_count / test_duration_seconds
        avg_latency_ms = statistics.mean(latencies) * 1000
        p95_ms = np.percentile(latencies, 95) * 1000

        print(f"Total Data: {current_total_data}")
        print(f"Total Requests: {total_requests} (Success: {success_count}, Failure: {failure_count})")
        print(f"Success Rate: {success_count / total_requests:.2%}")
        print(f"QPS: {qps:.2f}")
        print(f"Average Latency: {avg_latency_ms:.2f} ms")
        print(f"p95 Latency: {p95_ms:.2f} ms")

        if result_file_path:
            summary_df = pd.DataFrame(
                [
                    {
                        "total_data": current_total_data,
                        "concurrent_users": num_concurrent_users,
                        "test_duration_sec": test_duration_seconds,
                        "qps": qps,
                        "avg_latency_ms": avg_latency_ms,
                        "p95_latency_ms": p95_ms,
                        "success_rate": success_count / total_requests if total_requests > 0 else 0,
                    }
                ]
            )
            summary_df.to_csv(result_file_path, index=False)
            print(f"Summary results have been saved to '{result_file_path}'.")
    else:
        print("All requests failed.")
    print("-" * 28)


async def incremental_load_test(
    dim: int,
    test_plan: list,
    default_duration: int,
    top_k: int,
    result_file_path: str,
    test_type: str,
):
    """
    Main function that repeats the 'data insertion -> search test' cycle as defined in the 'Test Plan'.
    """
    print("=" * 50)
    print(f"Starting '{test_type}' scenario")
    print(f"  - Total Stages: {len(test_plan)}")
    print(f"  - Default Duration: {default_duration}s")
    print("=" * 50)

    index_name = f"{test_type}_index_{dim}"
    index = None
    all_db_vectors = []
    total_data_count = 0

    try:
        index = ev.create_index(index_name, dim=dim)

        for i, stage in enumerate(test_plan):
            cycle_num = i + 1
            insert_batch_size = stage["insert"]
            num_concurrent_users = stage["users"]
            # If duration is specified in the scenario, use it; otherwise, use default_duration
            duration = stage.get("duration", default_duration)

            print(f"\n{'=' * 20} Starting STAGE {cycle_num}/{len(test_plan)} {'=' * 20}")

            if insert_batch_size > 0:
                print(f"\n[INSERT PHASE] Inserting {insert_batch_size} new data points...")
                new_vectors = utils.insert_data(index, insert_batch_size, dim)
                all_db_vectors.extend(new_vectors)
                total_data_count = len(all_db_vectors)
                await asyncio.sleep(5)
                print(f"-> Insertion complete. Current total data: {total_data_count}")
            else:
                print("\n[INSERT PHASE] No new data to insert. Proceeding with existing data.")

            cycle_result_path = result_file_path.replace(".csv", f"_{test_type}_stage{cycle_num}.csv")
            await run_search_phase(
                index=index,
                db_vectors=all_db_vectors,
                num_concurrent_users=num_concurrent_users,
                test_duration_seconds=duration,
                top_k=top_k,
                result_file_path=cycle_result_path,
                current_total_data=total_data_count,
            )

    finally:
        if index:
            print("\nDeleting test index...")
            try:
                index.drop()
            except ValueError as e:
                print(f"Failed to delete index: {e}")
            print("-> Index deletion complete.")
        ev.reset()
        print("=" * 50)
        print(f"Finished '{test_type}' scenario")
        print("=" * 50)


if __name__ == "__main__":
    # --------------------------------------------------------------------
    # ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼ DEFINE SCENARIOS ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
    # --------------------------------------------------------------------
    scenarios = {
        "baseline": [
            {"insert": 10000, "users": 10, "duration": 30},
            {"insert": 10000, "users": 20, "duration": 60},
        ],
        "stress": [
            {"insert": 50000, "users": 50, "duration": 60},
            {"insert": 50000, "users": 100, "duration": 120},
            {"insert": 0, "users": 150},  # duration is not set, so the default value will be used
            {"insert": 0, "users": 200, "duration": 180},
        ],
        "data_scaling": [
            {"insert": 10000, "users": 50, "duration": 60},
            {"insert": 40000, "users": 50, "duration": 60},
            {"insert": 50000, "users": 50, "duration": 60},
            {"insert": 100000, "users": 50, "duration": 60},
        ],
        "long_run": [
            {"insert": 200000, "users": 100, "duration": 3600 * 2},  # 2 hour
        ],
    }
    # --------------------------------------------------------------------
    # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ DEFINE SCENARIOS ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
    # --------------------------------------------------------------------

    parser = argparse.ArgumentParser(description="Scenario-based Incremental Load Test for ES2")

    parser.add_argument(
        "--test_type",
        type=str,
        default="baseline",
        choices=scenarios.keys(),
        help=f"Type of test scenario to run. Available: {list(scenarios.keys())}",
    )
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument(
        "--duration", type=int, default=60, help="Default duration for a test stage if not specified in the scenario"
    )
    parser.add_argument("--top_k", type=int, default=10, help="Number of top results to return")
    parser.add_argument("--port", type=int, default=50050, help="Port for ES2 connection")
    parser.add_argument("--result_file_path", type=str, default="test_result.csv", help="Base path to save results")

    args = parser.parse_args()

    selected_plan = scenarios[args.test_type]

    ev.init(host="0.0.0.0", port=str(args.port), key_path="./keys", key_id="beaf-beaf-beaf-beaf")

    asyncio.run(
        incremental_load_test(
            dim=args.dim,
            test_plan=selected_plan,
            default_duration=args.duration,
            top_k=args.top_k,
            result_file_path=args.result_file_path,
            test_type=args.test_type,
        )
    )
