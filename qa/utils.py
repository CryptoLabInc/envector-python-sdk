import asyncio
import concurrent.futures
import timeit
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
from loguru import logger


def concurrent_query_test(
    index, test_data, test_idx=50, concurrent_clients=10, test_top_k=1, failure_ratio=0.0, verbose=True
):
    if verbose:
        logger.info(f"Starting concurrent query test with {concurrent_clients} clients...")

    query_vector = test_data[test_idx]
    ## Determine which clients will fail
    failure_count = int(concurrent_clients * failure_ratio)
    failure_clients = set(np.random.choice(range(concurrent_clients), size=failure_count, replace=False))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_clients) as executor:
        futures = [
            executor.submit(
                # Normal clients perform a direct search
                index.search,
                query_vector,
                test_top_k,
                ["metadata"],
            )
            if user_id not in failure_clients
            else executor.submit(
                # Simulated failure clients: first fail, then reconnect and retry
                _simulate_failure_then_reconnect,
                index,
                query_vector,
                test_top_k,
                user_id,
                verbose,
            )
            for user_id in range(concurrent_clients)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if isinstance(res, list) and len(res) > 0:
                    results.append(res[0])
                else:
                    logger.info("Search returned an empty result list")
            except Exception as e:
                logger.error(f"Unknown Exception while running search: {e}")

    fail_results = []
    reference = results[min([i for i in range(concurrent_clients) if i not in fail_results])]

    for idx, r in enumerate(results[1:], start=1):
        if r != reference:
            fail_results.append(
                {
                    "concurrent_clients": concurrent_clients,
                    "network_error_rate": failure_ratio,
                    "expected_id": reference["id"],
                    "test_id": r["id"],
                    "expected_score": reference["score"],
                    "test_score": r["score"],
                }
            )
    if verbose:
        if len(fail_results) == 0:
            logger.success(f"Concurrent query finished successfully for {concurrent_clients} clients")
        else:
            logger.error(f"Mismatch detected in {len(fail_results)} / {concurrent_clients} clients")
    return fail_results


def _simulate_failure_then_reconnect(index, query_vector, test_top_k, user_id, verbose):
    try:
        ## First attempt
        index.search(query_vector, top_k=test_top_k, output_fields=["metadata"])
        ## Intentionally raise an error to simulate a network failure
        raise RuntimeError(f"[User {user_id}] Simulated failure: network disconnected")
    except Exception as e:
        if verbose:
            logger.error(f"[User {user_id}] Query interrupted: {e}")
        ## Second attempt
        return index.search(query_vector, top_k=test_top_k, output_fields=["metadata"])


# Define a function to generate random vectors
def generate_random_vectors(dim):
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}.")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec = vec / norm

    return vec


def insert_data(index, num_data, dim):
    db_vectors = [generate_random_vectors(dim) for _ in range(num_data)]
    metadatas = [f"data_{i + 1}" for i in range(num_data)]
    index.insert(db_vectors, metadatas)

    return db_vectors


def make_similar_vectors(base_vector, similarity):
    if similarity < 0 or similarity > 1:
        raise ValueError(f"Invalid similarity: {similarity}.")

    dim = len(base_vector)
    # base_vector와 직교하는 단위벡터 생성
    random_vector = np.random.randn(dim)
    projection = np.dot(random_vector, base_vector) * base_vector
    orthogonal_component = random_vector - projection
    orthogonal_norm = np.linalg.norm(orthogonal_component)

    if orthogonal_norm < 1e-10:
        # 우연히 거의 같은 방향이 나왔다면 재시도
        return make_similar_vectors(base_vector, similarity)

    orthogonal_unit = orthogonal_component / orthogonal_norm

    # new_vector = similarity * base + sqrt(1 - similarity^2) * orthogonal
    new_vector = similarity * base_vector + np.sqrt(1 - similarity**2) * orthogonal_unit
    return new_vector


def search_test(index, test_data, test_top_k, verbose=True):
    if verbose:
        logger.info(f"Test : {len(test_data)} data points, dimension {len(test_data[0])}, top_k {test_top_k}")
    abs_error_list = []
    sim_abs_error_list = []
    for _ in range(100):
        test_idx = np.random.randint(0, len(test_data))
        ans_idx = test_idx + 1

        # Test the query with the same vector as the one in the database
        test_query = test_data[test_idx]
        _, err = search(index, test_query, test_data, ans_idx, test_top_k, verbose)
        abs_error_list.append(err)

        # Test the query with a similar vector
        new_simliar_query = make_similar_vectors(test_query, 0.8)
        _, err = search(index, new_simliar_query, test_data, ans_idx, test_top_k, verbose)
        sim_abs_error_list.append(err)

    same_res = {
        "mean": float(np.mean(abs_error_list)),
        "max": float(np.max(abs_error_list)),
        "95%": float(np.percentile(abs_error_list, 95)),
    }

    similar_res = {
        "mean": float(np.mean(sim_abs_error_list)),
        "max": float(np.max(sim_abs_error_list)),
        "95%": float(np.percentile(sim_abs_error_list, 95)),
    }

    if verbose:
        logger.info(
            f"Average absolute error for exact match: {same_res['mean']:.6f}, "
            f"max error: {same_res['max']:.6f}, "
            f"95% confidence interval: {same_res['95%']:.6f}, "
        )
        logger.info(
            f"Average absolute error for similar match: {similar_res['mean']:.6f}, "
            f"max error: {similar_res['max']:.6f}, "
            f"95% confidence interval: {similar_res['95%']:.6f}"
        )

    return same_res, similar_res


def search(index, test_query, test_data, ans_idx, test_top_k=2, verbose=True):
    plain_result = np.dot(test_query, test_data[ans_idx - 1])

    # Search for the top_k results
    start = timeit.default_timer()
    result = index.search(test_query, top_k=test_top_k, output_fields=["metadata"])[0]
    elapsed = timeit.default_timer() - start
    search_res = result[0]["score"]
    abs_error = abs(search_res - plain_result)

    assert len(result) == test_top_k, f"Expected {test_top_k} results, got {len(result)}"
    assert result[0]["metadata"] == f"data_{ans_idx}", f"Expected 'data_{ans_idx}', got {result[0]['metadata']}"
    assert result[0]["id"] == ans_idx, f"Expected ID {ans_idx}, got {result[0]['id']}"
    assert abs_error < 1e-3, f"Expected score to be close to {plain_result}, got {search_res}, difference: {abs_error}"
    if verbose:
        logger.success(
            f"Test Passed Search Query(Time : {elapsed:.4f}s) result: {search_res}, abs diff from plain result: "
            f"{abs_error}"
        )
    return elapsed, abs_error


def multi_query_search_test(index, test_data, test_top_k, verbose=True):
    num_queries = 2

    if verbose:
        logger.info(f"Test : {len(test_data)} data points, dimension {len(test_data[0])}, top_k {test_top_k}")
    abs_error_list = []
    sim_abs_error_list = []
    for _ in range(100):
        test_idx = np.random.randint(0, len(test_data), size=num_queries)
        ans_idx = [t + 1 for t in test_idx]

        # Test the query with the same vector as the one in the database
        test_query = [test_data[t] for t in test_idx]
        print(f"Test Num Queries: {len(test_query)}")
        _, err = multi_query_search(index, test_query, test_data, ans_idx, test_top_k, verbose)
        abs_error_list.append(err)

        # Test the query with a similar vector
        new_simliar_query = [make_similar_vectors(tq, 0.8) for tq in test_query]
        _, err = multi_query_search(index, new_simliar_query, test_data, ans_idx, test_top_k, verbose)
        sim_abs_error_list.append(err)

    same_res = {
        "mean": float(np.mean(abs_error_list)),
        "max": float(np.max(abs_error_list)),
        "95%": float(np.percentile(abs_error_list, 95)),
    }

    similar_res = {
        "mean": float(np.mean(sim_abs_error_list)),
        "max": float(np.max(sim_abs_error_list)),
        "95%": float(np.percentile(sim_abs_error_list, 95)),
    }

    if verbose:
        logger.info(
            f"Average absolute error for exact match: {same_res['mean']:.6f}, "
            f"max error: {same_res['max']:.6f}, "
            f"95% confidence interval: {same_res['95%']:.6f}, "
        )
        logger.info(
            f"Average absolute error for similar match: {similar_res['mean']:.6f}, "
            f"max error: {similar_res['max']:.6f}, "
            f"95% confidence interval: {similar_res['95%']:.6f}"
        )

    return same_res, similar_res


def multi_query_search(index, test_queries, test_data, ans_idx, test_top_k=2, verbose=True):
    plain_result = np.array([np.dot(q, test_data[i - 1]) for q, i in zip(test_queries, ans_idx)])

    start = timeit.default_timer()
    result = index.search(test_queries, top_k=test_top_k, output_fields=["metadata"])
    elapsed = timeit.default_timer() - start
    abs_error_list = []

    # compare search result per query
    for i in range(len(result)):
        search_res = result[i][0]["score"]
        abs_error = abs(search_res - plain_result[i])
        abs_error_list.append(abs_error)
        assert len(result[i]) == test_top_k, f"Expected {test_top_k} results, got {len(result[i])}"
        assert (
            abs_error < 1e-3
        ), f"Expected score to be close to {plain_result[i]}, got {search_res}, difference: {abs_error}"
        assert (
            result[i][0]["metadata"] == f"data_{ans_idx[i]}"
        ), f"Expected 'data_{ans_idx[i]}', got {result[i][0]['metadata']}"
        assert result[i][0]["id"] == ans_idx[i], f"Expected ID {ans_idx[i]}, got {result[i][0]['id']}"
        assert result[i][0]["id"] == ans_idx[i], f"Expected ID {ans_idx[i]}, got {result[i][0]['id']}"
        assert (
            abs_error < 1e-3
        ), f"Expected score to be close to {plain_result[i]}, got {search_res}, difference: {abs_error}"
        if verbose:
            logger.success(
                f"Test Passed Search Query(Time : {elapsed:.4f}s) result: {search_res}, abs diff from plain result: "
                f"{abs_error}"
            )

    return elapsed, abs_error_list


def save_core_result(df, file_path):
    """Persist core test metrics with MultiIndex columns derived from config keys."""

    def _parse_column(column_key):
        if isinstance(column_key, tuple):
            if len(column_key) >= 3:
                return column_key[:3]
            if len(column_key) == 2:
                return column_key[0], column_key[1], "default"
            return column_key[0], "default", "default"

        key_str = str(column_key)
        parts = key_str.split("_")

        dim_candidate = parts[0]
        try:
            dim_value = int(dim_candidate)
        except (TypeError, ValueError):
            dim_value = dim_candidate

        eval_mode = parts[1] if len(parts) >= 2 else "default"
        query_encryption = parts[2] if len(parts) >= 3 else "default"

        if len(parts) > 3:
            remainder = "_".join(parts[3:])
            if query_encryption == "default":
                query_encryption = remainder
            else:
                query_encryption = f"{query_encryption}_{remainder}"

        return dim_value, eval_mode, query_encryption

    parsed_columns = [_parse_column(col) for col in df.columns]

    result_df = df.copy()
    result_df.columns = pd.MultiIndex.from_tuples(parsed_columns, names=["dim", "eval_mode", "query_encryption"])
    result_df = result_df.sort_index(axis=1, level=[0, 1, 2])
    result_df.to_csv(file_path)


def print_time_table(time_res):
    dims = list(time_res.keys())
    test_nums = list(next(iter(time_res.values())).keys())

    header = f"{'dim \\ num_data':>12}"
    for test_num in test_nums:
        header += f"{str(test_num):>36}"
    print(header)
    print("=" * len(header))

    sub_header = f"{'':>12}"
    for _ in test_nums:
        sub_header += f"{'avg':>12}{'p95':>12}{'max':>12}"
    print(sub_header)
    print("-" * len(header))

    for dim in dims:
        row = f"{str(dim):>12}"
        for test_num in test_nums:
            stats = time_res[dim][test_num]
            row += f"{stats['avg']:>12.6f}{stats['p95']:>12.6f}{stats['max']:>12.6f}"
        print(row)


def save_single_result(res, file_path):
    rows = []
    index = []

    for dim, test_data in res.items():
        row = {}
        for num_data, stats in test_data.items():
            for stat_name, value in stats.items():
                row[(num_data, stat_name)] = value
        rows.append(row)
        index.append(dim)

    df = pd.DataFrame(rows, index=index)
    df.index.name = "dim"
    df.columns = pd.MultiIndex.from_tuples(df.columns)
    df = df.sort_index(axis=1, level=0)  # num_data 기준 정렬
    df.to_csv(file_path)


executor = ThreadPoolExecutor()


async def async_search(index, test_query):
    results = await asyncio.get_event_loop().run_in_executor(executor, index.search, test_query, 1, "metadata")
    return results


async def do_async_search(index, test_query, user_count):
    start_time = asyncio.get_event_loop().time()
    tasks = [async_search(index, test_query) for _ in range(user_count)]
    results = await asyncio.gather(*tasks)
    elapsed_time = asyncio.get_event_loop().time() - start_time
    qps = user_count / elapsed_time if elapsed_time > 0 else 0
    return results, qps


def save_scalability_result(res, result_file_path):
    csv_lines = []
    dim_list = sorted(res.keys())
    data_size_list = sorted(res[next(iter(res))].keys())
    num_of_users = sorted(res[next(iter(res))][next(iter(res[next(iter(res))]))].keys())

    for user in num_of_users:
        # 유저 블록 헤더
        csv_lines.append([f"User == {user}"])
        # 서브 헤더
        sub_header = ["dim"] + [str(s) if s < 1000 else f"{s // 1000}K" for s in data_size_list]
        csv_lines.append(sub_header)
        # 각 dim 행
        for dim in dim_list:
            row = [dim]
            for size in data_size_list:
                qps = res[dim][size][user]["qps"]
                row.append(f"{qps:.8f}")
            csv_lines.append(row)
        # 빈 줄로 블록 구분
        csv_lines.append([])
    # DataFrame으로 만들지 않고 직접 CSV로 저장
    with open(result_file_path, "w") as f:
        for line in csv_lines:
            f.write(",".join(map(str, line)) + "\n")
