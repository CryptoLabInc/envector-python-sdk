import argparse
import asyncio

import numpy as np
import pandas as pd
import utils

import pyenvector as ev


def data_consistency_test(result_file_path, test_type="nightly"):
    print(f"[START] Data Consistency Test | test_type={test_type} | result_file_path={result_file_path}")
    np.random.seed(0)
    test_num_data = 100

    index_name = "data_consist_test_index1"
    if test_type == "pr":
        test_count = 5
        dim_list = [512]
    elif test_type == "main":
        test_count = 10
        dim_list = [768, 1536]
    else:
        test_count = 20
        dim_list = [128, 256, 512, 768, 1024, 1536, 4096]

    test_result_concurrent = []
    test_result_recovery = []
    for dim in dim_list:
        print(f"  [PARAM] dim={dim}")
        index = ev.create_index(f"{index_name}_{dim}", dim)
        db_vectors = utils.insert_data(index, test_num_data, dim)
        ## Concurrent Consistency Test
        for _ in range(test_count):
            test_idx = np.random.randint(0, test_num_data)
            fail_result = utils.concurrent_query_test(index, db_vectors, concurrent_clients=10, test_idx=test_idx)
            test_result_concurrent.extend(fail_result)

        ## Recovery After Failure Test
        test_idx = np.random.randint(0, test_num_data)
        fail_result = utils.concurrent_query_test(
            index, db_vectors, concurrent_clients=10, test_idx=test_idx, failure_ratio=0.3
        )
        test_result_recovery.extend(fail_result)
        index.drop()
        del index, db_vectors

    all_result = {
        "Concurrent Consistency Test": test_result_concurrent,
        "Recovery After Failure Test": test_result_recovery,
    }
    if all_result:
        df = pd.DataFrame(all_result)
        df.to_csv(result_file_path, index=False)
        print(df)
    print(f"[END] Data Consistency Test | test_type={test_type} | result_file_path={result_file_path}")


def core_functionality_test(
    test_top_k,
    result_file_path,
    verbose,
    test_type="nightly",
    test_configs=None,
):
    print(
        f"[START] Core Functionality Test | test_type={test_type} | top_k={test_top_k} | "
        f"result_file_path={result_file_path}"
    )
    index_name = "core_func_test_index"
    test_num_data = 100
    if test_type == "pr":
        dim_list = [512]
    elif test_type == "main":
        dim_list = [768, 1536]
    else:
        dim_list = [128, 256, 512, 768, 1024, 1536, 4096]

    if test_configs is None:
        test_configs = [
            # {"eval_mode": "MM", "query_encryption": True},
            {"eval_mode": "MM", "query_encryption": False},
            # {"eval_mode": "MM", "query_encryption": False},
        ]

    res = {}
    for i, config in enumerate(test_configs):
        eval_mode = config["eval_mode"]
        query_encryption = config["query_encryption"]
        print(f"[CONFIG] eval_mode={eval_mode}, query_encryption={query_encryption}")
        for dim in dim_list:
            print(f"  [PARAM] dim={dim}")
            index = ev.create_index(
                f"{index_name}_{dim}_{i}",
                dim=dim,
                query_encryption="cipher" if query_encryption else "plain",
                eval_mode=eval_mode,
            )
            test_data = utils.insert_data(index, test_num_data, dim)
            same_abs, similar_abs = utils.search_test(
                index=index, test_data=test_data, test_top_k=test_top_k, verbose=verbose
            )
            print(
                f"Core Functionality Test Results: "
                f"Dimension: {dim}, Exact Same Query: {same_abs}, Similar Query: {similar_abs}"
            )
            res[f"{dim}_{eval_mode}_{query_encryption}"] = {
                "Exact Same Query": same_abs,
                "Similar Query": similar_abs,
            }
            del index, test_data
    if verbose:
        print(pd.DataFrame(res))
    utils.save_core_result(pd.DataFrame(res), result_file_path)
    print(pd.DataFrame(res))
    print(
        f"[END] Core Functionality Test | test_type={test_type} | top_k={test_top_k} | "
        f"result_file_path={result_file_path}"
    )


def single_query_latency_test(test_top_k, result_file_path, verbose=True, test_type="nightly"):
    print(
        f"[START] Single Query Latency Test | test_type={test_type} | top_k={test_top_k} | "
        f"result_file_path={result_file_path}"
    )
    index_name = "s_test_index"
    if test_type == "pr":
        test_num_datas = [100]
        dim_list = [512]
    elif test_type == "main":
        test_num_datas = [100]
        dim_list = [768, 1536]
    else:
        test_num_datas = [64000]
        dim_list = [128, 256, 512, 768, 1024, 1536, 4096]
    time_res = {}
    for dim in dim_list:
        for test_num_data in test_num_datas:
            print(f"  [PARAM] dim={dim}, num_data={test_num_data}")
            time = []
            index = ev.create_index(f"{index_name}_{test_num_data}_{dim}", dim=dim)
            test_data = utils.insert_data(index, test_num_data, dim)
            test_idx = np.random.randint(0, test_num_data)
            for _ in range(100):
                elapsed_time, _ = utils.search(
                    index=index,
                    test_query=test_data[test_idx],
                    test_data=test_data,
                    ans_idx=test_idx + 1,
                    test_top_k=test_top_k,
                )
                time.append(elapsed_time)
            avg_time = sum(time) / len(time)
            p95 = np.percentile(time, 95)
            max_time = max(time)
            if dim not in time_res:
                time_res[dim] = {}
            time_res[dim][test_num_data] = {"avg": avg_time, "p95": p95, "max": max_time}
            index.drop()
            del index, test_data, test_idx
    if verbose:
        utils.print_time_table(time_res)
    utils.save_single_result(time_res, result_file_path)
    print(pd.DataFrame(time_res))
    print(
        f"[END] Single Query Latency Test | test_type={test_type} | top_k={test_top_k} | "
        f"result_file_path={result_file_path}"
    )


def scalability_validation(result_file_path, verbose=True, test_type="nightly"):
    print(f"[START] Scalability Validation | test_type={test_type} | result_file_path={result_file_path}")
    index_name = "s_test_index"
    if test_type == "pr":
        num_of_users = [2]
        data_size_list = [100]
        dim_list = [512]
    elif test_type == "main":
        num_of_users = [10]
        data_size_list = [100]
        dim_list = [768, 1536]
    else:
        num_of_users = [np.random.choice([1, 10, 50, 100, 500, 1000])]
        data_size_list = [5000]
        dim_list = [128, 256, 512, 768, 1024, 1536, 4096]
    res = {}
    for dim in dim_list:
        for num_data in data_size_list:
            for user_count in num_of_users:
                print(f"  [PARAM] dim={dim}, num_data={num_data}, user_count={user_count}")
                index = ev.create_index(f"{index_name}_{num_data}_{dim}", dim=dim)
                db_vectors = utils.insert_data(index, num_data, dim)
                test_idx = np.random.randint(0, num_data)
                res_search, qps = asyncio.run(
                    utils.do_async_search(
                        index=index,
                        test_query=db_vectors[test_idx],
                        user_count=user_count,
                    )
                )
                if verbose:
                    print(f"User count: {user_count}, QPS: {qps}")
                if dim not in res:
                    res[dim] = {}
                if num_data not in res[dim]:
                    res[dim][num_data] = {}
                res[dim][num_data][user_count] = {"qps": qps}
                index.drop()
                del index, db_vectors, test_idx
    utils.save_scalability_result(res, result_file_path)
    print(pd.DataFrame(res))
    print(f"[END] Scalability Validation | test_type={test_type} | result_file_path={result_file_path}")


def multi_query_test(test_top_k, result_file_path, verbose, test_type="nightly", test_configs=None):
    print(
        f"[START] Multi Query Test | test_type={test_type} | top_k={test_top_k} | result_file_path={result_file_path}"
    )
    index_name = "multi_query_test_index"
    test_num_data = 100
    if test_configs is None:
        test_configs = [
            # {"eval_mode": "MM", "query_encryption": True},
            {"eval_mode": "MM", "query_encryption": False},
        ]
    if test_type == "pr":
        dim_list = [512]
    elif test_type == "main":
        dim_list = [768, 1536]
    else:
        dim_list = [128, 256, 512, 768, 1024, 1536, 4096]
    res = {}
    for i, config in enumerate(test_configs):
        eval_mode = config.get("eval_mode", "default")
        query_encryption = config.get("query_encryption", False)
        print(f"[CONFIG] eval_mode={eval_mode}, query_encryption={query_encryption}")
        for dim in dim_list:
            print(f"  [PARAM] dim={dim}")
            index = ev.create_index(
                f"{index_name}_{dim}_{i}",
                dim=dim,
                query_encryption="cipher" if query_encryption else "plain",
                eval_mode=eval_mode,
            )
            test_data = utils.insert_data(index, test_num_data, dim)
            same_abs, similar_abs = utils.multi_query_search_test(
                index=index, test_data=test_data, test_top_k=test_top_k, verbose=verbose
            )
            print(
                f"Multi Query Test Results: "
                f"Dimension: {dim}, Exact Same Query: {same_abs}, Similar Query: {similar_abs}"
            )
            res[(dim, eval_mode, str(query_encryption))] = {
                "Exact Same Query": same_abs,
                "Similar Query": similar_abs,
            }
            del index, test_data
    if verbose:
        print(pd.DataFrame(res))
    utils.save_core_result(pd.DataFrame(res), result_file_path)
    print(f"[END] Multi Query Test | test_type={test_type} | top_k={test_top_k} | result_file_path={result_file_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Core Functionality Test for ES2")
    parser.add_argument(
        "--test_name",
        type=str,
        default="core",
        help="Name of the QA test [core, latency, scalability, consistency, longrun, multiquery]",
    )
    parser.add_argument("--num_data", type=int, default=100, help="Number of data points to insert")
    parser.add_argument("--test_idx", type=int, default=50, help="Index of the test query")
    parser.add_argument("--dim", type=int, default=512, help="Dimension of the vectors")
    parser.add_argument("--top_k", type=int, default=2, help="Number of top results to return")
    parser.add_argument("--port", type=int, default=50050, help="Port for ES2 connection")
    parser.add_argument("--result_file_path", type=str, default="", help="File to save the results")
    parser.add_argument("--test_type", type=str, default="nightly", help="Type of test to run (nightly, main, pr.)")
    args = parser.parse_args()

    ev.init(
        host="0.0.0.0",
        port=str(args.port),
        key_path="./keys",
        key_id="beaf-beaf-beaf-beaf",
    )

    try:
        if args.result_file_path == "":
            result_file_path = f"result_{args.test_name}.csv"
        else:
            result_file_path = args.result_file_path

        if args.test_name == "core":
            core_functionality_test(
                test_top_k=args.top_k,
                result_file_path=result_file_path,
                verbose=True,
                test_type=args.test_type,
            )
        elif args.test_name == "latency":
            single_query_latency_test(
                test_top_k=args.top_k,
                result_file_path=result_file_path,
                verbose=True,
                test_type=args.test_type,
            )
        elif args.test_name == "scalability":
            scalability_validation(result_file_path=result_file_path, test_type=args.test_type)
        elif args.test_name == "consistency":
            data_consistency_test(result_file_path=result_file_path, test_type=args.test_type)
        elif args.test_name == "multiquery":
            multi_query_test(
                test_top_k=args.top_k, result_file_path=result_file_path, verbose=True, test_type=args.test_type
            )
        else:
            print(f"Unknown test name: {args.test_name}. Please use 'core' for core functionality test.")
    finally:
        ev.reset()
