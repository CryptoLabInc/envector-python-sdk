import argparse

import numpy as np

import pyenvector as ev

DIM = 512  # Dimension for the context


def get_random_vector(dim, seed=None):
    if seed is not None:
        np.random.seed(seed)

    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec = vec / norm  # L2 norm
    return vec


def main(args):
    # Key Path
    key_path = "./keys"
    key_id = args.key_id

    # Connect to endpoint of enVector
    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    ev.init(address=ENVECTOR_ADDRESS, key_path=key_path, key_id=key_id, eval_mode=args.eval_mode, preset=args.preset)
    if ev.is_connected():
        print("Connected to Indexer.")
    else:
        print("Failed to connect to Indexer.")
        return

    index_name = "basic_ins_enc_idx"
    index = ev.create_index(index_name, DIM)

    # Generate random vector with seed
    num_data = 10
    seed = 42  # Example seed value
    vectors = [get_random_vector(DIM, seed=seed + i) for i in range(num_data)]

    # Encrypt vectors.
    # NOTE: In MM eval mode, single-vector encryption may be unsupported; use batch encryption instead.
    db_ctxt = index.cipher.encrypt_multiple(vectors, "item")
    print("Vector encrypted successfully.")

    # Insert encrypted vector into index
    print(f"Inserting {num_data} encrypted vectors into index '{index_name}'...")
    db_metadata = [f"Item {i + 1}" for i in range(num_data)]
    index.insert([db_ctxt], metadata=db_metadata)

    # Search
    query = vectors[0].tolist()
    print(f"Searching for query vector in index '{index_name}'...")
    search_index = ev.Index(index_name)
    results = search_index.search(query, top_k=1, output_fields=["metadata"])
    print(f"Search results: {results[0]}")

    assert abs(results[0][0]["score"] - 1) < 0.001, "Search score should be close to 1"

    ev.drop_index(index_name)
    ev.unload_key(args.key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector API Example")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID")
    parser.add_argument("--eval-mode", type=str, choices=["mm", "mms", "mm32", "mms32"], default="mm32", help="Evaluation mode")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    main(args)
