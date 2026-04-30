"""
IVF_FLAT insert with pre-encrypted CipherBlock and explicit centroids_idx.

How to run:
    python ./example/client_and_server/indexing/ivf_with_encrypted_centroids.py
"""

import argparse

import numpy as np
from sklearn.cluster import KMeans

import pyenvector as ev


def get_random_vector(dim, seed=None):
    if seed is not None:
        np.random.seed(seed)

    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec


def main(args):
    envector_address = f"{args.host}:{args.port}"
    ev.init(
        address=envector_address,
        key_path="./keys",
        key_id="test-key",
    )

    dim = args.dim
    num_data = args.num_data
    nlist = args.nlist
    seed = 42

    vectors = [get_random_vector(dim, seed=seed + i) for i in range(num_data)]
    metadata = [f"item-{i}" for i in range(num_data)]

    kmeans = KMeans(n_clusters=nlist, random_state=seed)
    kmeans.fit(np.stack(vectors))
    centroids = [c for c in kmeans.cluster_centers_]
    centroids_idx = kmeans.predict(np.stack(vectors)).tolist()

    index_params = {"index_type": "IVF_FLAT", "nlist": nlist, "centroids": centroids, "default_nprobe": 1}
    index_name = "ivf_encrypted"
    index = ev.create_index(index_name, dim, index_params=index_params)
    print(f"Index created: {index_name}")

    # Encrypt item vectors with centroid assignments embedded in CipherBlock.
    encrypted_block = index.cipher.encrypt_multiple(vectors, centroids_idx=centroids_idx)

    # Insert pre-encrypted data into IVF index.
    index.insert([encrypted_block], metadata=metadata)
    print(f"Inserted {num_data} encrypted vectors with centroids_idx.")

    query = vectors[0].tolist()
    result = ev.Index(index_name).search(query, top_k=2, output_fields=["metadata"])[0]
    print("Search result:", result)

    ev.reset()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IVF encrypted insert with centroids_idx example")
    parser.add_argument("--dim", type=int, default=512)
    parser.add_argument("--num-data", type=int, default=10000, dest="num_data")
    parser.add_argument("--nlist", type=int, default=8)
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=50050)
    args = parser.parse_args()
    main(args)
