"""
enVector DeleteData End-to-End Example

Exercises the DeleteData RPC introduced in ES2-1842 against a FLAT index.

Steps
-----
1. Create a FLAT index (dim=512).
2. Insert a small batch of random unit vectors and trigger indexing + load.
3. Search with ``vectors[0]``. Expect top-1 ``id`` to equal the first
   inserted ``item_id`` (self-match by identity, not by score).
4. Delete the first inserted ``item_id`` via ``index.delete()`` which
   blocks until the DeleteData operation reaches SEARCHABLE.
5. Search again with ``vectors[0]``. Expect the deleted ``item_id`` to
   be absent from the entire top-k result set, confirming the deleted
   item has been excluded from the search path.

Run
---
    python ./example/client_and_server/e2e/delete_data.py --port 50050
"""

import argparse

import numpy as np

import pyenvector as ev
from pyenvector.utils.utils import resolve_preset


BASE_VECTOR_SEED = 42


def get_random_vector(dim, seed):
    np.random.seed(seed)
    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec


def main(args):
    preset = resolve_preset(args.preset, args.eval_mode)
    key_id = args.key_id or f"test-key-{args.eval_mode}-{preset}"
    address = f"{args.host}:{args.port}"
    index_name = f"{args.index_name}_{args.eval_mode}"

    ev.init(
        address=address,
        key_path="./keys",
        key_id=key_id,
        eval_mode=args.eval_mode,
        preset=preset,
    )
    print("enVector initialized.")

    # Clean slate: drop if a prior run left the index behind.
    if index_name in ev.get_index_list():
        ev.drop_index(index_name)

    index = ev.create_index(
        index_name, args.dim, index_params={"index_type": "FLAT"}
    )
    print(f"Index {index_name} (FLAT, dim={args.dim}) created.")

    vectors = [
        get_random_vector(args.dim, seed=BASE_VECTOR_SEED + i)
        for i in range(args.num_vectors)
    ]
    metadata = [f"Item {i}" for i in range(args.num_vectors)]

    print(f"Inserting {args.num_vectors} vectors...")
    request_ids = []
    item_ids = index.insert(
        vectors,
        metadata=metadata,
        request_ids=request_ids,
        await_completion=True,
    )
    if not item_ids or len(item_ids) != args.num_vectors:
        raise RuntimeError(
            f"Expected {args.num_vectors} item_ids, got "
            f"{len(item_ids) if item_ids else 0}"
        )
    target_item_id = item_ids[0]
    print(f"Target item_id for delete test: {target_item_id}")

    # Query is the first inserted vector itself — the self-match in the
    # index. If DeleteData works, this exact match must disappear after
    # the delete.
    query = [vectors[0]]

    # Pre-delete search: top-1 id must equal the target item_id.
    # Identity-based check is robust even when score gaps between
    # correct/incorrect neighbors are small (dense embedding spaces).
    pre_hits = index.search(query, top_k=args.topk, output_fields=["metadata"])
    assert pre_hits and pre_hits[0], "Expected pre-delete search to return hits"
    pre_top = pre_hits[0][0]
    pre_top_id = pre_top.get("id")
    print(
        f"Pre-delete top-1: id={pre_top_id} "
        f"score={float(pre_top.get('score', 0.0)):.4f} "
        f"metadata={pre_top.get('metadata')}"
    )
    if pre_top_id != target_item_id:
        raise AssertionError(
            f"Pre-delete top-1 id {pre_top_id} does not match target "
            f"item_id {target_item_id}; the index setup or data "
            f"generation is incorrect (self-match should be top-1)."
        )

    # Delete and wait for SEARCHABLE. Index.delete() defaults to
    # await_completion=True, so this call returns only after the
    # DeleteData operation has physically removed the item from the
    # search path.
    print(f"Deleting item_id={target_item_id} ...")
    index.delete(item_ids=[target_item_id])
    print("Delete completed (SEARCHABLE reached).")

    # Post-delete search: target_item_id must NOT appear anywhere in the
    # top-k hits. Checking the entire result set (not just top-1) is a
    # stronger guarantee that the item was physically excluded.
    post_hits = index.search(query, top_k=args.topk, output_fields=["metadata"])
    assert post_hits and post_hits[0], "Expected post-delete search to return hits"
    post_ids = [hit.get("id") for hit in post_hits[0]]
    post_top = post_hits[0][0]
    print(
        f"Post-delete top-1: id={post_top.get('id')} "
        f"score={float(post_top.get('score', 0.0)):.4f} "
        f"metadata={post_top.get('metadata')}"
    )
    print(f"Post-delete top-{args.topk} ids: {post_ids}")
    if target_item_id in post_ids:
        raise AssertionError(
            f"Post-delete top-{args.topk} still contains target item_id "
            f"{target_item_id}; deleted item was not excluded from the "
            f"search path."
        )
    print("PASS: deleted item is excluded from the search path.")

    # Cleanup.
    ev.drop_index(index_name)
    ev.unload_key(key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector DeleteData E2E Example")
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=50050)
    parser.add_argument("--dim", type=int, default=512)
    parser.add_argument("--num-vectors", type=int, default=10)
    parser.add_argument("--index-name", type=str, default="del_data_idx")
    parser.add_argument("--key-id", type=str, default=None)
    parser.add_argument(
        "--eval-mode",
        type=str,
        choices=["mm", "mms", "mm32", "mms32"],
        default="mm32",
    )
    parser.add_argument("--topk", type=int, default=5)
    parser.add_argument(
        "--preset",
        type=str,
        choices=["ip1", "ip2", "ip3"],
        default=None,
        help="Parameter preset. Default: ip1 for mm/mms, ip3 for mm32/mms32.",
    )
    args = parser.parse_args()
    main(args)
