"""
enVector UpdateMetadata End-to-End Example

Exercises the UpdateMetadata RPC introduced in ES2-1997 against a FLAT index.

UpdateMetadata edits the metadata string of existing items addressed by
``item_id``. It is a synchronous relational write: the metadata lives in a
table decoupled from the immutable encrypted shards, so the vector data and
search path are untouched and no re-index/merge is triggered. The new value
overwrites the stored metadata WHOLESALE (there is no read-modify-write merge);
to change one field you must supply the item's full new metadata.

Steps
-----
1. Create a FLAT index (dim=512).
2. Insert a small batch of random unit vectors with initial metadata and
   trigger indexing + load.
3. Search with ``vectors[0]``. Expect top-1 ``id`` to equal the first inserted
   ``item_id`` and its metadata to equal the original value.
4. Call ``index.update_metadata()`` to overwrite the first item's metadata,
   passing one extra non-existent ``item_id`` to show the lenient
   missing/soft-deleted reporting (returned in ``skipped``, not raised).
5. Search again with ``vectors[0]``. Expect the same top-1 ``id`` (vector
   unchanged) but the NEW metadata value, confirming the wholesale replace.

Run
---
    python ./example/client_and_server/metadata/update_metadata.py --port 50050
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
    original_metadata = [f"Item {i} (original)" for i in range(args.num_vectors)]

    print(f"Inserting {args.num_vectors} vectors...")
    request_ids = []
    item_ids = index.insert(
        vectors,
        metadata=original_metadata,
        request_ids=request_ids,
    )
    if not item_ids or len(item_ids) != args.num_vectors:
        raise RuntimeError(
            f"Expected {args.num_vectors} item_ids, got "
            f"{len(item_ids) if item_ids else 0}"
        )
    target_item_id = item_ids[0]
    print(f"Target item_id for update test: {target_item_id}")

    # Query is the first inserted vector itself — the self-match in the index.
    query = [vectors[0]]

    # Pre-update search: top-1 id is the target and its metadata is the original.
    pre_hits = index.search(query, top_k=args.topk, output_fields=["metadata"])
    assert pre_hits and pre_hits[0], "Expected pre-update search to return hits"
    pre_top = pre_hits[0][0]
    pre_top_id = pre_top.get("id")
    print(
        f"Pre-update top-1: id={pre_top_id} "
        f"score={float(pre_top.get('score', 0.0)):.4f} "
        f"metadata={pre_top.get('metadata')!r}"
    )
    if pre_top_id != target_item_id:
        raise AssertionError(
            f"Pre-update top-1 id {pre_top_id} does not match target "
            f"item_id {target_item_id} (self-match should be top-1)."
        )

    # Update the target's metadata wholesale. Also pass a non-existent item_id
    # to demonstrate lenient handling: missing/soft-deleted ids are reported in
    # "skipped" rather than raising.
    new_value = "Item 0 (UPDATED)"
    missing_item_id = max(item_ids) + 10_000
    print(
        f"Updating metadata of item_id={target_item_id} to {new_value!r}; "
        f"also requesting non-existent item_id={missing_item_id} ..."
    )
    report = index.update_metadata(
        item_ids=[target_item_id, missing_item_id],
        metadata=[new_value, "ignored"],
    )
    print(f"update_metadata report: {report}")
    if report["updated"] != [target_item_id]:
        raise AssertionError(
            f"Expected updated=[{target_item_id}], got {report['updated']}"
        )
    if report["skipped"] != [missing_item_id]:
        raise AssertionError(
            f"Expected skipped=[{missing_item_id}] (non-existent), "
            f"got {report['skipped']}"
        )

    # Post-update search: same top-1 id (the vector is untouched) but the NEW
    # metadata value. No re-index/merge was needed.
    post_hits = index.search(query, top_k=args.topk, output_fields=["metadata"])
    assert post_hits and post_hits[0], "Expected post-update search to return hits"
    post_top = post_hits[0][0]
    post_top_id = post_top.get("id")
    post_top_meta = post_top.get("metadata")
    print(
        f"Post-update top-1: id={post_top_id} "
        f"score={float(post_top.get('score', 0.0)):.4f} "
        f"metadata={post_top_meta!r}"
    )
    if post_top_id != target_item_id:
        raise AssertionError(
            f"Post-update top-1 id {post_top_id} changed unexpectedly; "
            f"UpdateMetadata must not move the vector."
        )
    if post_top_meta != new_value:
        raise AssertionError(
            f"Post-update metadata {post_top_meta!r} does not match the new "
            f"value {new_value!r}; the wholesale replace did not take effect."
        )
    print("PASS: metadata was replaced wholesale and the vector is unchanged.")

    # Cleanup.
    ev.drop_index(index_name)
    ev.unload_key(key_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector UpdateMetadata E2E Example")
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=50050)
    parser.add_argument("--dim", type=int, default=512)
    parser.add_argument("--num-vectors", type=int, default=10)
    parser.add_argument("--index-name", type=str, default="update_meta_idx")
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
