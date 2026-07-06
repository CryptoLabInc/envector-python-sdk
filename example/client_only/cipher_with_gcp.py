"""
Quick start (GCP + this example)

1) Set credentials:
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
   # or token-based flow expected by runtime
   # export GCP_OAUTH_TOKEN=...

2) Set bucket (must exist):
   export EVI_GCP_BUCKET=your-gcs-bucket

3) Run:
   python example/client_only/cipher_with_gcp.py

4) (Optional) Enable AES KEK sealing:
   - set `USE_AES_KEK = True`
   - set `KEK_PATH` to your KEK file path
"""

import json
import os
import sys
import time

import numpy as np

from pyenvector.crypto import Cipher, KeyGenerator
from pyenvector.utils import GCPClient, utils

EVAL_MODE = "mm32"
PRESET = "ip3"
DIM = 512

BUCKET_NAME = os.environ.get("EVI_GCP_BUCKET", "envector-key-storage")
SECRET_PREFIX = "envector/keys"
KEY_ID = os.environ.get("EVI_GCP_KEY_ID", f"test-key-gcp-{int(time.time())}")
OVERWRITE_IF_EXISTS = True
DELETE_AT_END = False

USE_AES_KEK = True
KEK_PATH = "./aes.kek"


def print_api(name, payload):
    print(f"[API] {name}")
    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(payload)
    print()


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


def summarize_key_dict(key_dict):
    summary = {"fields": sorted(list(key_dict.keys()))}
    for name, value in key_dict.items():
        value_type = type(value).__name__
        value_size = len(value) if hasattr(value, "__len__") else None
        summary[name] = {"type": value_type, "size": value_size}
    return summary


def main():
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") and not os.environ.get("GCP_OAUTH_TOKEN"):
        print("Skipping GCP example: set GOOGLE_APPLICATION_CREDENTIALS or GCP_OAUTH_TOKEN to run this example.")
        sys.exit(0)
    if USE_AES_KEK and not os.path.isfile(KEK_PATH):
        raise FileNotFoundError(f"KEK file not found: {KEK_PATH}")

    gcp_client = GCPClient(bucket_name=BUCKET_NAME, secret_prefix=SECRET_PREFIX)
    seal_info = utils._get_seal_info("aes", KEK_PATH) if USE_AES_KEK else None

    print_api(
        "config",
        {
            "bucket_name": BUCKET_NAME,
            "secret_prefix": SECRET_PREFIX,
            "key_id": KEY_ID,
            "eval_mode": EVAL_MODE,
            "overwrite_if_exists": OVERWRITE_IF_EXISTS,
            "use_aes_kek": USE_AES_KEK,
            "kek_path": KEK_PATH if USE_AES_KEK else None,
        },
    )

    before = gcp_client.check_key_id(KEY_ID)
    print_api("check_key_id (before)", before)

    if before.get("all_present") and OVERWRITE_IF_EXISTS:
        gcp_client.delete_all_keys(KEY_ID)
        print_api("delete_all_keys (overwrite)", {"ok": True, "key_id": KEY_ID})

    keygen = KeyGenerator(
        key_id=KEY_ID,
        eval_mode=EVAL_MODE,
        metadata_encryption=USE_AES_KEK,
    )
    key_dict = keygen.generate_keys_stream()
    print_api("keygen.generate_keys_stream", summarize_key_dict(key_dict))

    if USE_AES_KEK:
        gcp_client.store_key_dict_with_sealing(key_dict, key_id=KEY_ID, seal_info=seal_info)
    else:
        gcp_client.store_key_dict(key_dict, key_id=KEY_ID)
    print_api("store_key_dict", {"ok": True, "key_id": KEY_ID})

    exists = gcp_client.verify_key_id(KEY_ID)
    print_api("verify_key_id", {"exists": exists})

    if USE_AES_KEK:
        loaded = gcp_client.load_key_dict_with_unsealing(KEY_ID, seal_info=seal_info)
        sec_key_stream_bytes = loaded["sec_blob"]
    else:
        loaded = gcp_client.load_key_dict(key_id=KEY_ID)
        sec_key_stream_bytes = utils.get_key_stream(loaded["sec_blob"])
    print_api("load_key_dict", summarize_key_dict(loaded))

    all_keys = gcp_client.list_keys()
    print_api("list_keys", all_keys)

    vec = get_random_vector(DIM, seed=42)
    cipher = Cipher(
        dim=DIM,
        preset=PRESET,
        eval_mode=EVAL_MODE,
        use_key_stream=True,
        sec_key=sec_key_stream_bytes,
    )
    ctxt = cipher.encrypt_multiple([vec], "item", enc_key=loaded["enc_blob"])
    dec = cipher.decryptor.decrypt(ctxt.data[0], sec_key=sec_key_stream_bytes)

    print_api(
        "cipher.encrypt/decrypt",
        {
            "plaintext_head": [round(float(x), 6) for x in vec[0:5]],
            "ciphertext_size": len(ctxt.serialize()),
            "decrypted_head": [round(float(x), 6) for x in dec[0:5]],
        },
    )

    if DELETE_AT_END:
        gcp_client.delete_all_keys(KEY_ID)
        print_api("delete_all_keys", {"ok": True, "key_id": KEY_ID})

    after = gcp_client.check_key_id(KEY_ID)
    print_api("check_key_id (after)", after)


if __name__ == "__main__":
    main()
