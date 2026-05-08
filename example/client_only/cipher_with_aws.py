# """
# Quick start (AWS + this example)

# 1) Configure AWS credentials using the default provider chain:
#    - AWS profile: export AWS_PROFILE=your-profile
#    - IAM role (EC2/ECS/Lambda): no env vars needed
#    - Or env vars: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
#    export AWS_DEFAULT_REGION=us-east-1

# 2) Set target S3 bucket (must exist):
#    export EVI_AWS_BUCKET=your-bucket

# 3) Run:
#    pipenv run python example/client_only/cipher_with_aws.py

# 4) (Optional) Enable AES KEK sealing:
#    - set `USE_AES_KEK = True`
#    - set `KEK_PATH` to your KEK file path
# """

# import json
# import os
# from pathlib import Path
# import sys
# import time

# import numpy as np

# from pyenvector.crypto import Cipher, KeyGenerator
# from pyenvector.utils import AWSClient, utils

# # Simple single-example config
# EVAL_MODE = "mm32"
# PRESET = "ip1"
# DIM = 512

# REGION_NAME = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
# S3_BUCKET = os.environ.get("EVI_AWS_BUCKET", "amazon-s3-bucket")
# SECRET_PREFIX = "envector/keys"
# KEY_ID = os.environ.get("EVI_AWS_KEY_ID", f"test-key-{int(time.time())}")
# OVERWRITE_IF_EXISTS = True
# DELETE_AT_END = False

# # Added option: toggle AES KEK sealing for sec/metadata.
# USE_AES_KEK = True
# KEK_PATH = "./aes.kek"


# def print_api(name, payload):
#     print(f"[API] {name}")
#     if isinstance(payload, (dict, list)):
#         print(json.dumps(payload, indent=2, sort_keys=True, default=str))
#     else:
#         print(payload)
#     print()


# def get_random_vector(dim, seed=None):
#     if seed is not None:
#         np.random.seed(seed)

#     if dim < 32 or dim > 4096:
#         raise ValueError(f"Invalid dimension: {dim}")

#     vec = np.random.uniform(-1.0, 1.0, dim)
#     norm = np.linalg.norm(vec)
#     if norm > 0:
#         vec = vec / norm
#     return vec


# def summarize_key_dict(key_dict):
#     summary = {"fields": sorted(list(key_dict.keys()))}
#     for name, value in key_dict.items():
#         value_type = type(value).__name__
#         value_size = len(value) if hasattr(value, "__len__") else None
#         summary[name] = {"type": value_type, "size": value_size}
#     return summary


# def store_key_dict_compat(aws_client, key_dict, key_id, use_aes_kek, seal_info):
#     """
#     Store keys with best-effort compatibility across v0 and newer SDKs.
#     """
#     if not use_aes_kek:
#         aws_client.store_key_dict(key_dict, key_id=key_id)
#         return "plain"

#     store_with_sealing = getattr(aws_client, "store_key_dict_with_sealing", None)
#     if callable(store_with_sealing):
#         try:
#             store_with_sealing(key_dict, key_id=key_id, seal_info=seal_info)
#             return "sealed"
#         except TypeError:
#             # Older signatures may not accept seal_info; fall back to legacy path.
#             pass

#     aws_client.store_key_dict(key_dict, key_id=key_id)
#     return "legacy-no-seal"


# def load_key_dict_compat(aws_client, key_id, use_aes_kek, seal_info):
#     """
#     Load keys with best-effort compatibility across v0 and newer SDKs.
#     """
#     if use_aes_kek:
#         load_with_unsealing = getattr(aws_client, "load_key_dict_with_unsealing", None)
#         if callable(load_with_unsealing):
#             try:
#                 loaded = load_with_unsealing(key_id, seal_info=seal_info)
#                 return loaded, loaded["sec_blob"], "unsealed"
#             except TypeError:
#                 # Older signatures may not accept seal_info; fall through.
#                 pass

#     loaded = aws_client.load_key_dict(key_id=key_id)
#     return loaded, utils.get_key_stream(loaded["sec_blob"]), "legacy-load"


# def main():
#     if USE_AES_KEK and not os.path.isfile(KEK_PATH):
#         raise FileNotFoundError(f"KEK file not found: {KEK_PATH}")

#     aws_client = AWSClient(region_name=REGION_NAME, s3_bucket=S3_BUCKET, secret_prefix=SECRET_PREFIX)
#     seal_info = utils._get_seal_info("aes", KEK_PATH) if USE_AES_KEK else None

#     print_api(
#         "config",
#         {
#             "region_name": REGION_NAME,
#             "s3_bucket": S3_BUCKET,
#             "secret_prefix": SECRET_PREFIX,
#             "key_id": KEY_ID,
#             "eval_mode": EVAL_MODE,
#             "overwrite_if_exists": OVERWRITE_IF_EXISTS,
#             "use_aes_kek": USE_AES_KEK,
#             "kek_path": KEK_PATH if USE_AES_KEK else None,
#         },
#     )

#     before = aws_client.check_key_id(KEY_ID)
#     print_api("check_key_id (before)", before)

#     if before.get("all_present") and OVERWRITE_IF_EXISTS:
#         aws_client.delete_all_keys(KEY_ID)
#         print_api("delete_all_keys (overwrite)", {"ok": True, "key_id": KEY_ID})

#     keygen = KeyGenerator(
#         key_id=KEY_ID,
#         eval_mode=EVAL_MODE,
#         metadata_encryption=USE_AES_KEK,
#     )
#     key_dict = keygen.generate_keys_stream()
#     print_api("keygen.generate_keys_stream", summarize_key_dict(key_dict))

#     store_mode = store_key_dict_compat(
#         aws_client=aws_client,
#         key_dict=key_dict,
#         key_id=KEY_ID,
#         use_aes_kek=USE_AES_KEK,
#         seal_info=seal_info,
#     )
#     print_api("store_key_dict", {"ok": True, "key_id": KEY_ID, "mode": store_mode})

#     exists = aws_client.verify_key_id(KEY_ID)
#     print_api("verify_key_id", {"exists": exists})

#     loaded, sec_key_stream_bytes, load_mode = load_key_dict_compat(
#         aws_client=aws_client,
#         key_id=KEY_ID,
#         use_aes_kek=USE_AES_KEK,
#         seal_info=seal_info,
#     )
#     print_api("load_key_dict", summarize_key_dict(loaded))
#     print_api("load_key_dict_mode", {"mode": load_mode})

#     all_keys = aws_client.list_keys()
#     print_api("list_keys", all_keys)

#     vec = get_random_vector(DIM, seed=42)
#     cipher = Cipher(
#         dim=DIM,
#         preset=PRESET,
#         eval_mode=EVAL_MODE,
#         use_key_stream=True,
#         sec_key=sec_key_stream_bytes,
#     )
#     ctxt = cipher.encrypt_multiple([vec], "item", enc_key=loaded["enc_blob"])
#     dec = cipher.decryptor.decrypt(ctxt.data[0], sec_key=sec_key_stream_bytes)
#     print_api(
#         "cipher.encrypt/decrypt",
#         {
#             "plaintext_head": [round(float(x), 6) for x in vec[0:5]],
#             "ciphertext_size": len(ctxt.serialize()),
#             "decrypted_head": [round(float(x), 6) for x in dec[0:5]],
#         },
#     )

#     if DELETE_AT_END:
#         aws_client.delete_all_keys(KEY_ID)
#         print_api("delete_all_keys", {"ok": True, "key_id": KEY_ID})

#     after = aws_client.check_key_id(KEY_ID)
#     print_api("check_key_id (after)", after)


# if __name__ == "__main__":
#     main()
