# """
# Quick start (Docker Vault + this example)

# 1) Start Vault dev server:
#    docker rm -f dev-vault 2>/dev/null || true
#    docker run -d --rm --name dev-vault \
#      -p 8200:8200 \
#      -e VAULT_DEV_ROOT_TOKEN_ID=root \
#      -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
#      hashicorp/vault:1.16 server -dev

# 2) Set env vars:
#    export VAULT_ADDR=http://127.0.0.1:8200
#    export VAULT_TOKEN=root

# 3) Run:
#    pipenv run python example/client_only/cipher_with_vault.py

# 4) (Optional) Enable AES KEK sealing:
#    - set `USE_AES_KEK = True`
#    - set `KEK_PATH` to your KEK file path
# """

# import json
# import os
# import time

# import numpy as np

# from pyenvector.crypto import Cipher, KeyGenerator
# from pyenvector.utils import VaultClient, utils

# EVAL_MODE = "mm32"
# PRESET = "ip1"
# DIM = 512

# VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
# VAULT_MOUNT = os.environ.get("VAULT_MOUNT", "secret")
# SECRET_PREFIX = os.environ.get("EVI_VAULT_PREFIX", "envector/keys")
# KEY_ID = os.environ.get("EVI_VAULT_KEY_ID", f"test-key-vault-{int(time.time())}")
# OVERWRITE_IF_EXISTS = True
# DELETE_AT_END = False

# USE_AES_KEK = False
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


# def main():
#     if not os.environ.get("VAULT_TOKEN"):
#         raise ValueError("VAULT_TOKEN environment variable is required")
#     if USE_AES_KEK and not os.path.isfile(KEK_PATH):
#         raise FileNotFoundError(f"KEK file not found: {KEK_PATH}")

#     vault_client = VaultClient(
#         vault_addr=VAULT_ADDR,
#         vault_mount=VAULT_MOUNT,
#         secret_prefix=SECRET_PREFIX,
#     )
#     seal_info = utils._get_seal_info("aes", KEK_PATH) if USE_AES_KEK else None

#     print_api(
#         "config",
#         {
#             "vault_addr": VAULT_ADDR,
#             "vault_mount": VAULT_MOUNT,
#             "secret_prefix": SECRET_PREFIX,
#             "key_id": KEY_ID,
#             "eval_mode": EVAL_MODE,
#             "overwrite_if_exists": OVERWRITE_IF_EXISTS,
#             "use_aes_kek": USE_AES_KEK,
#             "kek_path": KEK_PATH if USE_AES_KEK else None,
#         },
#     )

#     before = vault_client.check_key_id(KEY_ID)
#     print_api("check_key_id (before)", before)

#     if before.get("all_present") and OVERWRITE_IF_EXISTS:
#         vault_client.delete_all_keys(KEY_ID)
#         print_api("delete_all_keys (overwrite)", {"ok": True, "key_id": KEY_ID})

#     keygen = KeyGenerator(
#         key_id=KEY_ID,
#         eval_mode=EVAL_MODE,
#         metadata_encryption=USE_AES_KEK,
#     )
#     key_dict = keygen.generate_keys_stream()
#     print_api("keygen.generate_keys_stream", summarize_key_dict(key_dict))

#     if USE_AES_KEK:
#         vault_client.store_key_dict_with_sealing(key_dict, key_id=KEY_ID, seal_info=seal_info)
#     else:
#         vault_client.store_key_dict(key_dict, key_id=KEY_ID)
#     print_api("store_key_dict", {"ok": True, "key_id": KEY_ID})

#     exists = vault_client.verify_key_id(KEY_ID)
#     print_api("verify_key_id", {"exists": exists})

#     if USE_AES_KEK:
#         loaded = vault_client.load_key_dict_with_unsealing(KEY_ID, seal_info=seal_info)
#         sec_key_stream_bytes = loaded["sec_blob"]
#     else:
#         loaded = vault_client.load_key_dict(key_id=KEY_ID)
#         sec_key_stream_bytes = utils.get_key_stream(loaded["sec_blob"])
#     print_api("load_key_dict", summarize_key_dict(loaded))

#     all_keys = vault_client.list_keys()
#     print_api("list_keys", all_keys)

#     vec = get_random_vector(DIM, seed=42)
#     cipher = Cipher(
#         dim=DIM,
#         preset=PRESET,
#         eval_mode=EVAL_MODE,
#         use_key_stream=True,
#         sec_key=sec_key_stream_bytes,
#     )
#     # Vault stores sec/metadata only. Use local in-memory enc key from keygen output.
#     ctxt = cipher.encrypt_multiple([vec], "item", enc_key=key_dict["enc_blob"])
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
#         vault_client.delete_all_keys(KEY_ID)
#         print_api("delete_all_keys", {"ok": True, "key_id": KEY_ID})

#     after = vault_client.check_key_id(KEY_ID)
#     print_api("check_key_id (after)", after)


# if __name__ == "__main__":
#     main()
