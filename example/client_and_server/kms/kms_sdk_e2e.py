"""Example: KMS <-> SDK only flow using the SDK KMS client.

This example keeps the scope limited to KMS gRPC operations exposed through
``pyenvector.kms.client.KMSClient``:

1. Generate a key bundle
2. Wait for READY
3. Read key details
4. Download EncKey and EvalKey
5. Optionally clean up the key
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parents[3]
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

from _kms_e2e_common import (
    configure_local_kms_tls_roots,
    derive_local_metadata_key_from_seed,
    parse_key_seed,
    short_key_id,
)

from pyenvector.kms.client import KMSClient
from pyenvector.utils.aes import decrypt_metadata

_DEFAULT_SEED_HEX = "00" * 64


def main(args: argparse.Namespace) -> None:
    key_id = args.key_id or short_key_id("sdk")
    key_seed = parse_key_seed(args.key_seed_hex, None)
    print(f"[config] KMS={args.kms_address}", flush=True)
    print(f"[config] KMS TLS={'disabled' if args.notls else 'enabled'}", flush=True)
    kms_ca = configure_local_kms_tls_roots(args.kms_address, secure=not args.notls)
    if kms_ca:
        print(f"[config] KMS CA={kms_ca}", flush=True)
    print(f"[config] key_id={key_id}", flush=True)
    print(f"[config] eval_mode={args.eval_mode}", flush=True)
    print(f"[config] preset={args.preset}", flush=True)
    print(f"[config] key_seed={'custom' if args.key_seed_hex != _DEFAULT_SEED_HEX else 'default'}", flush=True)

    kms_client = KMSClient(address=args.kms_address, secure=not args.notls, ca_cert=kms_ca)
    try:
        print("[step] GenerateKey", flush=True)
        generate_kwargs = {"key_id": key_id, "metadata_encryption": True, "seed": key_seed}
        if args.eval_mode is not None:
            generate_kwargs["eval_mode"] = args.eval_mode
        if args.preset is not None:
            generate_kwargs["preset"] = args.preset
        generate_result = kms_client.generate_key(**generate_kwargs)
        print(f"  -> {generate_result}", flush=True)

        print("[step] WaitForKey", flush=True)
        status = kms_client.wait_for_key(key_id, timeout=args.timeout)
        print(f"  -> {status}", flush=True)

        print("[step] GetKeyDetails", flush=True)
        details = kms_client.get_key_details(key_id)
        print(f"  -> versions={len(details.get('versions', []))}", flush=True)

        print("[step] DownloadKey", flush=True)
        enc_key = kms_client.download_enc_key(key_id)
        eval_key = kms_client.download_eval_key(key_id)
        print(f"  -> EncKey={len(enc_key)} bytes EvalKey={len(eval_key)} bytes", flush=True)

        if not details.get("versions"):
            raise RuntimeError("KMS returned no key versions after READY")
        if not enc_key or not eval_key:
            raise RuntimeError("KMS returned empty public key material")

        print("[step] Verify SDK decrypts metadata encrypted by KMS (seed-based key)", flush=True)
        local_meta_key = derive_local_metadata_key_from_seed(key_seed)
        kms_plaintext = [f'{{"source":"kms","rank":{i}}}' for i in range(3)]
        kms_encrypted = kms_client.encrypt_metadata(key_id, kms_plaintext)
        sdk_decrypted = [
            decrypt_metadata(base64.b64encode(item).decode("ascii"), local_meta_key)
            for item in kms_encrypted
        ]
        expected = [{"source": "kms", "rank": i} for i in range(3)]
        kms_encrypt_sdk_decrypt_match = sdk_decrypted == expected
        print("[result] kms_encrypt_sdk_decrypt_match =", kms_encrypt_sdk_decrypt_match, flush=True)
        if not kms_encrypt_sdk_decrypt_match:
            raise RuntimeError(
                f"SDK failed to decrypt KMS-encrypted metadata: got {sdk_decrypted}, expected {expected}"
            )

        print("[result] kms_sdk_only_ok = True", flush=True)
    finally:
        try:
            if not args.skip_cleanup:
                print("[cleanup] DeleteKey", flush=True)
                try:
                    kms_client.delete_key(key_id=key_id, reason="kms_sdk_e2e cleanup")
                except Exception as exc:
                    print(f"[cleanup] DeleteKey skipped: {exc}", flush=True)
        finally:
            kms_client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KMS <-> SDK only E2E example")
    parser.add_argument(
        "--kms-address",
        type=str,
        default=os.environ.get("KMS_INTEGRATION_ADDR", "localhost:50100"),
        help="KMS gRPC address",
    )
    parser.add_argument("--port", type=int, default=None, help="Ignored. Kept for script compatibility.")
    parser.add_argument("--notls", action="store_true", help="Use plaintext for the KMS gRPC connection")
    parser.add_argument("--key-id", type=str, default=None, help="Key ID for this run")
    parser.add_argument("--timeout", type=float, default=120.0, help="Key generation timeout in seconds")
    parser.add_argument("--skip-cleanup", action="store_true", help="Skip KMS key deletion")
    parser.add_argument(
        "--key-seed-hex",
        type=str,
        default=os.environ.get("E2E_KEY_SEED_HEX", _DEFAULT_SEED_HEX),
        help="128-character hex seed for deterministic key generation",
    )
    parser.add_argument(
        "--preset",
        type=str,
        default=os.environ.get("KMS_PRESET", "ip3"),
        help="Key preset (must match between SDK local KeyGenerator and KMS)",
    )
    parser.add_argument(
        "--eval-mode",
        type=str,
        default=os.environ.get("KMS_EVAL_MODE", "mm32"),
        help="Eval mode (must match between SDK local KeyGenerator and KMS)",
    )
    main(parser.parse_args())
