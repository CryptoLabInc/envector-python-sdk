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
import os

from _kms_e2e_common import short_key_id

from pyenvector.kms.client import KMSClient


def main(args: argparse.Namespace) -> None:
    key_id = args.key_id or short_key_id("sdk")
    print(f"[config] KMS={args.kms_address}", flush=True)
    print(f"[config] key_id={key_id}", flush=True)

    kms_client = KMSClient(address=args.kms_address)
    try:
        print("[step] GenerateKey", flush=True)
        generate_result = kms_client.generate_key(key_id=key_id)
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
    parser.add_argument("--key-id", type=str, default=None, help="Key ID for this run")
    parser.add_argument("--timeout", type=float, default=120.0, help="Key generation timeout in seconds")
    parser.add_argument("--skip-cleanup", action="store_true", help="Skip KMS key deletion")
    main(parser.parse_args())
