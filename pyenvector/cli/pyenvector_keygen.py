# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

import argparse
import sys
from pathlib import Path
from typing import Optional

import pyenvector
from pyenvector.crypto import KeyManager


def ensure_dir_empty(path_str: str) -> None:
    p = Path(path_str).expanduser().resolve()

    if p.exists() and p.is_file():
        raise ValueError(f"[ERROR] '{p}' is file. This should be directory.")

    if p.exists() and any(p.iterdir()):
        raise ValueError(f"[ERROR] '{p}' directory is NOT empty. Key generation canceled.")


def ensure_kek_loaded(args, parser):
    if args.seal_mode == "none":
        return "none", None
    elif args.seal_mode != "aes":
        raise ValueError(f"Invalid seal mode: {args.seal_mode}. Choose from 'none' or 'aes'.")

    if args.seal_key_path:
        with open(args.seal_key_path, "rb") as f:
            kek_bytes = f.read()
    else:
        if not args.seal_key_stdin:
            parser.error(
                "--seal_mode aes requires --seal_key_stdin (read KEK from stdin) or "
                "--seal_key_path (read KEK from file)."
            )
            sys.exit(1)

        if sys.stdin.isatty():
            print("Enter AES KEK (32 bytes):", file=sys.stderr)
        kek_bytes = sys.stdin.buffer.read(32)

    if len(kek_bytes) < 32:
        raise ValueError(f"KEK must be 32 bytes, got {len(kek_bytes)} bytes.")
    if len(kek_bytes) > 32:
        print("[WARN] KEK longer than 32 bytes; only the first 32 bytes will be used.", file=sys.stderr)
        kek_bytes = kek_bytes[:32]

    return "aes", kek_bytes


def _create_key_generator(
    key_path,
    key_id,
    dim_list,
    preset,
    seal_mode,
    seal_kek,
    eval_mode,
    metadata_encryption,
):
    metadata_flag = metadata_encryption if isinstance(metadata_encryption, bool) else metadata_encryption == "true"
    return pyenvector.KeyGenerator(
        key_path=key_path,
        key_id=key_id,
        dim_list=dim_list,
        preset=preset,
        seal_mode=seal_mode,
        seal_kek_path=seal_kek,
        eval_mode=eval_mode,
        metadata_encryption=metadata_flag,
    )


def generate_key(dim_list, outdir, seal_mode, seal_kek, preset, eval_mode, metadata_encryption, key_id):
    keygen = _create_key_generator(
        key_path=outdir,
        key_id=key_id,
        dim_list=dim_list,
        preset=preset,
        seal_mode=seal_mode,
        seal_kek=seal_kek,
        eval_mode=eval_mode,
        metadata_encryption=metadata_encryption,
    )

    print("Generating key...")
    keygen.generate_keys()

    print("Key generated with")
    print(f"  Dim: {dim_list}")
    print(f"  Preset: {preset}")
    print(f"  Seal Mode: {seal_mode}")
    print(f"  Path: {outdir}")


def generate_key_stream(dim_list, key_path, preset, eval_mode, metadata_encryption, key_id):
    keygen = _create_key_generator(
        key_path=key_path,
        key_id=key_id,
        dim_list=dim_list,
        preset=preset,
        seal_mode="none",
        seal_kek=None,
        eval_mode=eval_mode,
        metadata_encryption=metadata_encryption,
    )
    print("Generating key stream...")
    key_dict = keygen.generate_keys_stream()
    print("Key stream generated.")
    return key_dict


def upload_keys_to_aws(key_dict: dict, key_id: str, region_name: str, bucket_name: str, secret_prefix: str):
    """
    Upload generated keys to AWS storage using KeyManager.
    """
    km = KeyManager(
        key_id=key_id,
        key_store="aws",
        region_name=region_name,
        bucket_name=bucket_name,
        secret_prefix=secret_prefix,
    )
    km.save(key_dict)
    print(f"Keys uploaded to AWS for key_id '{key_id}'.")


def main():
    parser = argparse.ArgumentParser(description="Generate a key for the enVector API (pyenvector SDK).")
    parser.add_argument(
        "--dim",
        "--dim_list",
        dest="dim",
        type=int,
        nargs="+",
        default=[32, 64, 128, 256, 512, 1024, 2048, 4096],
        help="Dimension(s) of the key (default: All). You can specify multiple values, e.g., --dim 512 1024",
    )
    parser.add_argument(
        "--key-path",
        "--key_path",
        dest="key_path",
        type=str,
        default="./keys",
        help="Output directory for the key (default: './keys')",
    )
    parser.add_argument(
        "--key-id",
        "--key_id",
        dest="key_id",
        type=str,
        default=None,
        help="Key ID for the key (default: None)",
    )
    parser.add_argument(
        "--seal-mode",
        "--seal_mode",
        dest="seal_mode",
        type=str,
        default="none",
        choices=["none", "aes"],
        help="Sealing mode for the key (default: 'none')",
    )
    parser.add_argument(
        "--preset",
        type=str,
        default="ip",
        choices=["ip", "ip0"],
        help="Parameter preset for the key (default: 'ip')",
    )
    parser.add_argument(
        "--eval-mode",
        "--eval_mode",
        dest="eval_mode",
        type=str,
        default="rmp",
        choices=["rmp", "mm"],
        help="Evaluation mode for the key (default: 'rmp')",
    )
    parser.add_argument(
        "--metadata-encryption",
        "--metadata_encryption",
        dest="metadata_encryption",
        type=str,
        default="true",
        choices=["true", "false"],
        help="Metadata encryption mode for the key (default: 'true')",
    )
    parser.add_argument(
        "--seal-key-path",
        "--seal_key_path",
        dest="seal_key_path",
        type=str,
        help="When using --seal_mode aes, read KEK from file.",
    )
    parser.add_argument(
        "--seal-key-stdin",
        "--seal_key_stdin",
        dest="seal_key_stdin",
        action="store_true",
        help="When using --seal_mode aes, read KEK from standard input (must be exactly 32 bytes).",
    )
    parser.add_argument(
        "--key-store",
        "--key_store",
        dest="key_store",
        type=str,
        default="local",
        choices=["local", "aws"],
        help="Location to store generated keys. Use 'aws' to upload to AWS (default: 'local').",
    )
    parser.add_argument(
        "--region-name",
        "--region_name",
        dest="region_name",
        type=str,
        help="AWS region when --key-store aws is specified.",
    )
    parser.add_argument(
        "--bucket-name",
        "--bucket_name",
        dest="bucket_name",
        type=str,
        help="AWS S3 bucket when --key-store aws is specified.",
    )
    parser.add_argument(
        "--secret-prefix",
        "--secret_prefix",
        dest="secret_prefix",
        type=Optional[str],
        default=None,
        help="AWS Secrets Manager prefix when --key-store aws is specified.",
    )

    args = parser.parse_args()
    outdir = args.key_path + "/" + args.key_id if args.key_id else args.key_path

    use_aws = args.key_store == "aws"
    if use_aws:
        if not args.key_id:
            parser.error("--key-store aws requires --key_id to be specified.")
        if not args.region_name or not args.bucket_name:
            parser.error("--key-store aws requires --region-name and --bucket-name.")
        if args.seal_mode != "none":
            parser.error("--key-store aws does not support sealed key generation.")
        if args.seal_key_path or args.seal_key_stdin:
            parser.error("--seal_key_path and --seal_key_stdin are not supported when using --key-store aws.")
    else:
        ensure_dir_empty(outdir)

    if use_aws:
        key_dict = generate_key_stream(
            args.dim,
            None,
            args.preset,
            args.eval_mode,
            args.metadata_encryption,
            args.key_id,
        )
        upload_keys_to_aws(key_dict, args.key_id, args.region_name, args.bucket_name, args.secret_prefix)
    else:
        seal_mode, seal_kek = ensure_kek_loaded(args, parser)
        generate_key(
            args.dim,
            outdir,
            seal_mode,
            seal_kek,
            args.preset,
            args.eval_mode,
            args.metadata_encryption,
            args.key_id,
        )


if __name__ == "__main__":
    main()
