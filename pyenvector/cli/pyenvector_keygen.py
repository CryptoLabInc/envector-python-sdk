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

import pyenvector
from pyenvector.crypto import KeyManager
from pyenvector.utils.utils import validate_preset_evalmode


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


def load_seed(args, parser) -> bytes | None:
    if args.seed and args.seed_file:
        parser.error("--seed and --seed-file are mutually exclusive.")
    if args.seed:
        try:
            seed = bytes.fromhex(args.seed)
        except ValueError:
            parser.error("--seed must be a valid hex string (128 hex characters = 64 bytes).")
        if len(seed) != 64:
            parser.error(f"--seed must be exactly 64 bytes (128 hex chars), got {len(seed)} bytes.")
        return seed
    if args.seed_file:
        with open(args.seed_file, "rb") as f:
            seed = f.read(65)
        if len(seed) < 64:
            parser.error(f"--seed-file must contain at least 64 bytes, got {len(seed)}.")
        if len(seed) > 64:
            print("[WARN] Seed file longer than 64 bytes; only the first 64 bytes will be used.", file=sys.stderr)
        return seed[:64]
    return None


def _create_key_generator(
    key_path,
    key_id,
    dim_list,
    preset,
    seal_mode,
    seal_kek,
    eval_mode,
    metadata_encryption,
    seed=None,
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
        seed=seed,
    )


def generate_key(dim_list, outdir, seal_mode, seal_kek, preset, eval_mode, metadata_encryption, key_id, seed=None):
    keygen = _create_key_generator(
        key_path=outdir,
        key_id=key_id,
        dim_list=dim_list,
        preset=preset,
        seal_mode=seal_mode,
        seal_kek=seal_kek,
        eval_mode=eval_mode,
        metadata_encryption=metadata_encryption,
        seed=seed,
    )

    print("Generating key...")
    keygen.generate_keys()

    print("Key generated with")
    print(f"  Dim: {dim_list}")
    print(f"  Preset: {preset}")
    print(f"  Seal Mode: {seal_mode}")
    print(f"  Path: {outdir}")
    if seed is not None:
        print("  Seed: (provided, deterministic)")


def generate_key_stream(dim_list, key_path, preset, eval_mode, metadata_encryption, key_id, seed=None):
    keygen = _create_key_generator(
        key_path=key_path,
        key_id=key_id,
        dim_list=dim_list,
        preset=preset,
        seal_mode="none",
        seal_kek=None,
        eval_mode=eval_mode,
        metadata_encryption=metadata_encryption,
        seed=seed,
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


def upload_keys_to_gcp(key_dict: dict, key_id: str, bucket_name: str, secret_prefix: str):
    """
    Upload generated keys to GCP storage using KeyManager.
    """
    km = KeyManager(
        key_id=key_id,
        key_store="gcp",
        bucket_name=bucket_name,
        secret_prefix=secret_prefix,
    )
    km.save(key_dict)
    print(f"Keys uploaded to GCP for key_id '{key_id}'.")


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
        default="ip3",
        choices=["ip1", "ip2", "ip3"],
        help="Parameter preset for the key (default: 'ip3'; ip1/ip2 require mm/mms (u64), ip3 requires mm32/mms32 (u32))",
    )
    parser.add_argument(
        "--eval-mode",
        "--eval_mode",
        dest="eval_mode",
        type=str,
        default="mm32",
        choices=["mm", "mms", "mm32", "mms32"],
        help="Evaluation mode for the key (default: 'mm32')",
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
        choices=["local", "aws", "gcp"],
        help="Location to store generated keys. Use 'aws' or 'gcp' for cloud storage (default: 'local').",
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
        help="Storage bucket when --key-store aws or gcp is specified.",
    )
    parser.add_argument(
        "--secret-prefix",
        "--secret_prefix",
        dest="secret_prefix",
        type=str,
        default="",
        help="Secret prefix when --key-store aws or gcp is specified.",
    )
    parser.add_argument(
        "--seed",
        dest="seed",
        type=str,
        default=None,
        help=(
            "128-character hex string (64 bytes) for deterministic key generation. "
            "The same seed always produces the same key material."
        ),
    )
    parser.add_argument(
        "--seed-file",
        "--seed_file",
        dest="seed_file",
        type=str,
        default=None,
        help="Path to a binary file containing exactly 64 bytes used as seed for deterministic key generation.",
    )

    args = parser.parse_args()

    try:
        validate_preset_evalmode(args.preset, args.eval_mode)
    except ValueError as e:
        parser.error(str(e))

    outdir = args.key_path + "/" + args.key_id if args.key_id else args.key_path

    use_remote = args.key_store in {"aws", "gcp"}
    if use_remote:
        if not args.key_id:
            parser.error("--key-store aws or gcp requires --key_id to be specified.")
        if args.key_store == "aws" and (not args.region_name or not args.bucket_name):
            parser.error("--key-store aws requires --region-name and --bucket-name.")
        if args.key_store == "gcp" and not args.bucket_name:
            parser.error("--key-store gcp requires --bucket-name.")
        if args.seal_mode != "none":
            parser.error("--key-store aws or gcp does not support sealed key generation.")
        if args.seal_key_path or args.seal_key_stdin:
            parser.error("--seal_key_path and --seal_key_stdin are not supported when using --key-store aws or gcp.")
    else:
        ensure_dir_empty(outdir)

    seed = load_seed(args, parser)

    if use_remote:
        key_dict = generate_key_stream(
            args.dim,
            None,
            args.preset,
            args.eval_mode,
            args.metadata_encryption,
            args.key_id,
            seed=seed,
        )
        if args.key_store == "aws":
            upload_keys_to_aws(key_dict, args.key_id, args.region_name, args.bucket_name, args.secret_prefix)
        else:
            upload_keys_to_gcp(key_dict, args.key_id, args.bucket_name, args.secret_prefix)
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
            seed=seed,
        )


if __name__ == "__main__":
    main()
