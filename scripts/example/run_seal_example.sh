#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/example_runner.sh"

EXAMPLE_DIR="client_and_server/crypto/seal"

parse_common_args "$@"
KEY_ID="${KEY_ID:-seal-${EVAL_MODE}-${PRESET}}"
install_example_deps
ensure_aes_kek
reset_server

run_server_examples_in_dirs "$EXAMPLE_DIR" -- \
    --key-id "$KEY_ID" \
    --eval-mode "$EVAL_MODE" \
    --preset "$PRESET"

echo "Sealing examples completed successfully."
