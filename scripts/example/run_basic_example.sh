#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/example_runner.sh"

EXAMPLE_DIRS=(
    "client_and_server/basic"
    "client_and_server/crypto/no_seal"
)

parse_common_args "$@"
KEY_ID="${KEY_ID:-${EVAL_MODE}-${PRESET}}"
install_example_deps
reset_server

run_server_examples_in_dirs "${EXAMPLE_DIRS[@]}" -- \
    --key-id "$KEY_ID" \
    --eval-mode "$EVAL_MODE" \
    --preset "$PRESET"

echo "Basic examples completed successfully."
