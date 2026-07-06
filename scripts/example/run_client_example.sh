#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/example_runner.sh"

EXAMPLE_DIRS=(
    "client_only"
)

parse_common_args "$@"
KEY_ID="${KEY_ID:-${EVAL_MODE}-${PRESET}}"
install_example_deps
ensure_aes_kek

run_python_examples_in_dirs "${EXAMPLE_DIRS[@]}" -- \
    --key-id "$KEY_ID" \
    --eval-mode "$EVAL_MODE" \
    --preset "$PRESET"

echo "Client-only examples completed successfully."
