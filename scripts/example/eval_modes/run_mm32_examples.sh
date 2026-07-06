#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/example_runner.sh"

parse_common_args "$@"
install_example_deps

for mode in mm32; do
    case "$mode" in
        mm | mms)
            mode_preset="ip1"
            ;;
        mm32 | mms32)
            mode_preset="ip3"
            ;;
    esac
    mode_key_id="test-key-$mode-$mode_preset"

    reset_server
    run_server_example "client_and_server/e2e/e2e.py" --key-id "$mode_key_id" --eval-mode "$mode"
done

echo "Eval mode examples completed successfully."
