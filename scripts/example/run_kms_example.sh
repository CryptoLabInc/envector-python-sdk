#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/example_runner.sh"

parse_common_args "$@"
install_example_deps

if [[ -z "${KMS_INTEGRATION_ADDR:-}" ]]; then
    echo "Skipping KMS examples (set KMS_INTEGRATION_ADDR to enable)."
    exit 0
fi

key_label="kms"
if [[ "$BAO" == true ]]; then
    key_label="kms-bao"
fi

kms_sdk_args=(
    --port "$PORT"
    --key-id "${KMS_SDK_KEY_ID:-${key_label}-sdk-${EVAL_MODE}-${PRESET}}"
    --eval-mode "$EVAL_MODE"
    --preset "$PRESET"
)
run_python_example "client_and_server/kms/kms_sdk_e2e.py" "${kms_sdk_args[@]}"

kms_msa_args=(
    --host "$HOST"
    --port "$PORT"
    --key-id "${KMS_MSA_KEY_ID:-${key_label}-${EVAL_MODE}-${PRESET}}"
    --eval-mode "$EVAL_MODE"
    --preset "$PRESET"
)
if [[ -n "$ACCESS_TOKEN" ]]; then
    kms_msa_args+=(--access-token "$ACCESS_TOKEN")
fi
if [[ "$SECURE" == true ]]; then
    kms_msa_args+=(--secure)
fi
run_python_example "client_and_server/kms/kms_sdk_msa_e2e.py" "${kms_msa_args[@]}"

echo "KMS examples completed successfully."
