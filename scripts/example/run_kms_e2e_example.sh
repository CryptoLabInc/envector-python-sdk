#!/bin/bash
# Run the KMS <-> SDK <-> MSA example against a live deployment.
#
# Usage:
#   bash scripts/example/run_kms_e2e_example.sh \
#     --port <MSA_GRPC_PORT> \
#     [--kms-addr <KMS_GRPC_ADDR>]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE="$ROOT_DIR/example/client_and_server/e2e/kms_sdk_msa_e2e.py"

MSA_PORT=50050
KMS_ADDR="localhost:50100"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port)
            MSA_PORT="$2"
            shift 2
            ;;
        --kms-addr)
            KMS_ADDR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

pip install --quiet scikit-learn pandas

echo "Running KMS + SDK + MSA e2e example..."
echo "  MSA:          localhost:$MSA_PORT"
echo "  KMS gRPC:     $KMS_ADDR"
echo

python "$EXAMPLE" \
    --msa-address "localhost:$MSA_PORT" \
    --kms-address "$KMS_ADDR"

exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "KMS e2e example FAILED (exit code $exit_code)"
    exit $exit_code
fi
echo "KMS + SDK + MSA e2e example PASSED"
