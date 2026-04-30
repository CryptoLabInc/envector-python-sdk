#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example/client_and_server/e2e"
PORT=50050  # Default port

SKIP_FILES=()
if [[ -z "${KMS_INTEGRATION_ADDR:-}" ]]; then
    SKIP_FILES+=("kms_sdk_e2e.py" "kms_sdk_msa_e2e.py")
fi

should_skip() {
    local rel_path="$1"
    local pattern
    for pattern in "${SKIP_FILES[@]-}"; do
        case "$rel_path" in
            $pattern) return 0 ;;
        esac
    done
    return 1
}

# Ensure scikit-learn is installed
pip install --quiet scikit-learn pandas

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find all Python files in the e2e directory, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "_*.py" ! -name "utils.py" | sort)

if [[ -z "$python_files" ]]; then
    echo "No example files found in $EXAMPLE_DIR"
    exit 0
fi
# Run init_and_reset.py (or init.py) if present in client_and_server
init_file=$(find "$ROOT_DIR/example/client_and_server" -name "init_and_reset.py" | head -n 1)
if [[ -z "$init_file" ]]; then
    init_file=$(find "$ROOT_DIR/example/client_and_server" -name "init.py" | head -n 1)
fi
if [[ -n "$init_file" ]]; then
    relative_path="${init_file#$ROOT_DIR/example/}"
    echo "Running $relative_path..."
    python "$init_file" --port "$PORT"
    if [ $? -ne 0 ]; then
        echo "Error running $relative_path"
        exit 1
    fi
    echo
fi
# Execute Python files
for py_file in $python_files; do
    relative_path="${py_file#$EXAMPLE_DIR/}"
    if should_skip "$relative_path"; then
        echo "Skipping e2e/$relative_path..."
        continue
    fi
    # e2e.py: run across all four eval modes. The preset is implied by the
    # mode (mm / mms → IP1, mm32 / mms32 → IP2) via the mode_to_preset
    # table inside e2e.py, so passing --preset separately is redundant
    # (and a (mode, preset) mismatch just logs a warning and uses the
    # mode's implied preset anyway).
    if [[ "$relative_path" == "e2e.py" ]]; then
        for mode in mm mms mm32 mms32; do
            echo "Running e2e/$relative_path --eval-mode $mode..."
            python "$py_file" --port "$PORT" --eval-mode "$mode"
            if [ $? -ne 0 ]; then
                echo "Error running e2e/$relative_path --eval-mode $mode"
                exit 1
            fi
            echo
        done
        continue
    fi
    echo "Running e2e/$relative_path..."
    python "$py_file" --port "$PORT"
    if [ $? -ne 0 ]; then
        echo "Error running e2e/$relative_path"
        exit 1
    fi
    echo
done
