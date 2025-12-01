#!/bin/bash

# Run only the examples under example/client_only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example/client_only"

# Resolve Python interpreter (prefer python, fallback to python3)
PYTHON_BIN=${PYTHON_BIN:-python}
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN=python3
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "No Python interpreter found (python or python3)."
    exit 127
fi

# Ensure a default AES KEK exists for AES-sealed examples
AES_KEK_PATH="$ROOT_DIR/aes.kek"
if [[ ! -f "$AES_KEK_PATH" ]]; then
    echo "01234567890123456789012345678901" > "$AES_KEK_PATH"
fi

# Parse arguments (kept for future extension)
while [[ "$#" -gt 0 ]]; do
    case $1 in
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find all Python files in client_only, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "utils.py" | sort)

if [[ -z "$python_files" ]]; then
    echo "No example files found in $EXAMPLE_DIR"
    exit 0
fi

# Execute each Python example
for py_file in $python_files; do
    relative_path="${py_file#$ROOT_DIR/}"
    echo "Running $relative_path..."
    PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}" "$PYTHON_BIN" "$py_file"
    status=$?
    if [ $status -ne 0 ]; then
        echo "Error running $relative_path (exit $status)"
        exit $status
    fi
    echo
done

echo "All client_only examples completed successfully."
