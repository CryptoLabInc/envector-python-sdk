#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example/client_and_server/indexing"
PORT=50050  # Default port

SKIP_FILES=()

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

# Find all Python files in the indexing directory, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "utils.py" | sort)

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
        echo "Skipping indexing/$relative_path..."
        continue
    fi
    echo "Running indexing/$relative_path..."
    python "$py_file" --port "$PORT"
    if [ $? -ne 0 ]; then
        echo "Error running indexing/$relative_path"
        exit 1
    fi
    echo
done
