#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example/client_and_server/basic"
PORT=50050  # Default port

# Skip examples that rely on cipher query encryption because MM mode does not support encrypted-query search.
SKIP_FILES=(
    "search_with_encrypted_query.py"
    "load_unload.py"
)

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

# Find all Python files in the basic directory, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "utils.py" | sort)

if [[ -z "$python_files" ]]; then
    echo "No example files found in $EXAMPLE_DIR"
    exit 0
fi

# Ensure init_and_reset.py (or init.py) runs first if it exists
init_file=$(find "$EXAMPLE_DIR" -name "init_and_reset.py" | head -n 1)
if [[ -z "$init_file" ]]; then
    init_file=$(find "$EXAMPLE_DIR" -name "init.py" | head -n 1)
fi
if [[ -n "$init_file" ]]; then
    relative_path="${init_file#$EXAMPLE_DIR/}"
    if should_skip "$relative_path"; then
        echo "Skipping basic/$relative_path..."
    else
        echo "Running basic/$relative_path..."
        python "$init_file" --port "$PORT"
        if [ $? -ne 0 ]; then
            echo "Error running basic/$relative_path"
            exit 1
        fi
        echo
    fi
    # Remove init file from the list to avoid running it again
    python_files=$(echo "$python_files" | grep -v "$init_file")
fi

# Execute remaining Python files
for py_file in $python_files; do
    relative_path="${py_file#$EXAMPLE_DIR/}"
    if should_skip "$relative_path"; then
        echo "Skipping basic/$relative_path..."
        continue
    fi
    echo "Running basic/$relative_path..."
    python "$py_file" --port "$PORT"
    if [ $? -ne 0 ]; then
        echo "Error running basic/$relative_path"
        exit 1
    fi
    echo
done
