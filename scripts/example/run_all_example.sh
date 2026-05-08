#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example"
PORT=50050  # Default port
HOST="localhost"
ACCESS_TOKEN="${ACCESS_TOKEN:-}"
SECURE=false

ALLOW_FILES=()
SKIP_FILES=(
    "client_and_server/auth/*"
)

should_skip() {
    local rel_path="$1"
    local pattern
    for pattern in "${ALLOW_FILES[@]}"; do
        case "$rel_path" in
            $pattern) return 1 ;;
        esac
    done
    for pattern in "${SKIP_FILES[@]-}"; do
        case "$rel_path" in
            $pattern) return 0 ;;
        esac
    done
    return 1
}

run_example() {
    local py_file="$1"
    local cmd=(python "$py_file")

    if [[ "$py_file" == *"/client_and_server/"* ]]; then
        cmd+=(--host "$HOST" --port "$PORT")
        if [[ "$py_file" == *"/client_and_server/auth/"* ]]; then
            if [[ -n "$ACCESS_TOKEN" ]]; then
                cmd+=(--access-token "$ACCESS_TOKEN")
            fi
            if [[ "$SECURE" == true ]]; then
                cmd+=(--secure)
            fi
        fi
    fi

    "${cmd[@]}"
}

# Ensure scikit-learn is installed
pip install --quiet scikit-learn pandas

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --access-token)
            ACCESS_TOKEN="$2"
            shift 2
            ;;
        --secure)
            SECURE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find all Python files in the example directory, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "utils.py" | sort)

# Ensure init_and_reset.py (or init.py) runs first if it exists
init_file=$(find "$EXAMPLE_DIR/client_and_server" -name "init_and_reset.py" | head -n 1)
if [[ -z "$init_file" ]]; then
    init_file=$(find "$EXAMPLE_DIR/client_and_server" -name "init.py" | head -n 1)
fi
if [[ -n "$init_file" ]]; then
    relative_path="${init_file#$EXAMPLE_DIR/}"
    if should_skip "$relative_path"; then
        echo "Skipping $relative_path..."
    else
        echo "Running $relative_path..."
        run_example "$init_file"
        if [ $? -ne 0 ]; then
            echo "Error running $relative_path"
            exit 1
        fi
        echo
    fi
    # Remove init.py from the list to avoid running it again
    python_files=$(echo "$python_files" | grep -v "$init_file")
fi

# Execute remaining Python files
for py_file in $python_files; do
    relative_path="${py_file#$EXAMPLE_DIR/}"
    if should_skip "$relative_path"; then
        echo "Skipping $relative_path..."
        continue
    fi
    echo "Running $relative_path..."
    run_example "$py_file"
    if [ $? -ne 0 ]; then
        echo "Error running $relative_path"
        exit 1
    fi
    echo
done
