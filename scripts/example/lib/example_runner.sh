#!/bin/bash

set -euo pipefail

EXAMPLE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "$EXAMPLE_LIB_DIR/../../.." && pwd)"
EXAMPLE_ROOT="$SDK_ROOT/example"

HOST="localhost"
PORT=50050
ACCESS_TOKEN="${ACCESS_TOKEN:-}"
SECURE=false
BAO=false
KEY_ID=""
EVAL_MODE="mm32"
PRESET="ip3"

PYTHON_BIN=${PYTHON_BIN:-python}
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN=python3
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "No Python interpreter found (python or python3)."
    exit 127
fi

parse_common_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
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
            --bao)
                BAO=true
                shift
                ;;
            --key-id)
                KEY_ID="$2"
                shift 2
                ;;
            --eval-mode | --eval_mode)
                EVAL_MODE="$2"
                shift 2
                ;;
            --preset)
                PRESET="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

install_example_deps() {
    "$PYTHON_BIN" -m pip install --quiet scikit-learn pandas
}

ensure_aes_kek() {
    local aes_kek_path="$SDK_ROOT/aes.kek"
    if [[ ! -f "$aes_kek_path" ]]; then
        echo "01234567890123456789012345678901" > "$aes_kek_path"
    fi
}

run_python_example() {
    local rel_path="$1"
    shift
    local py_file="$EXAMPLE_ROOT/$rel_path"
    local args=("$@")

    if [[ "$rel_path" == client_and_server/* ]]; then
        local has_port=false
        local arg
        for arg in "${args[@]}"; do
            if [[ "$arg" == "--port" ]]; then
                has_port=true
                break
            fi
        done
        if [[ "$has_port" == false ]]; then
            args=(--port "$PORT" "${args[@]}")
        fi
    fi

    echo "Running $rel_path..."
    PYTHONPATH="$SDK_ROOT:${PYTHONPATH:-}" "$PYTHON_BIN" "$py_file" "${args[@]}"
    echo
}

run_server_example() {
    local rel_path="$1"
    shift
    run_python_example "$rel_path" --host "$HOST" --port "$PORT" "$@"
}

reset_server() {
    run_server_example "client_and_server/init/init_and_reset.py" --key-id "$KEY_ID"
}

run_python_examples_in_dirs() {
    local dirs=()
    local extra_args=()
    local parsing_dirs=true

    for arg in "$@"; do
        if [[ "$parsing_dirs" == true && "$arg" == "--" ]]; then
            parsing_dirs=false
        elif [[ "$parsing_dirs" == true ]]; then
            dirs+=("$arg")
        else
            extra_args+=("$arg")
        fi
    done

    for dir in "${dirs[@]}"; do
        for example_file in "$EXAMPLE_ROOT/$dir"/*.py; do
            [[ -e "$example_file" ]] || {
                echo "No example files found in $dir"
                exit 1
            }
            run_python_example "$dir/$(basename "$example_file")" "${extra_args[@]}"
        done
    done
}

run_server_examples_in_dirs() {
    local dirs=()
    local extra_args=()
    local parsing_dirs=true

    for arg in "$@"; do
        if [[ "$parsing_dirs" == true && "$arg" == "--" ]]; then
            parsing_dirs=false
        elif [[ "$parsing_dirs" == true ]]; then
            dirs+=("$arg")
        else
            extra_args+=("$arg")
        fi
    done

    for dir in "${dirs[@]}"; do
        for example_file in "$EXAMPLE_ROOT/$dir"/*.py; do
            [[ -e "$example_file" ]] || {
                echo "No example files found in $dir"
                exit 1
            }
            run_server_example "$dir/$(basename "$example_file")" "${extra_args[@]}"
        done
    done
}
