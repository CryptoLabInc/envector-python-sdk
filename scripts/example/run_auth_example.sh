#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/example/client_and_server/auth"
PORT=50050
HOST="localhost"
ACCESS_TOKEN="${ACCESS_TOKEN:-}"
SECURE=false

SKIP_FILES=("refresh_token.py")

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

run_auth_example() {
    local py_file="$1"
    local cmd=(python "$py_file" --host "$HOST" --port "$PORT")

    if [[ -n "$ACCESS_TOKEN" ]]; then
        cmd+=(--access-token "$ACCESS_TOKEN")
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

# Find all Python files in the auth directory, excluding utils.py
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
    cmd=(python "$init_file" --host "$HOST" --port "$PORT")
    if [[ -n "$ACCESS_TOKEN" ]]; then
        cmd+=(--access-token "$ACCESS_TOKEN")
    fi
    if [[ "$SECURE" == true ]]; then
        cmd+=(--secure)
    fi
    "${cmd[@]}"
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
        echo "Skipping auth/$relative_path..."
        continue
    fi
    echo "Running auth/$relative_path..."
    run_auth_example "$py_file"
    if [ $? -ne 0 ]; then
        echo "Error running auth/$relative_path"
        exit 1
    fi
    echo
done

# Refresh-token example: requires OIDC config + refresh token files.
# Only runs when REFRESH_TOKEN_CLIENT_ID and one of TOKEN_ENDPOINT / OIDC_ISSUER are provided.
refresh_example="$EXAMPLE_DIR/refresh_token.py"
if [[ -f "$refresh_example" && -n "${REFRESH_TOKEN_CLIENT_ID:-}" \
      && ( -n "${REFRESH_TOKEN_TOKEN_ENDPOINT:-}" || -n "${REFRESH_TOKEN_OIDC_ISSUER:-}" ) ]]; then
    echo "Running auth/refresh_token.py..."
    cmd=(python "$refresh_example" --host "$HOST" --port "$PORT" --client-id "$REFRESH_TOKEN_CLIENT_ID")
    if [[ -n "${REFRESH_TOKEN_TOKEN_ENDPOINT:-}" ]]; then
        cmd+=(--token-endpoint "$REFRESH_TOKEN_TOKEN_ENDPOINT")
    fi
    if [[ -n "${REFRESH_TOKEN_OIDC_ISSUER:-}" ]]; then
        cmd+=(--oidc-issuer "$REFRESH_TOKEN_OIDC_ISSUER")
    fi
    if [[ -n "${REFRESH_TOKEN_CLIENT_SECRET:-}" ]]; then
        cmd+=(--client-secret "$REFRESH_TOKEN_CLIENT_SECRET")
    fi
    if [[ -n "${REFRESH_TOKEN_SCOPE:-}" ]]; then
        cmd+=(--scope "$REFRESH_TOKEN_SCOPE")
    fi
    if [[ -n "${REFRESH_TOKEN_FILE:-}" ]]; then
        cmd+=(--refresh-token-file "$REFRESH_TOKEN_FILE")
    fi
    if [[ -n "${OTHER_REFRESH_TOKEN_FILE:-}" ]]; then
        cmd+=(--other-refresh-token-file "$OTHER_REFRESH_TOKEN_FILE")
    fi
    if [[ "$SECURE" == true ]]; then
        cmd+=(--secure)
    fi
    "${cmd[@]}"
    if [ $? -ne 0 ]; then
        echo "Error running auth/refresh_token.py"
        exit 1
    fi
    echo
else
    echo "Skipping auth/refresh_token.py (set REFRESH_TOKEN_CLIENT_ID and REFRESH_TOKEN_TOKEN_ENDPOINT or REFRESH_TOKEN_OIDC_ISSUER to enable)"
fi
