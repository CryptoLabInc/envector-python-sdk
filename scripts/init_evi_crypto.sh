#!/usr/bin/env bash

set -euo pipefail

# Get the absolute path of the script's directory
ROOT_DIR="$(dirname "$(realpath "$0")")/.."
PROJECT_ROOT="$(realpath "$ROOT_DIR")"

# Ensure the script is executed within a Git repository
if ! git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: $PROJECT_ROOT is not a Git repository."
    exit 1
fi

# Initialize variables
EVI_CRYPTO_COMMIT=""

print_usage() {
    cat <<EOF
Usage: $(basename "$0") [--evi-crypto-commit <sha|branch|tag>] | [<sha|branch|tag>]

Examples:
  $(basename "$0")
  $(basename "$0") --evi-crypto-commit main
  $(basename "$0") v1.2.3
EOF
}

# Parse input arguments (accepts named flag or positional value)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        --evi-crypto-commit)
            # Handle missing/empty value safely
            if [[ $# -gt 1 && -n "${2:-}" && "${2:0:2}" != "--" ]]; then
                EVI_CRYPTO_COMMIT="$2"
                shift 2
            else
                # value omitted; treat as not provided
                shift 1
            fi
            ;;
        --*)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
        *)
            # positional commit value (only if not already set)
            if [[ -z "$EVI_CRYPTO_COMMIT" ]]; then
                EVI_CRYPTO_COMMIT="$1"
                shift 1
            else
                echo "Unexpected extra argument: $1"
                print_usage
                exit 1
            fi
            ;;
    esac
done

# Initialize and update submodules
update_submodules() {
    cd "$PROJECT_ROOT"
    echo "Initializing and updating submodules..."

    # Keep existing submodule config (avoid wiping token-based URLs set by CI)
    git submodule sync --recursive

    # Initialize + update all submodules
    git submodule update --init --force --recursive || { echo "Failed to update submodules"; exit 1; }

    # Checkout specific commits if provided
    if [[ -n "$EVI_CRYPTO_COMMIT" ]]; then
        echo "Checking out provided EVI_CRYPTO_COMMIT: $EVI_CRYPTO_COMMIT"
        (
          cd external/evi-crypto
          # Ensure the desired commit is available: fetch all branches/tags with full history
          git fetch origin "+refs/heads/*:refs/remotes/origin/*" "+refs/tags/*:refs/tags/*" --prune || true

          checkout_evi_crypto_commit() {
              local target="$1"

              # Try an ordinary checkout first (covers existing branches, tags, SHAs, etc.)
              if git checkout "$target"; then
                  return 0
              fi

              # If only a remote branch exists, create/update a local tracking branch from origin
              if git rev-parse --verify --quiet "refs/remotes/origin/$target" >/dev/null 2>&1; then
                  git checkout -B "$target" "origin/$target"
                  return 0
              fi

              # Allow tags that only exist as refs/tags/<name>
              if git rev-parse --verify --quiet "refs/tags/$target" >/dev/null 2>&1; then
                  git checkout "refs/tags/$target"
                  return 0
              fi

              echo "Error: could not find commit/branch/tag '$target' in external/evi-crypto" >&2
              return 1
          }

          checkout_evi_crypto_commit "$EVI_CRYPTO_COMMIT"
        )
    fi
    echo "✅ Submodules initialized and updated successfully."
}

update_submodules
