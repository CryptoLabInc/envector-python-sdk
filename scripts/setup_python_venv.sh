#!/bin/bash
# setup_python_venv.sh - Portable Python venv setup for CI/CD environments
#
# Usage: source scripts/setup_python_venv.sh [--venv-dir DIR] [--python-version VER]
#
# This script:
# 1. Finds the correct Python binary (from actions/setup-python or system)
# 2. Creates a virtual environment without relying on pyenv
# 3. Activates the venv and exports PYTHON_VENV_DIR
#
# Designed to work on:
# - GitHub Actions runners (with actions/setup-python)
# - Self-hosted runners (with or without pyenv)
# - Local development machines

set -euo pipefail

# Default values
VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
VERBOSE="${VERBOSE:-false}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --venv-dir)
            VENV_DIR="$2"
            shift 2
            ;;
        --python-version)
            PYTHON_VERSION="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

log() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo "[setup_python_venv] $*" >&2
    fi
}

log_always() {
    echo "[setup_python_venv] $*" >&2
}

# Find Python binary
find_python() {
    local python_bin=""

    # Priority 1: Python from actions/setup-python (GitHub Actions)
    # This is usually in PATH and pythonLocation env var
    if [[ -n "${pythonLocation:-}" ]]; then
        local candidate="${pythonLocation}/bin/python"
        if [[ -x "$candidate" ]]; then
            log "Found Python from actions/setup-python: $candidate"
            echo "$candidate"
            return 0
        fi
    fi

    # Priority 2: Python{version} in PATH (e.g., python3.12)
    local versioned_python="python${PYTHON_VERSION}"
    if command -v "$versioned_python" &>/dev/null; then
        python_bin=$(command -v "$versioned_python")
        log "Found versioned Python: $python_bin"
        echo "$python_bin"
        return 0
    fi

    # Priority 3: python3 in PATH
    if command -v python3 &>/dev/null; then
        python_bin=$(command -v python3)
        # Verify it's not a broken binary
        if "$python_bin" --version &>/dev/null; then
            log "Found python3: $python_bin"
            echo "$python_bin"
            return 0
        else
            log "python3 found but broken, skipping: $python_bin"
        fi
    fi

    # Priority 4: pyenv if available
    if command -v pyenv &>/dev/null; then
        local pyenv_root
        pyenv_root=$(pyenv root 2>/dev/null || true)
        if [[ -n "$pyenv_root" ]]; then
            local pyenv_python="${pyenv_root}/shims/python"
            if [[ -x "$pyenv_python" ]] && "$pyenv_python" --version &>/dev/null; then
                log "Found Python via pyenv: $pyenv_python"
                echo "$pyenv_python"
                return 0
            fi
        fi
    fi

    # Priority 5: python in PATH
    if command -v python &>/dev/null; then
        python_bin=$(command -v python)
        if "$python_bin" --version &>/dev/null; then
            log "Found python: $python_bin"
            echo "$python_bin"
            return 0
        fi
    fi

    return 1
}

# Verify Python version
verify_python_version() {
    local python_bin="$1"
    local version_output
    version_output=$("$python_bin" --version 2>&1)

    if [[ "$version_output" == *"$PYTHON_VERSION"* ]]; then
        log "Python version verified: $version_output"
        return 0
    else
        log "Python version mismatch: expected $PYTHON_VERSION, got $version_output"
        # Don't fail, just warn - the Python might still work
        return 0
    fi
}

# Main setup logic
setup_venv() {
    log_always "Setting up Python virtual environment..."

    # Find Python
    local python_bin
    if ! python_bin=$(find_python); then
        echo "ERROR: Could not find a working Python installation" >&2
        exit 1
    fi

    log_always "Using Python: $python_bin ($($python_bin --version 2>&1))"

    # Verify version (warning only)
    verify_python_version "$python_bin"

    # Create venv if it doesn't exist
    if [[ ! -d "$VENV_DIR" ]]; then
        log_always "Creating virtual environment at $VENV_DIR..."
        "$python_bin" -m venv "$VENV_DIR"
    else
        log_always "Virtual environment already exists at $VENV_DIR"
    fi

    # Activate venv
    log_always "Activating virtual environment..."
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    log "Upgrading pip..."
    pip install --upgrade pip --quiet

    # Export for other scripts
    export PYTHON_VENV_DIR="$VENV_DIR"
    export PYTHON_VENV_ACTIVE="true"

    log_always "Virtual environment ready: $VENV_DIR"
    log_always "Python in venv: $(which python) ($(python --version 2>&1))"
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    setup_venv
    echo ""
    echo "To activate this environment in your shell, run:"
    echo "  source $VENV_DIR/bin/activate"
else
    # When sourced, run setup and keep venv active
    setup_venv
fi
