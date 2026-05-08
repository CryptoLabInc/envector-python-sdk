#!/bin/bash
# test_setup_python_venv.sh - Regression tests for setup_python_venv.sh
#
# Usage: bash scripts/test_setup_python_venv.sh
#
# Tests:
# 1. Script finds Python without pyenv
# 2. Virtual environment is created correctly
# 3. Python version in venv is correct
# 4. pip works in venv
#
# Exit codes:
# 0 - All tests passed
# 1 - One or more tests failed

set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
TEST_VENV_DIR=$(mktemp -d)
FAILED=0

cleanup() {
    rm -rf "$TEST_VENV_DIR"
}
trap cleanup EXIT

log_test() {
    echo ""
    echo "========================================"
    echo "TEST: $1"
    echo "========================================"
}

pass() {
    echo "PASS: $1"
}

fail() {
    echo "FAIL: $1"
    FAILED=1
}

# Test 1: Script exists and is executable
log_test "Script exists and is executable"
if [[ -x "$SCRIPT_DIR/setup_python_venv.sh" ]]; then
    pass "setup_python_venv.sh is executable"
else
    fail "setup_python_venv.sh is not executable"
fi

# Test 2: Script can find Python without pyenv
log_test "Script finds Python without pyenv"

# Temporarily hide pyenv if it exists
ORIGINAL_PATH="$PATH"
export PATH="$(echo "$PATH" | tr ':' '\n' | grep -v pyenv | tr '\n' ':' | sed 's/:$//')"

(
    cd "$TEST_VENV_DIR"
    export VENV_DIR="$TEST_VENV_DIR/test_venv"
    export VERBOSE="true"

    # Source the script
    if source "$SCRIPT_DIR/setup_python_venv.sh" 2>&1; then
        if [[ -d "$VENV_DIR" ]]; then
            pass "Virtual environment created at $VENV_DIR"
        else
            fail "Virtual environment not created"
        fi
    else
        fail "Script failed to execute"
    fi
)

export PATH="$ORIGINAL_PATH"

# Test 3: Python version in venv
log_test "Python version in venv"
VENV_PYTHON="$TEST_VENV_DIR/test_venv/bin/python"
if [[ -x "$VENV_PYTHON" ]]; then
    VERSION=$("$VENV_PYTHON" --version 2>&1)
    echo "Python version: $VERSION"
    if [[ "$VERSION" == *"3."* ]]; then
        pass "Python 3.x found in venv"
    else
        fail "Unexpected Python version: $VERSION"
    fi
else
    fail "Python not found in venv"
fi

# Test 4: pip works in venv
log_test "pip works in venv"
VENV_PIP="$TEST_VENV_DIR/test_venv/bin/pip"
if [[ -x "$VENV_PIP" ]]; then
    if "$VENV_PIP" --version &>/dev/null; then
        pass "pip works in venv"
    else
        fail "pip failed to run"
    fi
else
    fail "pip not found in venv"
fi

# Test 5: Can install a package
log_test "Can install a package in venv"
if "$VENV_PIP" install --quiet six; then
    if "$VENV_PYTHON" -c "import six; print(six.__version__)" &>/dev/null; then
        pass "Package installation works"
    else
        fail "Package import failed after install"
    fi
else
    fail "pip install failed"
fi

# Test 6: Script is idempotent (can run again on existing venv)
log_test "Script is idempotent"
(
    cd "$TEST_VENV_DIR"
    export VENV_DIR="$TEST_VENV_DIR/test_venv"
    export VERBOSE="true"

    if source "$SCRIPT_DIR/setup_python_venv.sh" 2>&1; then
        pass "Script ran successfully on existing venv"
    else
        fail "Script failed on existing venv"
    fi
)

# Test 7: Custom venv directory via argument
log_test "Custom venv directory via argument"
CUSTOM_VENV="$TEST_VENV_DIR/custom_venv"
(
    cd "$TEST_VENV_DIR"
    export VERBOSE="true"

    if source "$SCRIPT_DIR/setup_python_venv.sh" --venv-dir "$CUSTOM_VENV" 2>&1; then
        if [[ -d "$CUSTOM_VENV" ]]; then
            pass "Custom venv directory created"
        else
            fail "Custom venv directory not created"
        fi
    else
        fail "Script failed with custom venv directory"
    fi
)

# Summary
echo ""
echo "========================================"
echo "TEST SUMMARY"
echo "========================================"
if [[ $FAILED -eq 0 ]]; then
    echo "All tests PASSED"
    exit 0
else
    echo "Some tests FAILED"
    exit 1
fi
