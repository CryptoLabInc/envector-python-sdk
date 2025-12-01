#!/usr/bin/env bash

# ==============================================================================
# Build All macOS Combinations Script
#
# This script builds wheel files for all combinations of:
# - Apple Silicon supported macOS versions (11.0, 12.0, 13.0, 14.0)
# - Python versions (3.9, 3.10, 3.11, 3.12, 3.13)
#
# Usage: ./build_all_combinations_mac.sh [--clean] [--parallel]
# ==============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

function msg() { echo -e "${BLUE}INFO:${NC} $1"; }
function success() { echo -e "${GREEN}SUCCESS:${NC} $1"; }
function warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
function error() { echo -e "${RED}ERROR:${NC} $1"; }

# Configuration
MACOS_VERSIONS=("11.0")
PYTHON_VERSIONS=("3.9" "3.10" "3.11" "3.12" "3.13")
OUTPUT_DIR="dist"
CLEAN_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--clean]"
            echo "Builds wheel files for all macOS/Python combinations"
            echo ""
            echo "Options:"
            echo "  --clean     Clean previous builds before starting"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check platform
if [[ "$(uname)" != "Darwin" ]]; then
    error "This script is designed for macOS only"
    exit 1
fi

if [[ "$(uname -m)" != "arm64" ]]; then
    warn "This script is designed for Apple Silicon Macs"
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Setup
msg "Setting up build environment..."
mkdir -p "$OUTPUT_DIR"

# Clean if requested
if [[ "$CLEAN_MODE" == "true" ]]; then
    msg "Cleaning previous builds..."
    rm -rf .venv dist
    if [ -f "$SCRIPT_DIR/clean_proto.sh" ]; then
        bash "$SCRIPT_DIR/clean_proto.sh"
    fi
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# If CIBW_BUILD is provided (e.g., from CI), derive Python versions from it.
# Accept tokens like: cp312-* cp311-* cp310-* cp39-*
if [[ -n "${CIBW_BUILD:-}" ]]; then
    msg "CIBW_BUILD detected: '${CIBW_BUILD}'. Deriving Python versions for macOS build."
    derived_versions=()
    for tok in $CIBW_BUILD; do
        if [[ "$tok" =~ ^cp([0-9]{2,3}) ]]; then
            digits="${BASH_REMATCH[1]}"
            if [[ ${#digits} -eq 2 ]]; then
                # e.g., cp39 -> 3.9
                py_ver="3.${digits:1:1}"
            else
                # e.g., cp310 -> 3.10, cp311 -> 3.11
                py_ver="3.${digits:1:2}"
            fi
            # deduplicate
            already=false
            for v in "${derived_versions[@]}"; do
                if [[ "$v" == "$py_ver" ]]; then already=true; break; fi
            done
            if [[ "$already" == false ]]; then
                derived_versions+=("$py_ver")
            fi
        fi
    done
    if [[ ${#derived_versions[@]} -gt 0 ]]; then
        PYTHON_VERSIONS=("${derived_versions[@]}")
        msg "Using Python versions derived from CIBW_BUILD: ${PYTHON_VERSIONS[*]}"
    else
        warn "CIBW_BUILD provided but no cpXY tokens parsed. Falling back to default Python versions: ${PYTHON_VERSIONS[*]}"
    fi
fi

# Build all combinations
total_combinations=$((${#MACOS_VERSIONS[@]} * ${#PYTHON_VERSIONS[@]}))
current=0

msg "Starting build of $total_combinations combinations..."

for macos_version in "${MACOS_VERSIONS[@]}"; do
    for python_version in "${PYTHON_VERSIONS[@]}"; do
        current=$((current + 1))
        msg "Progress: $current/$total_combinations - Python $python_version, macOS $macos_version"

        # Clean previous build artifacts (keep dist for all combinations)
        rm -rf .venv

        # Run setup script
        if "$SCRIPT_DIR/setup.sh" --python "$python_version" --type wheel --macosx-target "$macos_version"; then
            # Wheel files are already in dist directory, no need to copy
            if [ -d "dist" ]; then
                for wheel_file in dist/*.whl; do
                    if [ -f "$wheel_file" ]; then
                        success "Built: $(basename "$wheel_file")"
                    fi
                done
            fi
        else
            error "Failed to build Python $python_version, macOS $macos_version"
        fi

        echo "" # Empty line for readability
    done
done

# Generate summary
msg "Generating build summary..."
{
    echo "pyenvector macOS Build Summary"
    echo "======================="
    echo "Build Date: $(date)"
    echo "Platform: $(uname -s) $(uname -m)"
    echo ""
    # Git commit info
    if git -C "$PROJECT_DIR" rev-parse --git-dir > /dev/null 2>&1; then
        echo "Git Commit: $(git -C "$PROJECT_DIR" rev-parse HEAD)"
        echo "Git Commit (short): $(git -C "$PROJECT_DIR" log -1 --pretty=format:'%h %s')"
    else
        echo "Git Commit: (not a git repository)"
    fi
    echo ""
    echo "Build Combinations:"
    echo "  macOS versions: ${MACOS_VERSIONS[*]}"
    echo "  Python versions: ${PYTHON_VERSIONS[*]}"
    echo "  Total combinations: $total_combinations"
    echo ""
    echo "Generated Wheel Files:"
    echo "======================"

    if [ -d "$OUTPUT_DIR" ]; then
        if ls "$OUTPUT_DIR"/*.whl >/dev/null 2>&1; then
            ls -la "$OUTPUT_DIR"/*.whl | awk '{print "  " $9}'
        else
            echo "  No wheel files found"
        fi
    fi

    echo ""
    echo "Installation Instructions:"
    echo "========================="
    echo "All wheel files are in the dist directory. Install the appropriate one:"
    echo "  pip install dist/<wheel_file>"
    echo ""
    echo "Example:"
    echo "  pip install dist/pyenvector-1.0.0-cp39-cp39-macosx_11_0_arm64.whl"
} > "$OUTPUT_DIR/build_summary.txt"

success "Build process completed!"
msg "Check the $OUTPUT_DIR directory for all generated wheel files"
msg "See $OUTPUT_DIR/build_summary.txt for detailed information"
