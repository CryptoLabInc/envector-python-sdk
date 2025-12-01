#!/usr/bin/env bash

# ==============================================================================
# Project Development Environment Setup Script
#
# This script performs the following tasks:
# 1. Clean up previous build artifacts and virtual environment
# 2. Check for required tools (pipenv, python3.11)
# 3. Set up the .env file
# 4. Create a Pipenv virtual environment and install dependencies
# 5. Generate Protobuf code and run additional scripts
#
# Usage: ./setup.sh
# ==============================================================================

# --- Script Configuration ---
# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# The return value of a pipeline is the status of the last command to exit
# with a non-zero status, or zero if no command exited with a non-zero status.
set -o pipefail

# --- Colors and Logging ---
# Define color variables for log messages.
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m' # No Color

# Function to print an informational message.
# Usage: msg "This is a message."
function msg() {
    echo -e "${COLOR_BLUE}INFO:${COLOR_NC} $1"
}

# Function to print a success message.
function success() {
    echo -e "${COLOR_GREEN}SUCCESS:${COLOR_NC} $1"
}

# Function to print a warning message.
function warn() {
    echo -e "${COLOR_YELLOW}WARN:${COLOR_NC} $1"
}


# --- Function Definitions ---

# 1. Function to check for required dependencies
function check_dependencies() {
    msg "Checking for required dependencies..."

    # Get Python version from input or default to 3.12
    PYTHON_VERSION=${1:-3.12}
    platform="$(uname)"
    CI_ARG=""
    if [[ -n "${CI:-}" ]]; then
        CI_ARG="--ci"
    fi
    if [[ "$platform" == "Linux" ]]; then
        echo "Detected Linux platform."
        echo "Running install_deps_linux.sh to set up dependencies..."
        . ./scripts/install_deps_linux.sh --python $PYTHON_VERSION $CI_ARG
    elif [[ "$platform" == "Darwin" ]]; then
        echo "Detected macOS platform."
        echo "Running install_deps_mac.sh to set up dependencies..."
        . ./scripts/install_deps_mac.sh --python $PYTHON_VERSION $CI_ARG
    else
        echo "Unsupported platform: $platform. Please run the setup script on Linux or macOS."
        exit 1
    fi

    success "All required dependencies are ready. Using Python $PYTHON_VERSION."
}

# 2. Function to clean up the previous state
function cleanup() {
    msg "Cleaning up previous build artifacts and virtual environment..."
    # If '.venv' directory exists, remove it.
    if [ -d ".venv" ]; then
        rm -rf .venv
        msg "Removed '.venv' virtual environment directory."
    fi

    success "Cleanup complete."
}

# 4. Function to set up virtual environment and install dependencies
function setup_pipenv() {
    msg "Setting up Pipenv virtual environment and installing dependencies..."
    PYTHON_VERSION=${1:-3.12}
    ./scripts/setup_pipenv.sh $PYTHON_VERSION
    success "Virtual environment setup and package installation complete."
}

# 5. Function to initialize and update submodules
function init_submodule() {
    msg "Initializing and updating submodules..."
    local EVI_CRYPTO_COMMIT=${1:-}
    if [[ -n "$EVI_CRYPTO_COMMIT" ]]; then
        ./scripts/init_evi_crypto.sh --evi-crypto-commit "$EVI_CRYPTO_COMMIT"
    else
        ./scripts/init_evi_crypto.sh
    fi
    success "Submodules initialized and updated."
}

# 6. Function to build the project and run additional scripts
function build_project() {
    local BUILD_TYPE=${1:-install}
    local MACOSX_TARGET=${2:-11.0}
    local SKIP_BUILD=${3:-false}
    msg "Starting project build..."
    if [[ "$SKIP_BUILD" == "true" ]]; then
        msg "--skip-build-evi set: Skipping build_and_install step."
        success "Project proto installation complete."
        return 0
    fi
    # Run the evi-crypto installation script inside the virtual environment.
    msg "Running the installation script..."

    pipenv run ./scripts/build_and_install.sh --type $BUILD_TYPE --macosx-target $MACOSX_TARGET

    success "Project build complete."
}


# --- Main Script Execution ---
function main() {
    msg "Starting project development environment setup."

    # Parse arguments
    PYTHON_VERSION=3.12  # Default Python version
    BUILD_TYPE=install   # Default build type
    MACOSX_TARGET=11.0   # Default macOS deployment target
    EVI_CRYPTO_COMMIT=""
    SKIP_BUILD_EVI_CRYPTO=false
    while [[ $# -gt 0 ]]; do
        case $1 in
            --python)
                PYTHON_VERSION=$2
                shift 2
                ;;
            --type)
                BUILD_TYPE=$2
                shift 2
                ;;
            --macosx-target)
                MACOSX_TARGET=$2
                shift 2
                ;;
            --evi-crypto-commit)
                if [[ $# -gt 1 && -n "$2" && "$2" != --* ]]; then
                    EVI_CRYPTO_COMMIT=$2
                    shift 2
                else
                    EVI_CRYPTO_COMMIT=""
                    shift 1
                fi
                ;;
            --skip-build-evi-crypto)
                SKIP_BUILD_EVI_CRYPTO=true
                shift 1
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_dependencies $PYTHON_VERSION
    cleanup
    init_submodule "$EVI_CRYPTO_COMMIT"
    setup_pipenv $PYTHON_VERSION
    build_project $BUILD_TYPE $MACOSX_TARGET $SKIP_BUILD_EVI_CRYPTO

    echo # Newline for spacing
    success "All setup steps completed successfully!"
    msg "To activate the virtual environment, run the following command:"
    echo -e "${COLOR_YELLOW}pipenv shell${COLOR_NC}"
}

# Call the main function to execute the script.
main "$@"
