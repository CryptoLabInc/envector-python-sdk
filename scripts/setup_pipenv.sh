#!/usr/bin/env bash

# ==============================================================================
# Pipenv Virtual Environment Setup Script
# Usage: ./setup_venv.sh [PYTHON_VERSION]
# ===============================================================================

set -e

# Get Python version from input or default to 3.12
PYTHON_VERSION=${1:-3.12}

# Set pipenv to create the .venv folder inside the project directory.
export PIPENV_VENV_IN_PROJECT=1

# Informational message
echo "Setting up Pipenv virtual environment and installing dependencies..."

# Initialize pipenv with the specified Python version.
pipenv --python $PYTHON_VERSION

# Install all packages (including dev packages) specified in the Pipfile.
pipenv install --dev --skip-lock

echo "Virtual environment setup and package installation complete."
