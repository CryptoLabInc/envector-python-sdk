#!/usr/bin/env bash

set -e

# Parse input arguments for Python version and CI flag
PYTHON_VERSION=3.12  # Default Python version
CI_FLAG=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --python)
      PYTHON_VERSION=$2
      shift 2
      ;;
    --ci)
      CI_FLAG="true"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "Detected Linux platform."

# Detect CI environment
if [[ -n "$CI_FLAG" || -n "${CI:-}" ]]; then
  echo "CI environment detected. Skipping pyenv and Python installation."
  PYTHON_BIN=python3
else
  # Install pyenv
  if [[ "$SHELL" =~ "zsh" ]]; then
    RC_FILE="$HOME/.zshrc"
    RC_SHELL="zsh"
  else
    RC_FILE="$HOME/.bashrc"
    RC_SHELL="bash"
  fi
  if ! command -v pyenv &> /dev/null; then
    echo "Installing pyenv..."
    rm -rf "$HOME/.pyenv"  # Remove existing pyenv directory if it exists
    curl https://pyenv.run | bash
    # Add pyenv init to the appropriate rc file for persistent shell usage
    if ! grep -q 'export PYENV_ROOT="$HOME/.pyenv"' "$RC_FILE"; then
      echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "$RC_FILE"
    fi
    if ! grep -q 'export PATH="$PYENV_ROOT/bin:$PATH"' "$RC_FILE"; then
      echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> "$RC_FILE"
    fi
    if ! grep -q "eval \"\$(pyenv init - $RC_SHELL)\"" "$RC_FILE"; then
      echo "eval \"\$(pyenv init - $RC_SHELL)\"" >> "$RC_FILE"
    fi
    if ! grep -q 'eval "$(pyenv virtualenv-init -)"' "$RC_FILE"; then
      echo 'eval "$(pyenv virtualenv-init -)"' >> "$RC_FILE"
    fi
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init - $RC_SHELL)"
  else
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init - $RC_SHELL)"
  fi
  # Install the specified Python version
  if ! pyenv versions --bare | grep -q "^$PYTHON_VERSION$"; then
    echo "Installing Python $PYTHON_VERSION with pyenv..."
    pyenv install --skip-existing "$PYTHON_VERSION"
  else
    echo "Python $PYTHON_VERSION is already installed. Skipping installation."
  fi
  # Set the specified Python version as the local version
  echo "Setting Python $PYTHON_VERSION as local version..."
  pyenv local "$PYTHON_VERSION"
  pyenv rehash
  PYTHON_BIN=python
fi

# Ensure pip is available and upgrade it
echo "Upgrading pip..."
if command -v $PYTHON_BIN &> /dev/null; then
  if $PYTHON_BIN -m pip --version &> /dev/null; then
    $PYTHON_BIN -m pip install --upgrade pip
  else
    echo "pip not found for $PYTHON_BIN. Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    $PYTHON_BIN get-pip.py
    rm get-pip.py
  fi
else
  echo "Error: $PYTHON_BIN command not found. Cannot upgrade pip."
  exit 1
fi

# Install pipenv using the correct pip for the selected Python
echo "Installing pipenv..."
$PYTHON_BIN -m pip install --user pipenv
# Detect shell rc file (bashrc or zshrc) using $SHELL
if [[ "$SHELL" =~ "zsh" ]]; then
  RC_FILE="$HOME/.zshrc"
else
  RC_FILE="$HOME/.bashrc"
fi
# Add $HOME/.local/bin to PATH in rc file if not already present
if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$RC_FILE"; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC_FILE"
fi
export PATH="$HOME/.local/bin:$PATH"

# Verify installations
echo "Verifying installations..."
if command -v cmake &> /dev/null; then
  cmake --version
else
  echo "cmake not found."
fi
if command -v pipenv &> /dev/null; then
  pipenv --version
else
  echo "pipenv not found."
fi
if command -v pyenv &> /dev/null; then
  pyenv --version
else
  echo "pyenv not found. (This is OK if system python is used)"
fi

echo "✅ Development environment setup complete."
