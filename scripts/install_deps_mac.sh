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

# Detect CI environment
if [[ -n "$CI_FLAG" || -n "${CI:-}" ]]; then
  echo "CI environment detected. Skipping Homebrew installation."
else
  echo "Detected macOS platform."
  # macOS-specific install logic
  # Install Homebrew if not installed
  if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$('/opt/homebrew/bin/brew' shellenv)"
  else
    echo "Homebrew is already installed."
    eval "$('/opt/homebrew/bin/brew' shellenv)"
  fi
  # Update Homebrew
  echo "Updating Homebrew..."
  brew update

  # Install dependencies if not already installed
  dependencies=(libffi openssl@3 libomp python pybind11 cmake pipenv pyenv)
  for dep in "${dependencies[@]}"; do
    if ! brew list --formula | grep -q "^$dep$"; then
      echo "Installing $dep..."
      brew install "$dep"
    else
      echo "$dep is already installed. UPDATE."
      brew upgrade "$dep"
    fi
  done
fi
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
  if ! grep -q 'eval "$(pyenv init - $RC_SHELL)"' "$RC_FILE"; then
    echo "eval \"\$(pyenv init - $RC_SHELL)\"" >> "$RC_FILE"
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
# Ensure pip is available and upgrade it
if command -v python &> /dev/null; then
  echo "Upgrading pip..."
  if command -v pip &> /dev/null; then
    pip install --upgrade pip
  else
    echo "Warning: 'pip' command not found directly. Attempting to upgrade via 'python -m pip'."
    python -m pip install --upgrade pip
  fi
else
  echo "Error: Python command not found. Cannot upgrade pip."
  exit 1
fi
# Install pipenv using the correct pip for the pyenv-managed Python
echo "Installing pipenv..."
if command -v pip &> /dev/null; then
  pip install pipenv
else
  echo "Warning: 'pip' command not found directly. Attempting to install pipenv via 'python -m pip'."
  python -m pip install pipenv
fi
pyenv rehash

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
  echo "pyenv not found."
fi

echo "✅ Development environment setup complete."
