# Contributing to pyenvector

This guide covers development environment setup, building from source, and running tests.

## Requirements

**Linux (Ubuntu 22.04+)**
- Python 3.12 (recommended)
- pipenv
- Build tools: `make`, `build-essential`, `libssl-dev`, `zlib1g-dev`, `libbz2-dev`, `libreadline-dev`, `libsqlite3-dev`, `wget`, `curl`, `llvm`, `libncursesw5-dev`, `xz-utils`, `tk-dev`, `libxml2-dev`, `libxmlsec1-dev`, `libffi-dev`, `liblzma-dev`, `git`

```bash
sudo apt-get update
sudo apt-get install -y make build-essential \
  libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm \
  libncursesw5-dev xz-utils tk-dev \
  libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev git
```

**macOS (Sequoia 15.5+)**
- Homebrew
- Python 3.12 (recommended)
- pipenv

## Clone

```bash
git clone git@github.com:CryptoLabInc/envector-python-sdk.git
cd envector-python-sdk
```

## Quick Setup (Recommended)

```bash
./scripts/setup.sh --python 3.12

# Verify
pipenv run python -c "import pyenvector as ev; print(ev.__version__)"

# Activate shell
pipenv shell
```

All dependencies, submodules, and build steps are automated.
The published wheel keeps AWS and GCP key-store backends optional via
`pyenvector[aws]` and `pyenvector[gcp]`.

## Manual Step-by-Step Setup

```bash
# 1. Initialize submodules
./scripts/init_evi.sh

# 2. Install Python & pipenv
./scripts/install_deps_linux.sh   # Linux
./scripts/install_deps_mac.sh     # macOS

# 3. Set up pipenv environment
./scripts/setup_pipenv.sh

# 4. Build and install the SDK
pipenv run ./scripts/build_and_install.sh

# 5. Verify
pipenv run python -c "import pyenvector as ev; print(ev.__version__)"
```

## Running Tests

```bash
pipenv run pytest
```

## Building Documentation

```bash
pipenv run docs
```

## Building a Wheel

> Wheel files are for deployment and distribution, not for development.
> SDK developers should use the Quick Setup above.

**If you already have a pipenv environment:**

```bash
pipenv run export-wheel
pip install dist/pyenvector-*.whl
```

**Wheel-only build (no dev environment):**

```bash
./scripts/setup.sh --type wheel
pip install dist/pyenvector-*.whl
```

### Installing a Wheel (End Users)

**macOS:**
```bash
brew install virtualenv python@3.12 libomp
virtualenv -p python3.12 pyenvector_venv
source pyenvector_venv/bin/activate
pip install dist/pyenvector-*.whl
```

**Linux:**
```bash
# Ensure Python 3.12 is available (via pyenv, system package, etc.)
virtualenv -p python3.12 pyenvector_venv
source pyenvector_venv/bin/activate
pip install dist/pyenvector-*.whl
```

## Publishing to PyPI

```bash
export GITHUB_TOKEN="{your_github_token}"
export WHEEL_VERSION="x.x.x"
./scripts/build_wheel_by_os.sh

export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="{your_pypi_api_token}"

# Test PyPI
./scripts/upload_wheel_to_pypi.sh

# Production PyPI
UPLOAD_TARGET="release-pypi" ./scripts/upload_wheel_to_pypi.sh
```

## Troubleshooting

**Log level:** SDK logs are hidden by default. Enable debug logs:

```bash
export PYENVECTOR_LOG_LEVEL=DEBUG
```

**Python / pipenv issues:** If the setup scripts don't work for your system, install Python 3.12 and pipenv manually (via pyenv, conda, or your OS package manager), then continue with the manual setup steps.
