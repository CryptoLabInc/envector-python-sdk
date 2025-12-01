## enVector Python SDK: Development Environment Setup

### Requirements

**Ubuntu**
- OS: Ubuntu 22.04+
- Shell: bash
- Python: 3.12 (recommended)
- Virtual Environment: pipenv

**Mac**
- OS: macOS Sequoia 15.5+
- Shell: zsh
- Package Manager: Homebrew
- Python: 3.12 (recommended)
- Virtual Environment: pipenv

---
### 0. Install Dependencies (Linux)
```
sudo apt-get update
sudo apt-get install -y make build-essential \
  libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm \
  libncursesw5-dev xz-utils tk-dev \
  libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev git
```

### 1. Clone the Repository

> **Tip:** Make sure your SSH key is registered with GitHub for private repo access.

```bash
git config url."git@github.com:".insteadOf https://github.com/
git clone git@github.com:CryptoLabInc/envector-python-sdk.git
```

---

### 2. Quick Setup (Recommended)

**For SDK developers:**
> Use this quick setup to prepare a full development environment.
>
**For SDK User:**
> See section 4 (B) below if you only want to build the wheel file for distribution or installation.

```bash
./scripts/setup.sh --python 3.12
# Check importing pyenvector and its version
pipenv run python -c "import pyenvector as ev; print(ev.__version__)"
# Activate Pipenv
pipenv shell
```
- Default Python version is 3.12.
- All dependencies, submodules, and build steps are automated.

---

### 3. Manual Step-by-Step Setup

```bash
# 1. Initialize submodules
./scripts/init_evi_crypto.sh

# 3. Install Python & pipenv
#
# If the above scripts do not work for your system, please ensure that Python 3.12 and pipenv are installed manually.
# You can use your OS package manager, pyenv, conda, or any other method to install Python 3.12 and pipenv.
# After installation, continue with the next steps.
./scripts/install_deps_linux.sh   # For Linux
./scripts/install_deps_mac.sh     # For Mac

# 4. Set up pipenv environment
./scripts/setup_pipenv.sh

# 5. Build and install the SDK
pipenv run ./scripts/build_and_install.sh

# 6. Check importing pyenvector and its version
pipenv run python -c "import pyenvector as ev; print(ev.__version__)"

# 7. Activate Pipenv
pipenv shell
```

---

### 4. Build a Wheel File

> **Note:**
> The wheel file (`.whl`) is intended for deployment and distribution, **not for development**.
> **SDK developers should NOT use the wheel build for development.**
> If you are developing the SDK, skip this section and use the Quick Setup above.
> Only follow these instructions if you need to generate a wheel for deployment or installation elsewhere.


#### (A) If you have already run `./scripts/setup.sh` and have a working pipenv environment:

```bash
# Activate Pipenv
pipenv shell

pipenv run export-wheel

pip install dist/pyenvector-XXX.whl
```

#### (B) If you have NOT run `./scripts/setup.sh` (or want to only build the wheel):

```bash
./scripts/setup.sh --type wheel
# The wheel file will be generated in the dist/ directory
pipenv shell

pip install dist/pyenvector-XXX.whl
```

---

### 5. Run Tests

```bash
pipenv run pytest
```

---

### 6. Build Documentation

> **Note:** Make sure the SDK is installed before building docs.

```bash
pipenv run docs
```

---

### 7. CLI Key Generation Example

You can generate keys using the CLI after installing the SDK wheel.
Keys will be stored in `{key_path}/{key_id}`.

#### Basic Usage

```bash
source .venv/bin/activate
# Generate keys without KEK (Key Encryption Key)
pyenvector-keygen --key_path keys --key_id id --seal_mode none --metadata_encryption true
```

#### Generate keys with AES KEK

```bash
pyenvector-keygen --key_path keys --key_id seal --seal_mode aes --seal_kek_path aes.kek --eval_mode rmp --preset ip
```

**Arguments (with defaults):**
- `--key_path`: Directory to store keys (default: `./keys`)
- `--key_id`: Key ID (subdirectory under key_path, default: `id`)
- `--preset`: Parameter preset (e.g. `ip`, default: `ip`)
- `--eval_mode`: Evaluation mode (e.g. `rmp`, default: `rmp`)
- `--seal_mode`: Seal mode (`none` or `aes`, default: `none`)
- `--seal_kek_path`: Path to AES KEK file (required if `seal_mode` is `aes`)
- `--seal_kek_stdin`: Read AES KEK from stdin (if set, overrides `--seal_kek_path`)
- `--metadata_encryption`: Metadata encryption mode (`false` for no encryption, `true` for AES-GCM encryption; default: `true`)

If you use `--seal_kek_stdin`, you can provide the KEK via standard input:
```bash
echo "your-32-byte-kek" | pyenvector-keygen \
--key_path keys \
--key_id seal \
--seal_mode aes \
--seal_kek_stdin \
--eval_mode rmp \
--preset ip \
--metadata_encryption true
```
Or, you can use file redirection:
```bash
pyenvector-keygen --key_path keys --key_id seal --seal_mode aes --seal_kek_stdin --eval_mode rmp --preset ip < aes.kek
```
---

**For troubleshooting or custom setups, refer to each script's comments and logs.**
If you encounter issues with Python or pipenv installation, please install them manually and retry the setup steps.


### Whl User (MacOS)
```
brew install virtualenv python@3.12 libomp
virtualenv -p python3.12 pyenvector_venv
source pyenvector_venv/bin/activate
pip install dist/pyenvector-1.0.0-cp312-cp312-macosx_15_0_arm64.whl
```

### Whl User (Linux)
```
# Make sure Python 3.12 is available in your virtual environment, or use pyenv to install python3.12

# Install Pyenv (if you do not have python3.12 and virtualenv)
rm -rf "$HOME/.pyenv"  # Remove existing pyenv directory if it exists
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
pyenv install 3.12
pyenv global 3.12

# Activate virtualenv and install whl file
pip install virtualenv
virtualenv -p python3.12 pyenvector_venv
source pyenvector_venv/bin/activate
pip install dist/pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl
```

**Log Level Troubleshooting:**
- By default, SDK logs are hidden. To enable detailed loguru logs (for debugging), set the environment variable before running any Python commands:

```bash
export PYENVECTOR_LOG_LEVEL=DEBUG  # PYENVECTOR_LOG_LEVEL is still accepted for compatibility
```
- This will show debug-level logs for SDK operations.

## How to Deploy a Wheel to PyPI
```
export GITHUB_TOKEN="{your_github_token}"
export WHEEL_VERSION="x.x.x"
# build wheel by os
./scripts/build_wheel_by_os.sh
```

```
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="{your_pypi_api_token}"
# uplooad test pypi
./scripts/upload_wheel_to_pypi.sh
# upload to pypi
UPLOAD_TARGET="release-pypi" ./scripts/upload_wheel_to_pypi.sh
```

```
# download stable version
pip install pyenvector
# download pre-release version
pip install pyenvector --pre
```
