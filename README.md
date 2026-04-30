# pyenvector — enVector Python SDK

[![PyPI version](https://img.shields.io/pypi/v/pyenvector)](https://pypi.org/project/pyenvector/)
[![Python](https://img.shields.io/pypi/pyversions/pyenvector)](https://pypi.org/project/pyenvector/)
[![License](https://img.shields.io/badge/license-proprietary-blue)](./LICENSE)

Python SDK for **enVector** — encrypted vector search powered by fully homomorphic encryption (FHE).

Your vectors and similarity scores stay encrypted during the entire computation.
The server never sees plaintext data.

---
### 0. Install Dependencies (Linux)
```
sudo apt-get update
sudo apt-get install -y make build-essential \
  libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm \
  libcurl4-openssl-dev \
  libncursesw5-dev xz-utils tk-dev \
  libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev git
```

### 1. Clone the Repository

> **Tip:** Make sure your SSH key is registered with GitHub for private repo access.

```bash
pip install pyenvector

# or, for pre-release versions:
pip install pyenvector --pre
```

Requires Python 3.9 -- 3.13. Wheels are available for Linux (x86_64) and macOS (arm64).

## Quick Start

```python
import numpy as np
import pyenvector as ev

# 1. Connect and load keys
ev.init(host="localhost", port=50050, key_path="./keys", key_id="my_key")

# 2. Create an index
index = ev.create_index("my_index", dim=512)

# 3. Insert vectors
vectors = np.random.randn(100, 512).astype(np.float32)
vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
metadata = [f"item_{i}" for i in range(100)]

index.insert(vectors, metadata=metadata)

# 4. Search (encrypted end-to-end)
result = index.search(vectors[0], top_k=5, output_fields=["metadata"])
print(result)

# 5. Clean up
ev.drop_index("my_index")
# ev.delete_key("my_key")  # optional: remove keys from server
```

## Key Features

- **End-to-end encryption** — vectors are encrypted on the client before leaving your machine. Search computation happens on ciphertext via FHE. Scores are decrypted only on the client.
- **Drop-in vector DB API** — `create_index`, `insert`, `search`, `drop_index`. Familiar interface if you have used Milvus, Pinecone, or similar.
- **Admin management APIs** — inspect index summaries with `get_index_summary` and duplicate existing indexes with `clone_index`.
- **Key management** — generate, seal (AES KEK), and upload keys to AWS S3 / GCP Cloud Storage via the `pyenvector-keygen` CLI.
- **Cloud-ready** — deploy the enVector server on GKE, EKS, or on-prem. The SDK talks gRPC.

## CLI: Key Generation

```bash
# Generate keys locally
pyenvector-keygen --key-path ./keys --key-id my_key

# Generate with AES sealing
pyenvector-keygen --key-path ./keys --key-id my_key \
  --seal-mode aes --seal-key-path aes.kek

# Upload directly to AWS
pyenvector-keygen --key-store aws --key-id my_key \
  --region-name ap-northeast-2 \
  --bucket-name my-bucket \
  --secret-prefix envector/keys

# Upload directly to GCP
pyenvector-keygen --key-store gcp --key-id my_key \
  --bucket-name my-bucket \
  --secret-prefix envector/keys
```

Run `pyenvector-keygen --help` for all options.

## Examples

See the [`example/`](./example) directory:

| Directory | Description |
|-----------|-------------|
| `client_only/` | Client-side encryption, key generation, and cipher operations without a server |
| `client_and_server/` | End-to-end workflows: index creation, insert, search, and index operations |

## Documentation

- [enVector Documentation](https://docs.envector.io) — full product docs (deployment, architecture, API reference)
- [PyPI page](https://pypi.org/project/pyenvector/) — package info and install instructions

## Requirements

- Python 3.9 -- 3.13
- A running enVector server (for search operations; client-only crypto works offline)
- HE keys generated via `pyenvector-keygen`

## Docker

Docker packaging is split into two phases under `sdk/python/docker/`:

- **wheel build**: [`docker/buildpack/Dockerfile`](./docker/buildpack/Dockerfile)
  builds manylinux wheels from source using the private
  `external/evi` submodule (cmake source-dir: `external/evi/crypto`).
- **runtime packaging**:
  [`docker/dockerize/Dockerfile`](./docker/dockerize/Dockerfile)
  installs only prebuilt wheels into a minimal runtime image. Its build context
  is the wheelhouse only, so the private source tree is not available to the
  runtime image build.

The helper [`./scripts/build_docker.sh`](./scripts/build_docker.sh) orchestrates
both phases by default. The private submodule must be populated only for the
wheel-build phase (`git submodule update --init --recursive`).

```bash
# Single arch (host), loads into local daemon -- defaults to amd64
./scripts/build_docker.sh

# arm64 build (qemu emulation is auto-registered on first run)
./scripts/build_docker.sh --target-arch arm64

# Build wheel artifacts only (no runtime image)
./scripts/build_docker.sh --wheel-only

# Package from an existing wheelhouse without reading the private source tree
./scripts/build_docker.sh \
  --wheelhouse ./dist/sdk-wheel-house/1.4.0a5-py312

# Multi-arch manifest -- must push to a registry (docker cannot --load
# a multi-platform manifest into the local daemon)
./scripts/build_docker.sh --target-arch multiarch --action push \
  --image <registry>/pyenvector --tag v1.4.0a5

# Different CPython ABI
./scripts/build_docker.sh --python 3.11 --tag dev

# Raw buildx equivalent: build a wheel artifact for amd64
docker buildx build --platform linux/amd64 \
  --target wheelhouse \
  --output type=local,dest=./dist/sdk-wheel-house/dev-py312/amd64 \
  --build-arg PYTHON_VERSION=3.12 \
  --build-arg PYTHON_TAG=cp312 \
  -f ./docker/buildpack/Dockerfile .

# Raw buildx equivalent: package a runtime image from the wheelhouse only
docker buildx build --platform linux/amd64 --load \
  --build-arg PYTHON_VERSION=3.12 \
  -t pyenvector:dev-amd64 \
  -f ./docker/dockerize/Dockerfile \
  ./dist/sdk-wheel-house/dev-py312
```

The helper auto-creates a `docker-container` buildx builder
(`pyenvector-builder`) and bootstraps qemu for cross-arch emulation when
needed. Cross-arch builds under emulation are substantially slower than
native — prefer native CI runners (or `--target-arch multiarch` on a runner
that has both architectures available) for routine release builds. See
`./scripts/build_docker.sh --help` for all flags.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development environment setup, build instructions, and how to run tests.

## License

Proprietary. See [LICENSE](./LICENSE) for details.
Contact: pypi@cryptolab.co.kr
