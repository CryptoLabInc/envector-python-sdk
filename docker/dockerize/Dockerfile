# syntax=docker/dockerfile:1.6
#
# Package a prebuilt pyenvector wheelhouse into a minimal runtime image.
#
# Expected build context layout:
#   ./amd64/*.whl
#   ./arm64/*.whl
#
# Build the wheelhouse first with sdk/python/docker/buildpack/Dockerfile
# or sdk/python/scripts/build_docker.sh --wheel-only. This Dockerfile never
# reads the private SDK source tree.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS runtime
ARG TARGETARCH
ARG USER_UID=1000
ARG USER_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      libgomp1 libopenblas0 ca-certificates vim-tiny && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /tmp/wheelhouse/
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) WHEEL_DIR="/tmp/wheelhouse/amd64" ;; \
      arm64) WHEEL_DIR="/tmp/wheelhouse/arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    if [ ! -d "${WHEEL_DIR}" ]; then \
      echo "Missing wheel directory for ${TARGETARCH}: ${WHEEL_DIR}" >&2; \
      exit 1; \
    fi; \
    WHEEL="$(find "${WHEEL_DIR}" -maxdepth 1 -type f -name '*.whl' | head -n1)"; \
    if [ -z "${WHEEL}" ]; then \
      echo "No wheel found in ${WHEEL_DIR}" >&2; \
      exit 1; \
    fi; \
    pip install "${WHEEL}"; \
    rm -rf /tmp/wheelhouse

RUN groupadd --gid "${USER_GID}" app && \
    useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

CMD ["python", "-c", "import pyenvector; print(f'pyenvector {pyenvector.__version__} ready')"]
