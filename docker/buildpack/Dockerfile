# syntax=docker/dockerfile:1.6
#
# Build pyenvector wheel artifacts from source.
#
# This Dockerfile intentionally stops at the wheel artifact boundary. Use
# sdk/python/docker/dockerize/Dockerfile to package a runtime image from a
# prebuilt wheelhouse without exposing the private source tree in the runtime
# image build context.
#
# Example:
#   docker buildx build --platform linux/amd64 \
#     --target wheelhouse \
#     --output type=local,dest=./sdk/python/dist/sdk-wheel-house/dev-py312/amd64 \
#     --build-arg PYTHON_VERSION=3.12 \
#     --build-arg PYTHON_TAG=cp312 \
#     -f sdk/python/docker/buildpack/Dockerfile sdk/python

ARG PYTHON_VERSION=3.12
ARG PYTHON_TAG=cp312
ARG MANYLINUX_AMD64_IMAGE=quay.io/pypa/manylinux_2_28_x86_64
ARG MANYLINUX_ARM64_IMAGE=quay.io/pypa/manylinux_2_28_aarch64
ARG OPENSSL_VERSION=3.1.4

FROM --platform=linux/amd64 ${MANYLINUX_AMD64_IMAGE} AS manylinux-amd64
FROM --platform=linux/arm64 ${MANYLINUX_ARM64_IMAGE} AS manylinux-arm64

FROM manylinux-${TARGETARCH} AS builder
ARG TARGETARCH
ARG PYTHON_TAG
ARG OPENSSL_VERSION

WORKDIR /src

RUN set -eux; \
    PYBIN="$(ls -d /opt/python/${PYTHON_TAG}-${PYTHON_TAG}*/bin | head -n1)"; \
    ln -sf "${PYBIN}/python" /usr/local/bin/python; \
    ln -sf "${PYBIN}/pip" /usr/local/bin/pip

RUN dnf install -y --setopt=install_weak_deps=False \
      git perl-IPC-Cmd perl-Digest-SHA perl-core \
      libcurl-devel curl && \
    dnf clean all && rm -rf /var/cache/dnf

# Build static OpenSSL (no-shared + -fPIC) required by crypto/CMakeLists.txt.
# The CMake build validates libcrypto.a exists and rejects shared libs.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) OPENSSL_TARGET=linux-x86_64 ;; \
      arm64) OPENSSL_TARGET=linux-aarch64 ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir /tmp/openssl-build && cd /tmp/openssl-build && \
    curl -fsSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" | tar xz && \
    cd "openssl-${OPENSSL_VERSION}" && \
    ./Configure "${OPENSSL_TARGET}" \
        --prefix=/opt/openssl-static \
        --openssldir=/opt/openssl-static/ssl \
        --libdir=lib \
        -fPIC -fno-lto \
        no-shared no-dso \
        no-ssl3 no-ssl3-method no-weak-ssl-ciphers && \
    make -j"$(nproc)" && \
    make install_sw && \
    rm -rf /tmp/openssl-build

ENV OPENSSL_ROOT_DIR=/opt/openssl-static
ENV CMAKE_PREFIX_PATH=/opt/openssl-static

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt auditwheel

COPY pyproject.toml README_pypi.md MANIFEST.in LICENSE ./
COPY pyenvector ./pyenvector
COPY external/evi ./external/evi

# scikit-build-core reads cmake.source-dir = ./external/evi/crypto
RUN CXXFLAGS='-include cstdint' pip wheel --no-deps --wheel-dir /wheels/raw .

RUN mkdir -p /wheels/out && \
    for w in /wheels/raw/*.whl; do \
      auditwheel repair "$w" -w /wheels/out || cp "$w" /wheels/out/; \
    done && \
    ls -la /wheels/out

FROM scratch AS wheelhouse
COPY --from=builder /wheels/out/ /
