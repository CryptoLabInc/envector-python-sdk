#!/usr/bin/env bash

set -euo pipefail

install_build_deps_with_dnf() {
  local -r packages=(
    git openssl-devel libcurl-devel curl
    make perl tar gzip gcc gcc-c++
    perl-IPC-Cmd perl-Digest-SHA perl-Time-Piece
  )
  local attempt

  use_almalinux_baseurls

  for attempt in 1 2 3; do
    if dnf install -y --disablerepo='epel*' "${packages[@]}"; then
      return 0
    fi

    if [[ "$attempt" -lt 3 ]]; then
      echo "[WARN] dnf install failed on attempt ${attempt}; cleaning metadata and retrying..." >&2
      dnf clean all || true
      rm -rf /var/cache/dnf
      sleep "$attempt"
    fi
  done

  echo "[ERROR] dnf install failed after 3 attempts." >&2
  return 1
}

install_build_deps_with_yum() {
  local -r packages=(
    git openssl-devel libcurl-devel curl
    make perl tar gzip gcc gcc-c++
    perl-IPC-Cmd perl-Digest-SHA perl-Time-Piece
  )
  local attempt

  for attempt in 1 2 3; do
    if yum install -y --disablerepo='epel*' "${packages[@]}"; then
      return 0
    fi

    if [[ "$attempt" -lt 3 ]]; then
      echo "[WARN] yum install failed on attempt ${attempt}; cleaning metadata and retrying..." >&2
      yum clean all || true
      rm -rf /var/cache/yum
      sleep "$attempt"
    fi
  done

  echo "[ERROR] yum install failed after 3 attempts." >&2
  return 1
}

use_almalinux_baseurls() {
  if compgen -G "/etc/yum.repos.d/almalinux*.repo" >/dev/null; then
    sed -i -E \
      -e 's|^mirrorlist=|#mirrorlist=|' \
      -e 's|^# baseurl=https://repo.almalinux.org/almalinux/|baseurl=https://repo.almalinux.org/almalinux/|' \
      /etc/yum.repos.d/almalinux*.repo
  fi
}

build_tools_available() {
  local missing=0
  local command_name
  for command_name in git curl make perl tar gzip gcc g++ sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      echo "[WARN] Missing build command: ${command_name}" >&2
      missing=1
    fi
  done
  if ! perl -MFindBin -MIPC::Cmd -MDigest::SHA -MTime::Piece -e1 >/dev/null 2>&1; then
    echo "[WARN] Missing Perl modules required for OpenSSL source build." >&2
    missing=1
  fi
  return "$missing"
}

download_with_retries() {
  local -r output_path="$1"
  shift

  local url
  local attempt
  for url in "$@"; do
    for attempt in 1 2 3; do
      if curl -fsSL "$url" -o "$output_path"; then
        return 0
      fi

      if [[ "$attempt" -lt 3 ]]; then
        echo "[WARN] Download failed from ${url} on attempt ${attempt}; retrying..." >&2
        sleep "$attempt"
      fi
    done
  done

  echo "[ERROR] Failed to download $output_path from all configured URLs." >&2
  return 1
}

verify_sha256() {
  local -r expected_sha256="$1"
  local -r archive="$2"

  echo "${expected_sha256}  ${archive}" | sha256sum -c -
}

build_jobs() {
  getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 2
}

openssl_target_for_arch() {
  case "$(uname -m)" in
    x86_64) echo "linux-x86_64" ;;
    aarch64 | arm64) echo "linux-aarch64" ;;
    *)
      echo "[ERROR] Unsupported OpenSSL build arch: $(uname -m)" >&2
      return 1
      ;;
  esac
}

openssl_old_source_dir() {
  local -r version="$1"
  if [[ "$version" == 1.1.1* ]]; then
    echo "1.1.1"
  else
    echo "${version%.*}"
  fi
}

build_static_zlib() {
  local -r version="${CIBW_ZLIB_VERSION:-1.3.2}"
  local -r default_sha256="bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
  local -r expected_sha256="${CIBW_ZLIB_SHA256:-$default_sha256}"
  local -r prefix="${CIBW_ZLIB_PREFIX:-/opt/zlib-static}"
  local -r archive="/tmp/zlib-${version}.tar.gz"
  local -r workdir="/tmp/cibw-static-zlib-${version}"

  if [[ -f "${prefix}/lib/libz.a" ]]; then
    echo "[INFO] Reusing static zlib: ${prefix}/lib/libz.a"
    return 0
  fi

  echo "[INFO] Building static zlib ${version} into ${prefix}"
  rm -rf "$workdir"
  mkdir -p "$workdir"
  download_with_retries \
    "$archive" \
    "https://zlib.net/fossils/zlib-${version}.tar.gz" \
    "https://zlib.net/zlib-${version}.tar.gz"
  verify_sha256 "$expected_sha256" "$archive"
  tar -xzf "$archive" -C "$workdir" --strip-components=1

  (
    cd "$workdir"
    CFLAGS="${CFLAGS:-} -fPIC" ./configure --static --prefix="$prefix"
    make -j"$(build_jobs)"
    make install
  )

  test -f "${prefix}/lib/libz.a"
}

build_static_openssl() {
  local -r version="${CIBW_OPENSSL_VERSION:-3.5.6}"
  local -r default_sha256="deae7c80cba99c4b4f940ecadb3c3338b13cb77418409238e57d7f31f2a3b736"
  local -r expected_sha256="${CIBW_OPENSSL_SHA256:-$default_sha256}"
  local -r prefix="${CIBW_OPENSSL_PREFIX:-/opt/openssl-static}"
  local -r openssldir="${CIBW_OPENSSL_OPENSSLDIR:-/etc/ssl}"
  local -r archive="/tmp/openssl-${version}.tar.gz"
  local -r workdir="/tmp/cibw-static-openssl-${version}"
  local openssl_target
  local old_dir

  if [[ -f "${prefix}/lib/libcrypto.a" && -f "${prefix}/lib/libssl.a" ]]; then
    echo "[INFO] Reusing static OpenSSL: ${prefix}/lib/libcrypto.a"
    return 0
  fi

  openssl_target="$(openssl_target_for_arch)"
  old_dir="$(openssl_old_source_dir "$version")"

  echo "[INFO] Building static OpenSSL ${version} (${openssl_target}) into ${prefix}"
  rm -rf "$workdir"
  mkdir -p "$workdir"
  download_with_retries \
    "$archive" \
    "https://www.openssl.org/source/openssl-${version}.tar.gz" \
    "https://www.openssl.org/source/old/${old_dir}/openssl-${version}.tar.gz"
  verify_sha256 "$expected_sha256" "$archive"
  tar -xzf "$archive" -C "$workdir" --strip-components=1

  (
    cd "$workdir"
    ./Configure "$openssl_target" \
      --prefix="$prefix" \
      --openssldir="$openssldir" \
      --libdir=lib \
      -fPIC \
      no-shared \
      no-tests \
      no-zlib
    make -j"$(build_jobs)"
    make install_sw
  )

  test -f "${prefix}/lib/libcrypto.a"
  test -f "${prefix}/lib/libssl.a"
}

# Install build dependencies required for native extensions and the static
# OpenSSL/zlib source builds. manylinux_2_28 uses dnf; manylinux2014 uses yum.
if command -v dnf >/dev/null 2>&1; then
  install_build_deps_with_dnf
elif command -v yum >/dev/null 2>&1; then
  install_build_deps_with_yum
else
  echo "[ERROR] Missing build commands and no supported package manager found." >&2
  exit 1
fi

if ! build_tools_available; then
  echo "[ERROR] Required build commands or Perl modules are still missing after setup." >&2
  exit 1
fi

build_static_zlib
build_static_openssl

echo "[INFO] Static dependency artifacts:"
ls -lh \
  "${CIBW_ZLIB_PREFIX:-/opt/zlib-static}/lib/libz.a" \
  "${CIBW_OPENSSL_PREFIX:-/opt/openssl-static}/lib/libcrypto.a" \
  "${CIBW_OPENSSL_PREFIX:-/opt/openssl-static}/lib/libssl.a"

# Configure git to use the provided GitHub token for private repositories.
# Note: run from a neutral directory to avoid touching a submodule worktree
# that points to a non-existent superproject .git inside the container.
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  if command -v git >/dev/null 2>&1; then
    (
      cd / || cd /tmp || true
      git config --global url."https://oauth2:${GITHUB_TOKEN}@github.com/".insteadOf https://github.com/
      git config --global --add url."https://oauth2:${GITHUB_TOKEN}@github.com/".insteadOf git@github.com:
    )
  else
    echo "[WARN] git is not available; cannot preconfigure token for GitHub clones." >&2
  fi
else
  echo "[WARN] GITHUB_TOKEN not set; private dependencies may fail to download." >&2
fi
