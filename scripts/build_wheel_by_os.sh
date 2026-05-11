#!/usr/bin/env bash

print_usage() {
  cat <<'EOF'
Usage:
  WHEEL_VERSION=<version> [CIBW_BUILD='<python-tags>'] [CIBW_MANYLINUX_POLICIES='<policies>'] ./scripts/build_wheel_by_os.sh

Environment:
  WHEEL_VERSION              Required package version to write into pyproject.toml and pyenvector/__init__.py.
  CIBW_BUILD                 Optional cibuildwheel Python selector.
                             Default: cp39-* cp310-* cp311-* cp312-* cp313-*
  CIBW_MANYLINUX_POLICIES    Optional Linux policy list.
                             Choices: manylinux_2_28, manylinux2014, or both separated by spaces.
                             Default: manylinux_2_28
  BUILD_ARM                  On macOS, set to 1 to build Linux/aarch64 instead of macOS wheels.

Examples:
  # Python 3.12 + manylinux_2_28 only
  CIBW_BUILD='cp312-*' \
  CIBW_MANYLINUX_POLICIES='manylinux_2_28' \
  WHEEL_VERSION=1.4.3 \
  ./scripts/build_wheel_by_os.sh

  # Python 3.10 + manylinux2014 only
  CIBW_BUILD='cp310-*' \
  CIBW_MANYLINUX_POLICIES='manylinux2014' \
  WHEEL_VERSION=1.4.3 \
  ./scripts/build_wheel_by_os.sh

  # Python 3.11 + both Linux policies
  CIBW_BUILD='cp311-*' \
  CIBW_MANYLINUX_POLICIES='manylinux_2_28 manylinux2014' \
  WHEEL_VERSION=1.4.3 \
  ./scripts/build_wheel_by_os.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  print_usage
  exit 0
fi

set -ex

PLATFORM=$(uname)
echo "[INFO] Detected platform: $PLATFORM"

set -euo pipefail

TOML_FILE="pyproject.toml"
PY_INIT_FILE="pyenvector/__init__.py"

: "${WHEEL_VERSION:?[ERROR] WHEEL_VERSION not set}"
echo "[INFO] Target version: $WHEEL_VERSION"

# External toggle to build Linux aarch64 wheels from macOS
BUILD_ARM="${BUILD_ARM:-0}"

clean_local_build_inputs() {
    echo "[INFO] Cleaning local build inputs..."
    rm -rf _skbuild build ./*.egg-info
}

validate_manylinux_policy() {
    local -r policy="$1"
    case "$policy" in
        manylinux_2_28 | manylinux2014) ;;
        *)
            echo "[ERROR] Unsupported CIBW_MANYLINUX_POLICIES entry: ${policy}" >&2
            echo "[ERROR] Choices: manylinux_2_28, manylinux2014, or both separated by spaces." >&2
            exit 1
            ;;
    esac
}

# update __version__
echo "[INFO] Updating __version__ in $PY_INIT_FILE"
sed -i.bak -E \
  "s/^([[:space:]]*__version__[[:space:]]*=[[:space:]]*)\"[^\"]+\"/\1\"$WHEEL_VERSION\"/" \
  "pyenvector/__init__.py"
if ! grep -Eq '^[[:space:]]*__version__[[:space:]]*=' "$PY_INIT_FILE"; then
  echo "__version__ = \"$WHEEL_VERSION\"" >> "$PY_INIT_FILE"
fi
rm -rf "$PY_INIT_FILE.bak"
# update pyproject.toml version
echo "[INFO] Updating version in $TOML_FILE"
sed -i.bak -E \
  "s/^version[[:space:]]*=[[:space:]]*\"[^\"]+\"/version = \"$WHEEL_VERSION\"/" \
  "pyproject.toml"
rm -rf "$TOML_FILE.bak"


if [[ "$PLATFORM" == "Darwin" && "$BUILD_ARM" == "0" ]]; then
    echo "[INFO] Building macOS wheels..."
    rm -rf dist
    echo "[INFO] Running build_all_combinations_mac.sh"
    ./scripts/build_all_combinations_mac.sh
    echo "[INFO] macOS build completed successfully."
else
    echo "[INFO] Building Linux wheels with cibuildwheel..."
    rm -rf dist
    clean_local_build_inputs
    mkdir -p dist
    # Respect pre-set CIBW_BUILD (e.g., from CI). Default to all supported versions.
    # Export to ensure cibuildwheel (and its Docker container) sees these variables.
    export CIBW_PLATFORM=linux
    export CIBW_SKIP="*-manylinux_i686 *-musllinux*"
    export CIBW_BUILD="${CIBW_BUILD:-cp39-* cp310-* cp311-* cp312-* cp313-*}"
    export CIBW_BUILD_VERBOSITY="${CIBW_BUILD_VERBOSITY:-1}"
    export CIBW_BEFORE_ALL="bash /project/scripts/cibw_before_all.sh"
    STATIC_CMAKE_ARGS="-DBUILD_PYTHON=ON -DEVI_KM_PREFER_AWS_SDK=OFF -DEVI_KM_PREFER_GCP_SDK=OFF -DOPENSSL_ROOT_DIR=/opt/openssl-static -DOPENSSL_INCLUDE_DIR=/opt/openssl-static/include -DOPENSSL_CRYPTO_LIBRARY=/opt/openssl-static/lib/libcrypto.a -DOPENSSL_SSL_LIBRARY=/opt/openssl-static/lib/libssl.a -DOPENSSL_USE_STATIC_LIBS=TRUE -DZLIB_INCLUDE_DIR=/opt/zlib-static/include -DZLIB_LIBRARY=/opt/zlib-static/lib/libz.a"
    export CIBW_ENVIRONMENT="GITHUB_TOKEN=${GITHUB_TOKEN:-} CXXFLAGS='-include cstdint' CMAKE_ARGS='${CMAKE_ARGS:-} ${STATIC_CMAKE_ARGS}' CIBW_OPENSSL_PREFIX=/opt/openssl-static CIBW_ZLIB_PREFIX=/opt/zlib-static"

    # Build multiple manylinux policies so pip can select the best compatible
    # wheel for the user's glibc version.
    read -r -a MANYLINUX_POLICIES <<< "${CIBW_MANYLINUX_POLICIES:-manylinux_2_28}"
    if [[ "${#MANYLINUX_POLICIES[@]}" -eq 0 ]]; then
        echo "[ERROR] CIBW_MANYLINUX_POLICIES must contain at least one policy." >&2
        exit 1
    fi
    for policy in "${MANYLINUX_POLICIES[@]}"; do
        validate_manylinux_policy "$policy"
    done
    for policy in "${MANYLINUX_POLICIES[@]}"; do
        echo "[INFO] Building Linux wheels for ${policy}..."
        export CIBW_MANYLINUX_X86_64_IMAGE="$policy"
        export CIBW_MANYLINUX_AARCH64_IMAGE="$policy"

        python3 -m cibuildwheel . --output-dir dist
    done

    ls -lh dist/*.whl
    echo "[INFO] Linux build completed successfully."
fi

echo "[INFO] All done!"
