#!/usr/bin/env bash

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
    # Respect pre-set CIBW_BUILD (e.g., from CI). Default to all supported versions.
    # Export to ensure cibuildwheel (and its Docker container) sees these variables.
    export CIBW_PLATFORM=linux
    export CIBW_SKIP="*-manylinux_i686 *-musllinux*"
    export CIBW_BUILD="${CIBW_BUILD:-cp39-* cp310-* cp311-* cp312-* cp313-*}"
    export CIBW_BEFORE_ALL="bash /project/scripts/cibw_before_all.sh"
    export CIBW_ENVIRONMENT="GITHUB_TOKEN=${GITHUB_TOKEN} CXXFLAGS='-include cstdint'"
    # cibuildwheel already writes wheels to the specified output dir (dist).
    # No extra move is needed; moving into the same directory causes an error.
    python3 -m cibuildwheel . --output-dir dist
    echo "[INFO] Linux build completed successfully."
fi

echo "[INFO] All done!"
