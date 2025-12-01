#!/usr/bin/env bash

set -euo pipefail

echo "Running wheel validation..."

usage() {
  echo "Usage: $0 [cpXY ... | 3.Y ...]" >&2
  echo "Examples:" >&2
  echo "  $0 cp312" >&2
  echo "  $0 cp39 cp310 cp311 cp312 cp313" >&2
  echo "  $0 3.12 3.11" >&2
  echo >&2
  echo "Env/flags:" >&2
  echo "  WHEEL_DIR=<dir>   Directory containing wheels (default: all-dist)" >&2
}

# Parse args -> cp tags
declare -a py_tags
if [ "$#" -gt 0 ]; then
  for arg in "$@"; do
    if [[ "$arg" =~ ^cp[0-9]{2,3}$ ]]; then
      py_tags+=("$arg")
    elif [[ "$arg" =~ ^3\.([0-9]{1,2})$ ]]; then
      minor="${BASH_REMATCH[1]}"
      if [ "$minor" -lt 10 ]; then
        py_tags+=("cp3${minor}")
      else
        py_tags+=("cp3${minor}")
      fi
    else
      echo "::error::Unrecognized Python version token: '$arg'" >&2
      usage
      exit 2
    fi
  done
else
  # Default to all supported tags if none provided
  py_tags=(cp39 cp310 cp311 cp312 cp313)
fi

echo "Validating for tags: ${py_tags[*]}"

# Determine wheel directory (can be overridden via WHEEL_DIR)
WHEEL_DIR="${WHEEL_DIR:-all-dist}"
echo "Using wheel directory: ${WHEEL_DIR}"

# check wheel directory
if [ ! -d "${WHEEL_DIR}" ]; then
  echo "::error::'${WHEEL_DIR}' directory not found. Please ensure artifacts are downloaded correctly."
  exit 1
fi
ls -lh "${WHEEL_DIR}" || true

missing=0
for v in "${py_tags[@]}"; do
  # check manylinux wheel
  if ! compgen -G "${WHEEL_DIR}/*-${v}-*-manylinux_*_x86_64.whl" >/dev/null; then
    echo "::error::Missing manylinux wheel for ${v}"
    missing=1
  fi
  # check macOS wheel
  if ! compgen -G "${WHEEL_DIR}/*-${v}-*-macosx_*_arm64.whl" >/dev/null && \
     ! compgen -G "${WHEEL_DIR}/*-${v}-*-macosx_*_universal2.whl" >/dev/null; then
    echo "::error::Missing macOS wheel for ${v} (arm64/universal2)"
    missing=1
  fi
done

if [ -n "${WHEEL_VERSION:-}" ]; then
  normalized_version="$(printf '%s\n' "${WHEEL_VERSION}" | sed -E 's/-rc\.?([0-9]+)/rc\1/g')"
  versions_to_check=("${WHEEL_VERSION}")
  if [ "${normalized_version}" != "${WHEEL_VERSION}" ]; then
    versions_to_check+=("${normalized_version}")
  fi

  found=0
  for version in "${versions_to_check[@]}"; do
    if ls "${WHEEL_DIR}"/*"${version}"*.whl >/dev/null 2>&1; then
      found=1
      break
    fi
  done

  if [ "${found}" -eq 0 ]; then
    echo "::error::No wheel contains version '${WHEEL_VERSION}' (checked: ${versions_to_check[*]})"
    ls -1 "${WHEEL_DIR}" || true
    exit 1
  fi
fi

if [ "$missing" -ne 0 ]; then
  echo "❌ Some required wheels are missing. Failing the job."
  echo "Found files:"; ls -1 "${WHEEL_DIR}" || true
  exit 1
fi

echo "✅ Required wheels present for: ${py_tags[*]}"
