#!/usr/bin/env bash
#
# Build pyenvector wheel artifacts and/or package them into a runtime image.
#
# Usage:
#   ./scripts/build_docker.sh [--tag <tag>] [--python <3.11|3.12|3.13>]
#                             [--image <name>]
#                             [--target-arch amd64|arm64|multiarch]
#                             [--action load|push]
#                             [--builder <buildx-builder-name>]
#                             [--wheel-only]
#                             [--wheelhouse <path>]
#                             [--no-cache]
#
# Defaults:
#   image        pyenvector
#   tag          value of WHEEL_VERSION (or pyproject version) or 'dev'
#   python       3.12
#   target-arch  amd64
#   action       load (single arch) / push (multiarch -- required)
#   builder      pyenvector-builder (auto-created if missing)
#   wheelhouse   sdk/python/dist/sdk-wheel-house/<tag>-py<python>
#
# By default the helper runs a two-phase flow:
#   1. build audited wheels from source via sdk/python/docker/buildpack
#   2. package only the prebuilt wheelhouse via sdk/python/docker/dockerize
#
# Use --wheel-only to stop after artifact generation, or --wheelhouse <path> to
# package an existing wheelhouse without reading the private source tree.
#
# Cross-arch builds bootstrap qemu/binfmt on first use via tonistiigi/binfmt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SDK_DOCKER_DIR="${SDK_DIR}/docker"
WHEEL_BUILDER_DOCKERFILE="${SDK_DOCKER_DIR}/buildpack/Dockerfile"
RUNTIME_DOCKERFILE="${SDK_DOCKER_DIR}/dockerize/Dockerfile"

IMAGE_NAME="pyenvector"
TAG=""
PYTHON_VERSION="3.12"
TARGET_ARCH="amd64"
ACTION=""
BUILDER_NAME="pyenvector-builder"
NO_CACHE=""
WHEEL_ONLY="false"
WHEELHOUSE_INPUT=""
WHEELHOUSE_DIR=""

resolve_path_from_pwd() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s\n' "$(pwd)/$path"
  fi
}

require_wheels_for_arch() {
  local arch="$1"
  local arch_dir="${WHEELHOUSE_DIR}/${arch}"
  local wheel_count=""

  if [[ ! -d "${arch_dir}" ]]; then
    echo "[ERROR] Missing wheel directory: ${arch_dir}" >&2
    exit 1
  fi

  wheel_count="$(find "${arch_dir}" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
  if [[ "${wheel_count}" == "0" ]]; then
    echo "[ERROR] No wheel artifacts found in ${arch_dir}" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)         TAG="$2"; shift 2 ;;
    --python)      PYTHON_VERSION="$2"; shift 2 ;;
    --image)       IMAGE_NAME="$2"; shift 2 ;;
    --target-arch) TARGET_ARCH="$2"; shift 2 ;;
    --action)      ACTION="$2"; shift 2 ;;
    --builder)     BUILDER_NAME="$2"; shift 2 ;;
    --wheel-only)  WHEEL_ONLY="true"; shift ;;
    --wheelhouse)  WHEELHOUSE_INPUT="$2"; shift 2 ;;
    --no-cache)    NO_CACHE="--no-cache"; shift ;;
    -h|--help)
      awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' \
        "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Resolve action defaults & guard invalid combinations.
case "$TARGET_ARCH" in
  amd64|arm64)
    ACTION="${ACTION:-load}"
    PLATFORM="linux/${TARGET_ARCH}"
    PACKAGE_ARCHES=("${TARGET_ARCH}")
    ;;
  multiarch)
    ACTION="${ACTION:-push}"
    PLATFORM="linux/amd64,linux/arm64"
    PACKAGE_ARCHES=(amd64 arm64)
    if [[ "$ACTION" == "load" ]]; then
      echo "[ERROR] --target-arch multiarch does not support --action load." >&2
      echo "        docker cannot load a multi-platform manifest into the local daemon." >&2
      echo "        Use --action push or build a single arch." >&2
      exit 1
    fi
    ;;
  *)
    echo "[ERROR] Invalid --target-arch: $TARGET_ARCH (expected amd64|arm64|multiarch)" >&2
    exit 1
    ;;
esac

case "$ACTION" in
  load|push) : ;;
  *) echo "[ERROR] Invalid --action: $ACTION (expected load|push)" >&2; exit 1 ;;
esac

if [[ "$WHEEL_ONLY" == "true" && -n "$WHEELHOUSE_INPUT" ]]; then
  echo "[ERROR] --wheel-only cannot be combined with --wheelhouse." >&2
  exit 1
fi

PYTHON_TAG="cp${PYTHON_VERSION//./}"

# Resolve tag: --tag > WHEEL_VERSION > pyproject version > 'dev'
if [[ -z "$TAG" ]]; then
  if [[ -n "${WHEEL_VERSION:-}" ]]; then
    TAG="$WHEEL_VERSION"
  elif [[ -f "${SDK_DIR}/pyproject.toml" ]]; then
    TAG="$(grep -E '^version[[:space:]]*=' "${SDK_DIR}/pyproject.toml" \
           | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
  fi
  TAG="${TAG:-dev}"
fi

if [[ -n "${WHEELHOUSE_INPUT}" ]]; then
  WHEELHOUSE_DIR="$(resolve_path_from_pwd "${WHEELHOUSE_INPUT}")"
else
  WHEELHOUSE_DIR="${SDK_DIR}/dist/sdk-wheel-house/${TAG}-py${PYTHON_VERSION//./}"
fi

# Tagging: multiarch uses a single tag; single-arch appends the arch to avoid
# overwriting a sibling arch image in the local daemon.
if [[ "$TARGET_ARCH" == "multiarch" ]]; then
  PRIMARY_TAG="${IMAGE_NAME}:${TAG}"
  SECONDARY_TAG="${IMAGE_NAME}:${TAG}-py${PYTHON_VERSION//./}"
else
  PRIMARY_TAG="${IMAGE_NAME}:${TAG}-${TARGET_ARCH}"
  SECONDARY_TAG="${IMAGE_NAME}:${TAG}-py${PYTHON_VERSION//./}-${TARGET_ARCH}"
fi

# Ensure buildx + a container-driver builder (needed for multi-platform).
if ! docker buildx version >/dev/null 2>&1; then
  echo "[ERROR] docker buildx is not available. Install Docker 19.03+ with buildx." >&2
  exit 1
fi

if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "[INFO] Creating buildx builder: ${BUILDER_NAME}"
  docker buildx create --name "${BUILDER_NAME}" --driver docker-container --bootstrap >/dev/null
fi
docker buildx use "${BUILDER_NAME}"

# Bootstrap qemu for cross-arch emulation (idempotent).
if [[ "$TARGET_ARCH" == "multiarch" || "$TARGET_ARCH" != "$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" ]]; then
  echo "[INFO] Ensuring qemu/binfmt is registered for cross-arch builds"
  if ! docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null; then
    echo "[WARN] Failed to register qemu/binfmt. Cross-arch builds may fail later." >&2
    echo "[WARN] If they do, re-run with privileged Docker access or pre-configure binfmt on the host." >&2
  fi
fi

if [[ -z "${WHEELHOUSE_INPUT}" ]]; then
  if [[ ! -f "${SDK_DIR}/external/evi-crypto/CMakeLists.txt" ]]; then
    echo "[ERROR] external/evi-crypto is empty. Run:" >&2
    echo "          git -C $(dirname "${SDK_DIR}") submodule update --init --recursive" >&2
    exit 1
  fi

  rm -rf "${WHEELHOUSE_DIR}"
  mkdir -p "${WHEELHOUSE_DIR}"

  echo "[INFO] Building pyenvector wheel artifacts"
  echo "[INFO]   source        = ${SDK_DIR}"
  echo "[INFO]   wheelhouse    = ${WHEELHOUSE_DIR}"
  echo "[INFO]   python        = ${PYTHON_VERSION} (${PYTHON_TAG})"
  echo "[INFO]   arches        = ${PACKAGE_ARCHES[*]}"
  echo "[INFO]   builder       = ${BUILDER_NAME}"

  for arch in "${PACKAGE_ARCHES[@]}"; do
    arch_dir="${WHEELHOUSE_DIR}/${arch}"
    mkdir -p "${arch_dir}"
    echo "[INFO]   -> wheel ${arch} (${PYTHON_TAG})"
    docker buildx build ${NO_CACHE} \
      --platform "linux/${arch}" \
      --build-arg "PYTHON_VERSION=${PYTHON_VERSION}" \
      --build-arg "PYTHON_TAG=${PYTHON_TAG}" \
      --target wheelhouse \
      --output "type=local,dest=${arch_dir}" \
      -f "${WHEEL_BUILDER_DOCKERFILE}" \
      "${SDK_DIR}"
    require_wheels_for_arch "${arch}"
  done
else
  echo "[INFO] Using existing wheelhouse: ${WHEELHOUSE_DIR}"
  for arch in "${PACKAGE_ARCHES[@]}"; do
    require_wheels_for_arch "${arch}"
  done
fi

if [[ "${WHEEL_ONLY}" == "true" ]]; then
  echo "[INFO] Wheel-only mode complete."
  exit 0
fi

echo "[INFO] Packaging ${PRIMARY_TAG}"
echo "[INFO]   context       = ${WHEELHOUSE_DIR}"
echo "[INFO]   dockerfile    = ${RUNTIME_DOCKERFILE}"
echo "[INFO]   python        = ${PYTHON_VERSION}"
echo "[INFO]   target-arch   = ${TARGET_ARCH}"
echo "[INFO]   platform      = ${PLATFORM}"
echo "[INFO]   action        = ${ACTION}"
echo "[INFO]   builder       = ${BUILDER_NAME}"

docker buildx build ${NO_CACHE} \
  --platform "${PLATFORM}" \
  --build-arg "PYTHON_VERSION=${PYTHON_VERSION}" \
  -t "${PRIMARY_TAG}" \
  -t "${SECONDARY_TAG}" \
  -f "${RUNTIME_DOCKERFILE}" \
  "--${ACTION}" \
  "${WHEELHOUSE_DIR}"

echo "[INFO] Built ${PRIMARY_TAG} and ${SECONDARY_TAG}"

# Smoke test only possible when the image is in the local daemon (action=load).
if [[ "$ACTION" == "load" ]]; then
  IMAGE_SIZE="$(docker inspect "${PRIMARY_TAG}" -f '{{.Size}}' \
                | awk '{ printf "%.2f MB\n", $1/1024/1024 }')"
  echo "[INFO] Image size: ${IMAGE_SIZE}"
  echo "[INFO] Smoke test: import pyenvector"
  docker run --rm --platform "${PLATFORM}" "${PRIMARY_TAG}"
else
  echo "[INFO] Skipping smoke test (--action push pushed the manifest to the registry)."
fi
