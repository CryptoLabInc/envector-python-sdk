#!/usr/bin/env bash
set -e

# Parse input arguments first
TYPE="install"  # Default to install
MACOSX_TARGET="11.0"  # Default macOS deployment target
JOBS=""

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --type)
      TYPE="$2"
      shift 2
      ;;
    --macosx-target)
      MACOSX_TARGET="$2"
      shift 2
      ;;
    -j|--jobs)
      if [[ $# -lt 2 ]]; then
        echo "Option $1 requires a positive integer value."
        exit 1
      fi
      if ! is_positive_integer "$2"; then
        echo "Invalid jobs value: $2. Expected a positive integer."
        exit 1
      fi
      JOBS="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Detect platform
platform="$(uname)"
base_cmake_args="${CMAKE_ARGS:-}"
cmake_args="-DBUILD_PYTHON=ON"

# Platform-specific tweaks
if [[ "$platform" == "Darwin" ]]; then
  echo "Detected macOS"
  echo "Setting macOS deployment target to: $MACOSX_TARGET"
  # Set minimum macOS deployment target for Apple Silicon compatibility
  export MACOSX_DEPLOYMENT_TARGET="$MACOSX_TARGET"
  cmake_args+=" \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=$MACOSX_TARGET \
    -DCMAKE_C_COMPILER=/usr/bin/clang \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
    -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
    -DOpenMP_CXX_FLAGS='-Xpreprocessor -fopenmp -I/opt/homebrew/opt/libomp/include' \
    -DOpenMP_CXX_LIB_NAMES=omp \
    -DOpenMP_omp_LIBRARY=/opt/homebrew/opt/libomp/lib/libomp.dylib"
else
  echo "Detected Linux or other Unix"
fi

# Preserve externally provided CMake args (e.g., CI overrides) and append
# package defaults.
if [[ -n "$base_cmake_args" ]]; then
  cmake_args="$base_cmake_args $cmake_args"
fi

cmake_args+=" -DEVI_KM_PREFER_AWS_SDK=OFF -DEVI_KM_PREFER_GCP_SDK=OFF"

# Pin CMake to the active Python so it does not pick up a stale toolcache binary
PYTHON_EXE="$(command -v python3 || command -v python)"
if [[ -n "$PYTHON_EXE" ]]; then
  cmake_args+=" -DPython3_EXECUTABLE=$PYTHON_EXE -DPython_EXECUTABLE=$PYTHON_EXE"
fi

# Export for pip/scikit-build-core
export CMAKE_ARGS="${CMAKE_ARGS:-} $cmake_args"
if [[ -n "$JOBS" ]]; then
  export CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"
  echo "Using parallel build jobs: $CMAKE_BUILD_PARALLEL_LEVEL"
fi

if [[ "$TYPE" == "wheel" ]]; then
  echo "Building wheel with CMAKE_ARGS:"
  echo "$CMAKE_ARGS"
  pip wheel --no-deps . -w dist -v
elif [[ "$TYPE" == "install" ]]; then
  echo "Installing package with CMAKE_ARGS:"
  cd ./external/evi-crypto
  echo "$CMAKE_ARGS"
  pip install . -v
else
  echo "Unknown type: $TYPE"
  exit 1
fi
