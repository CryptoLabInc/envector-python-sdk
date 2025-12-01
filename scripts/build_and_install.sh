#!/usr/bin/env bash
set -e

# Parse input arguments first
TYPE="install"  # Default to install
MACOSX_TARGET="11.0"  # Default macOS deployment target

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
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Detect platform
platform="$(uname)"
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

# Export for pip/scikit-build-core
export CMAKE_ARGS="$cmake_args"

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
