#!/bin/bash

# Default environment variables
export TOPK=${TOPK:-2}
export ENVECTOR_ENDPOINT_HOST_PORT=${ENVECTOR_ENDPOINT_HOST_PORT:-50050}

# Get test_type from arguments or set default
test_type=${1:-"nightly"}

# Run tests
run_test() {
  local test_name=$1
  local fail_file="$test_name.fail"

  echo "Running $test_name test with test_type=$test_type..."
  python qa-test.py \
    --test_name $test_name \
    --top_k $TOPK \
    --port $ENVECTOR_ENDPOINT_HOST_PORT \
    --test_type $test_type || echo "fail" > $fail_file
}

# Execute all tests
run_test core
run_test latency
run_test scalability
run_test consistency

# Check results
if ls ./*.fail 1> /dev/null 2>&1; then
  echo "Some tests failed:"
  cat ./*.fail
  exit 1
else
  echo "All tests passed."
fi
