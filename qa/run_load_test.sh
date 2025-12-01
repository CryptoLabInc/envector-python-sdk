#!/bin/bash

# ==============================================================================
# ES2 Load Test Scenario Runner Script (Latest Version)
# This script selects a scenario by using the --test_type argument of the Python script.
#
# USAGE:
#   ./run_scenarios.sh <scenario_name> [options]
#
# EXAMPLES:
#   ./run_scenarios.sh baseline
#   ./run_scenarios.sh stress --port 50051
#   ./run_scenarios.sh long_run
#   ./run_scenarios.sh all
# ==============================================================================

# --- Common Parameters ---
PYTHON_SCRIPT="load-test.py" # Python script filename
PORT=50050                 # Default port
DEFAULT_DURATION=60          # Default test duration
DEFAULT_DIM=512              # Default vector dimension

# --- Parse Command-Line Arguments ---
if [ $# -eq 0 ]; then
  echo "Error: Please provide a scenario name to run."
  echo "Usage: $0 {baseline|stress|data_scaling|long_run|all}"
  exit 1
fi

SCENARIO_TO_RUN=$1
shift # Remove the first argument (the scenario name)

# Parse remaining arguments like --port, --duration, --dim
# (The Python script handles these directly, so no special parsing is needed here)
EXTRA_ARGS="$@"


# --- Function Definition: Run a Scenario ---
run_scenario() {
  local test_type=$1
  # Pass additional arguments into the function
  local additional_args=${@:2}

  echo ""
  echo "======================================================================"
  echo "🚀 Running Scenario: ${test_type}"
  echo "======================================================================"

  # Execute the Python script
  # Additional args ($additional_args) are passed for --port, --duration, etc.
  python ${PYTHON_SCRIPT} \
    --test_type ${test_type} \
    ${additional_args}

  echo "✅ Finished Scenario: ${test_type}"
  echo "======================================================================"
  echo ""
  sleep 5 # Wait a moment before the next test
}


# --- Select and Run Scenario ---

case "$SCENARIO_TO_RUN" in
  "baseline")
    run_scenario "baseline" ${EXTRA_ARGS}
    ;;

  "stress")
    run_scenario "stress" ${EXTRA_ARGS}
    ;;

  "data_scaling")
    run_scenario "data_scaling" ${EXTRA_ARGS}
    ;;

  "long_run")
    run_scenario "long_run" ${EXTRA_ARGS}
    ;;

  "all")
    echo "🔥 Running all scenarios sequentially..."
    run_scenario "baseline" ${EXTRA_ARGS}
    run_scenario "data_scaling" ${EXTRA_ARGS}
    run_scenario "stress" ${EXTRA_ARGS}
    run_scenario "long_run" ${EXTRA_ARGS}
    ;;

  *)
    echo "Error: Unknown scenario name: '$SCENARIO_TO_RUN'"
    echo "Available scenarios: {baseline|stress|data_scaling|long_run|all}"
    exit 1
    ;;
esac

echo "All requested scenarios have been completed."

# Consolidate all CSV results into a single TXT file
CONSOLIDATED_RESULTS="consolidated_results.txt"
echo "Consolidating all results into ${CONSOLIDATED_RESULTS}..."
> $CONSOLIDATED_RESULTS # Clear the file if it exists
for csv_file in *.csv; do
  echo "Processing $csv_file..." >> $CONSOLIDATED_RESULTS
  echo "---" >> $CONSOLIDATED_RESULTS
  cat $csv_file >> $CONSOLIDATED_RESULTS
  echo "\n" >> $CONSOLIDATED_RESULTS

done

echo "All results have been consolidated into ${CONSOLIDATED_RESULTS}."
