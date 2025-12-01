#!/bin/bash

EXAMPLE_DIR="$(dirname "$0")/../example"
PORT=50050  # Default port

# Ensure scikit-learn is installed
pip install --quiet scikit-learn pandas

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find all Python files in the example directory, excluding utils.py
python_files=$(find "$EXAMPLE_DIR" -name "*.py" ! -name "utils.py" | sort)

# Ensure init.py runs first if it exists
init_file=$(find "$EXAMPLE_DIR/client_and_server" -name "init.py")
if [[ -n "$init_file" ]]; then
    relative_path="${init_file#$EXAMPLE_DIR/}"
    echo "Running $relative_path..."
    python "$init_file" --port "$PORT"
    if [ $? -ne 0 ]; then
        echo "Error running $relative_path"
        exit 1
    fi
    echo
    # Remove init.py from the list to avoid running it again
    python_files=$(echo "$python_files" | grep -v "$init_file")
fi

# Execute remaining Python files
for py_file in $python_files; do
    relative_path="${py_file#$EXAMPLE_DIR/}"
    echo "Running $relative_path..."
    if [[ "$py_file" == *"client_and_server"* ]]; then
        python "$py_file" --port "$PORT"
    else
        python "$py_file"
    fi
    if [ $? -ne 0 ]; then
        echo "Error running $relative_path"
        exit 1
    fi
    echo
done
