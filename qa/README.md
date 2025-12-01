# enVector QA Tests

### Requirements

**Ubuntu**
- OS: Ubuntu 22.04+
- Shell: bash
- Python: 3.12 (recommended)
- Virtual Environment: pipenv

**Mac**
- OS: macOS Sequoia 15.5+
- Shell: zsh
- Package Manager: Homebrew
- Python: 3.12 (recommended)
- Virtual Environment: pipenv


### 1. SetUp Pipenv
```bash
# 1. make virtual environment directory
mkdir .venv

# 2. make new virtual environment python 3.12
pipenv --python 3.12

# 3. set pipenv to use the virtual environment directory
pipenv shell

# 4. install whl file, pandas
pip install /path/to/whl/file/dist/pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl
pip install --extra-index-url=https://pypi.nvidia.com \
  cuml-cu12 cudf-cu12 libcuml-cu12
```

### How to Run Test
```bash
python3 qa-test.py --test_name core --top_k 2 --port 50050
```

### How to Run Load Test
```bash
python3 load-test.py --num_data 1000000 --dim 1536 --port 50050 --result_file_path result_load.csv
```

### How to Run PCMM-ANN Test
```bash
python3 pcmm-ann-test.py --num_vectors 1000000 --dim 1536 --n_lists 250 --n_probes 6 --num_queries 100 --top_k 10 --port 50050 --host 0.0.0.0
```

#### qa-test Options
- `--test_name`: Name of the test to run (e.g., `core`, `latency` `scalability`, `consistency`)
- `--num_data`: Number of data points to insert into the index (default: 100) # temporary not used options
- `--test_idx`: Index of the test query to use (default: 50) # temporary not used options
- `--dim`: Dimension of the vectors (default: 512) # temporary not used options
- `--top_k`: Number of top results to return (default: 2)
- `--port`: Port number for the enVector endpoint service (default: 50050)
- `--result_file_path`: Path to save the results (default: `result_core.csv` for core test, `result_latency.csv` for latency test, etc.)

#### load-test Options
- `--num_data`: Number of data points to insert into the index (default: 1000000)
- `--dim`: Dimension of the vectors (default: 1536)
- `--port`: Port number for the enVector endpoint service (default: 50050)
- `--result_file_path`: Path to save the results (default: `result_load.csv`)

#### pcmm-ann-test Options
- `--num_vectors`: Number of vectors in dataset (default: 1000000)
- `--dim`: Dimension of each vector (default: 1536)
- `--n_lists`: Number of IVF clusters (nlist, default: 250)
- `--n_probes`: Number of probes for search (default: 6)
- `--num_queries`: Number of queries for QPS/latency test (default: 100)
- `--top_k`: Top K for search (default: 10)
- `--port`: Port number for the enVector endpoint service (default: 50050)
- `--host`: enVector server host (default: 0.0.0.0)
- `--random_centroid`: Generate Centroid on server side
- `--eval_mode`: Evaluation Mode (default: rmp)
````
