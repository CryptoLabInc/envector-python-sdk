# What is enVector?
enVector is a high-performance encrypted vector search service that keeps both your vectors and similarity scores private during computation. The `pyenvector` Python SDK lets you talk to the enVector server from Python while keeping all sensitive data encrypted end to end.

# pyenvector Example

This example walks through the typical pyenvector workflow for encrypted similarity search and vector database operations.

---

## Install and Import

Install the SDK and import it as `ev` for brevity.

```bash
pip install pyenvector
```

```python
import pyenvector as ev
```

---

## 🔍 Vector Search

### 1. Initialize enVector

Set up the connection to the enVector server and configure your key material.

```python
ev.init(
    host="localhost",
    port=50050,
    key_path="./keys",
    key_id="quickstart_key",
)
```

---

### 2. Create Index

Create an index before inserting data. Define the index name and vector dimensionality.

```python
index = ev.create_index("quickstart_index", dim=512)
```

---

### 3. Insert Data

Insert vectors into the index. The snippet below generates random 512-dimensional vectors with normalization and metadata.

```python
import numpy as np

# Function to generate normalized random vectors
def generate_random_vector(dim):
    if dim < 32 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}.")

    vec = np.random.uniform(-1.0, 1.0, dim)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec = vec / norm

    return vec

# Prepare sample data
num_data = 10
db_vectors = [generate_random_vector(512) for _ in range(num_data)]
db_metadata = [f"data_{i+1}" for i in range(num_data)]

# Insert into index
index.insert(db_vectors, metadata=db_metadata)
```

---

### 4. Encrypted Similarity Search

Query the index and retrieve encrypted similarity scores that are decrypted on the client side.

```python
query = db_vectors[1]
top_k = 2

result = index.search(query, top_k=top_k, output_fields=["metadata"])
print(result)
```

---

## 🧹 Clean Up

Remove test data and release keys when you are done.

```python
ev.drop_index("quickstart_index")
ev.delete_key("quickstart_key")
```
