# pyenvector — enVector Python SDK

Python SDK for [enVector](https://envector.io) — encrypted vector search powered by fully homomorphic encryption (FHE).

Your vectors and similarity scores stay encrypted during the entire computation. The server never sees plaintext data.

## Install

```bash
pip install pyenvector
```

## Quick Start

```python
import numpy as np
import pyenvector as ev

# Connect and load keys
ev.init(host="localhost", port=50050, key_path="./keys", key_id="my_key")

# Create an index
index = ev.create_index("my_index", dim=512)

# Insert vectors
vectors = np.random.randn(100, 512).astype(np.float32)
vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
metadata = [f"item_{i}" for i in range(100)]

index.insert(vectors, metadata=metadata)

# Search (encrypted end-to-end)
result = index.search(vectors[0], top_k=5, output_fields=["metadata"])
print(result)

# Clean up
ev.drop_index("my_index")
# ev.delete_key("my_key")  # optional: remove keys from server
```

## Key Features

- **End-to-end encryption** — vectors are encrypted on the client. Search runs on ciphertext via FHE. Scores are decrypted only on the client.
- **Familiar API** — `create_index`, `insert`, `search`, `drop_index`. Works like Milvus or Pinecone.
- **Key management CLI** — generate, seal, and upload HE keys to AWS S3 or GCP Cloud Storage.
- **Cloud-ready** — deploy the enVector server on GKE, EKS, or on-prem.

## Documentation

- [enVector Docs](https://docs.envector.io) — deployment, architecture, API reference
- [GitHub](https://github.com/CryptoLabInc/envector-python-sdk) — source, examples, issues

## License

Proprietary. See [LICENSE](https://github.com/CryptoLabInc/envector-python-sdk/blob/main/LICENSE) for details.
