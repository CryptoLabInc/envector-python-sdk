Overview
===============

Introduction
-----------------

Welcome to the enVector Self-Hosted 1.0 guide! This simplified version allows you to deploy and test CryptoLab's encrypted vector search solution locally using Docker Compose.

**enVector (Encrypted Similarity Search)** is a privacy-preserving vector search solution that enables secure similarity search over encrypted data without ever decrypting the vectors on the server side.

What You'll Learn
-----------------------

By completing this guide, you will:

- **Deploy enVector Self-Hosted** locally using Docker Compose
- **Understand the architecture** of encrypted vector search
- **Learn best practices** for secure vector search deployment
- **Complete tutorials** for practical applications:

  - **Encrypted RAG (Retrieval-Augmented Generation)** with encrypted documents
  - **Multi-Modal Search** for text and image data
  - **Encrypted Face Recognition** systems with biometric security

Hands-on Scenarios
-----------------------

1. Encrypted RAG (Retrieval-Augmented Generation) Demo
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Scenario**: Secure document search in enterprise environments

- **Use Case**: Search through confidential company documents
- **Security**: Vector embeddings are encrypted for secure similarity search
- **Search**: Perform similarity search on encrypted vector embeddings
- **Results**: Search results are returned without decrypting the vector embeddings

**What you'll do**:

- Upload documents and generate encrypted vector embeddings
- Perform similarity searches on encrypted vectors
- Verify security preservation of vector data
- Analyze search accuracy

**Demo**:

- `examples/rag-demo <../../examples/02-encrypted-rag.html>`_  - Test RAG functionality with encrypted documents

2. Multi-Modal Search Demo
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Scenario**: Secure search across multiple data types

- **Use Case**: Search through text and image data
- **Security**: All data types are encrypted before storage
- **Search**: Cross-modal similarity search on encrypted data
- **Results**: Unified search results across modalities

**What you'll do**:

- Process and encrypt text and image data
- Perform cross-modal similarity searches
- Verify security across different data types
- Analyze multi-modal search accuracy

**Demo**:

- TBD

3. Encrypted Face Recognition Demo
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Scenario**: Security-preserving biometric authentication

- **Use Case**: Secure face recognition without storing raw biometric data
- **Security**: Face embeddings are encrypted before storage
- **Authentication**: Similarity matching on encrypted face embeddings
- **Results**: Authentication decisions without exposing biometric data

**What you'll do**:

- Generate encrypted face embeddings
- Perform similarity matching on encrypted face data
- Verify security preservation in biometric systems
- Analyze recognition accuracy and security

**Demo**:

- TBD

Architecture Overview
-----------------------------

.. code-block:: text

   ┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
   │   Client SDK    │      │   enVector Endpoint │      │   enVector Backend  │
   │                 │      │                     │      │                     │
   │ • Key Generation│◄───► │ • RESTful/gRPC      │ ◄───►│ • Business Logic    │
   │ • Encryption    │      │                     │      │ • Data Validation   │
   │ • Decryption    │      │                     │      │ • Orchestration     │
   └─────────────────┘      └─────────────────────┘      └─────────────────────┘
                                                                │
                                                                ▼
   ┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
   │  Documentation  │      │   enVector Workers  │      │  enVector Scheduler │
   │                 │      │                     │      │                     │
   │ • API Docs      │      │ • Task Queue        │ ◄───►│ • Resource Mgmt     │
   │ • Config Guides │      │ • EVI Library       │      │                     │
   │ • Examples      │      │ • Vector Search     │      │                     │
   └─────────────────┘      └─────────────────────┘      └─────────────────────┘

Key Components
--------------------

enVector Endpoint
^^^^^^^^^^^^^^^^^^^^^^
- REST/gRPC API server for client interactions
- Request routing and load balancing

enVector Backend
^^^^^^^^^^^^^^^^^^^^^^
- Business logic processing
- Metadata storage and management
- Integration with scheduler and workers

enVector Scheduler
^^^^^^^^^^^^^^^^^^^^^^
- Task scheduling and distribution
- Worker node management
- Resource allocation and monitoring

enVector Workers
^^^^^^^^^^^^^^^^^^^^^^
- CPU or GPU-accelerated vector processing
- EVI (Encrypted Vector Index) library integration
- Encrypted similarity search execution

Documentation
^^^^^^^^^^^^^^^^^^^^^^
- API documentation and examples
- User guides and tutorials
- Configuration guides

Technology Stack
---------------------

- **Containerization**: Docker and Docker Compose
- **Application**: enVector microservices
- **Encryption**: EVI (Encrypted Vector Index) library
- **Vector Processing**: CPU or GPU-accelerated computation
- **API**: RESTful and gRPC services
- **Documentation**: API docs and configuration guides

Prerequisites
---------------------

Before starting this hands-on guide, ensure you have:

- **Docker**: Docker Engine installed and running
- **Docker Compose**: Docker Compose v2.0 or later
- **System Requirements**: 64GB RAM, 16 CPU cores minimum, 50GB free disk space
- **Python**: Python 3.12 for SDK and notebooks

For detailed prerequisites, see :doc:`02-prerequisites`.

Estimated Time and Cost
----------------------------

- **Total Time**: 30-45 minutes
- **Difficulty Level**: Beginner to Intermediate
- **Cost**: Free (local deployment)
- **Platform Support**: Linux Ubuntu 24.04 only

Hands-on Flow
--------------------

1. :doc:`02-prerequisites` - Set up your environment
2. :doc:`03-docker-setup` - Configure Docker environment
3. :doc:`04-service-deployment` - Deploy enVector services
4. :doc:`05-sdk-installation` - Configure client SDK
5. `examples/quick-start <../../examples/00-quick-start.html>`_ - Quick start with encrypted vector search
6. `examples/api-flow <../../examples/01-api-flow.html>`_ - Understand enVector API flow and usage
7. `examples/rag-demo <../../examples/02-encrypted-rag.html>`_ - Test RAG functionality
8. :doc:`06-troubleshooting` - Common issues and solutions

Expected Outcomes
----------------------

After completing this hands-on guide, you will be able to:

- **Deploy enVector Self-Hosted** locally using Docker Compose
- **Understand encrypted vector search** concepts and implementation
- **Implement Encrypted RAG solutions** with security preservation
- **Build Multi-Modal Search systems** for text and image data (TBD)
- **Create Encrypted Face Recognition** systems with biometric security (TBD)

Advantages of Docker Compose Approach
--------------------------------------------

- **Fast Setup**: No cloud infrastructure required
- **Cost Effective**: Free local deployment
- **Simple Management**: Single ``docker-compose.yml`` file
- **Easy Cleanup**: ``docker compose down`` removes everything
- **Development Friendly**: Easy to modify and test

Support and Resources
--------------------------

- **Documentation**: `enVector Self-Hosted Documentation (TBD) <https://xxx>`_
- **GitHub Issues**: `enVector Repository Issues <https://github.com/cryptolab/pyenvector-msa/issues>`_
- **Community**: `CryptoLab Community Forum (TBD) <https://xxx>`_

Next Steps
------------

Ready to get started? Begin with :doc:`02-prerequisites` to set up your environment.
