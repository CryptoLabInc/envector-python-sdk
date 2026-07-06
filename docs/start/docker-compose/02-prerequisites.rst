Prerequisites
================================================

This guide covers all the prerequisites needed to run enVector Self-Hosted using Docker Compose.

Server Requirements
-----------------------

System Requirements
~~~~~~~~~~~~~~~~~~~~~~~~
- **Operating System**: Linux Ubuntu 24.04
- **RAM**: 64GB minimum
- **CPU**: 16 cores minimum
- **Storage**: 50GB free disk space
- **Network**: Internet connection for downloading Docker images

Recommended Server Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- **RAM**: 64GB or more
- **CPU**: 16 cores or more
- **Storage**: 50GB free disk space
- **GPU**: Optional, for accelerated vector processing

Note:
- Storage requirements may vary based on your data size and indexing. Please refer `Storage Issues <06-troubleshooting.html#storage_issues>`_ in :doc:`06-troubleshooting` for more details.


Server Software Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Docker Engine
^^^^^^^^^^^^^^^^^^^^^^^^^^

Installation by Platform:

Ubuntu/Debian
""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   # Update package index
   sudo apt-get update

   # Install prerequisites
   sudo apt-get install \
       apt-transport-https \
       ca-certificates \
       curl \
       gnupg \
       lsb-release

   # Add Docker's official GPG key
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

   # Set up stable repository
   echo \
     "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
     $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

   # Install Docker Engine
   sudo apt-get update
   sudo apt-get install docker-ce docker-ce-cli containerd.io

   # Add user to docker group
   sudo usermod -aG docker $USER

2. Docker Compose
^^^^^^^^^^^^^^^^^^^^^

**Docker Compose v2.0+ is included with Docker Desktop**

To verify installation:

.. code-block:: bash

   docker --version
   docker compose version

Server Verification Steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Verify Docker Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check Docker version
   docker --version

   # Check Docker Compose version
   docker compose version

   # Test Docker with hello-world
   docker run hello-world

2. Verify Server Resources
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check available resources
   free -h
   nproc
   df -h

3. Verify Network Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Test network connectivity
   ping 8.8.8.8

   # Test Docker Hub access
   docker pull hello-world

Client Requirements
-----------------------

Client System Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- **Operating System**: Linux Ubuntu 24.04 (only)
- **RAM**: 8GB minimum (for SDK and notebooks)
- **CPU**: 4 cores minimum
- **Storage**: 10GB free disk space
- **Network**: Connection to enVector server

Client Software Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Python Environment
^^^^^^^^^^^^^^^^^^^^^^^^

**Python 3.12 is required for the SDK and notebooks**

Ubuntu/Debian
""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   # Install Python 3.12
   sudo apt-get update
   sudo apt-get install python3.12 python3.12-pip python3.12-venv

   # Create virtual environment
   python3.12 -m venv pyenvector-env
   source pyenvector-env/bin/activate

MacOS
""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   brew install virtualenv python@3.12 libomp
   virtualenv -p python3.12 es2_venv
   source es2_venv/bin/activate


2. Jupyter Notebook
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Install Jupyter
   pip install jupyter notebook

   # Or install with all dependencies
   pip install jupyter notebook pandas numpy matplotlib

3. enVector SDK
^^^^^^^^^^^^^^

The enVector SDK wheel file will be provided separately.
The file can be found in `pyenvector-deployment <https://github.com/CryptoLabInc/pyenvector-deployment/tree/release/v1.0>`_ repository.

Ubuntu/Debian
""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   # Install SDK from the provided wheel file
   pip install pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl

MacOS
""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   # Install SDK from the provided wheel file
   pip install pyenvector-1.0.0-cp312-cp312-macosx_11_0_arm64.whl

Client Verification Steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Verify Python Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Check Python version (should be 3.12)
   python --version
   # or
   python3 --version

   # Check pip version
   pip --version

2. Verify Jupyter Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Jupyter Notebook is required for running examples. This is not required for the SDK itself, but is useful for testing and development.

.. code-block:: bash

   # Check Jupyter version
   jupyter --version

   # Test Jupyter
   jupyter notebook --version

3. Verify SDK Installation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Test SDK import
   python -c "import pyenvector as ev; print('SDK installed successfully')"

   # Check SDK version
   python -c "import pyenvector as ev; print(ev.__version__)"

Pre-flight Checklist
--------------------------

Server Checklist
~~~~~~~~~~~~~~~~~~~~~

Before starting the server deployment, verify:

- [ ] Docker Engine is running
- [ ] Docker Compose is available
- [ ] 64GB+ RAM is available
- [ ] 50GB+ free disk space
- [ ] Internet connection is stable
- [ ] Docker Hub access is working

Client Checklist
~~~~~~~~~~~~~~~~~~~~~

Before starting the client setup, verify:

- [ ] Python 3.12 is installed
- [ ] enVector SDK is installed
- [ ] 8GB+ RAM is available
- [ ] 10GB+ free disk space
- [ ] Network connection to enVector server is available
- [ ] Jupyter Notebook is installed (for running examples)

Troubleshooting
---------------------

Server Issues
~~~~~~~~~~~~~~~~

**Docker daemon not running:**

.. code-block:: bash

   # Ubuntu
   sudo systemctl start docker
   sudo systemctl enable docker

**Permission denied:**

.. code-block:: bash

   # Add user to docker group
   sudo usermod -aG docker $USER
   # Log out and log back in

**Insufficient resources:**

.. code-block:: bash

   # Check available resources
   free -h
   nproc
   df -h

Client Issues
~~~~~~~~~~~~~~~~

**Python not found:**

.. code-block:: bash

   # Check available Python versions
   python3 --version
   python3.12 --version

   # Create alias if needed
   alias python=python3

**Pip not found:**

.. code-block:: bash

   # Install pip
   sudo apt-get install python3-pip  # Ubuntu

**Jupyter not found:**

.. code-block:: bash

   # Install Jupyter
   pip install jupyter notebook

   # Or use conda
   conda install jupyter notebook

**SDK import error:**

.. code-block:: bash

   # Reinstall SDK
   pip uninstall pyenvector
   pip install pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl

   # Check installation
   pip list | grep pyenvector

Performance Optimization
---------------------------

Server Optimization
~~~~~~~~~~~~~~~~~~~~~~~

**Linux (Ubuntu 24.04):**

1. Check system resources
2. Ensure Docker has sufficient resources
3. Allocate at least 64GB RAM and 16 CPU cores

**Linux:**

.. code-block:: bash

   # Check available resources
   free -h
   nproc

Client Optimization
~~~~~~~~~~~~~~~~~~~~~~

**For better SDK performance:**

.. code-block:: bash

   # Install additional dependencies
   pip install numpy pandas matplotlib

   # Set environment variables for better performance
   export PYTHONPATH="${PYTHONPATH}:/path/to/pyenvector-sdk"

Network Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Test network connectivity
   ping 8.8.8.8

   # Test Docker Hub access (server only)
   docker pull hello-world

   # Test connection to enVector server (client only)
   curl http://localhost:50050/health

Next Steps
-------------

Server Setup
~~~~~~~~~~~~~~

Once server prerequisites are verified, proceed to:

1. :doc:`03-docker-setup` - Configure Docker environment
2. :doc:`04-service-deployment` - Deploy enVector services

Client Setup
~~~~~~~~~~~~~~

Once client prerequisites are verified, proceed to:

1. :doc:`05-sdk-installation` - Install and configure SDK
2. `examples/quick-start <../../examples/00-quick-start.html>`_ - Quick start with encrypted vector search
3. `examples/api-flow <../../examples/01-api-flow.html>`_ - Understand enVector API flow and usage
4. `examples/rag-demo <../../examples/02-encrypted-rag.html>`_ - Test RAG functionality

Support
----------

If you encounter issues with prerequisites:

- **Docker Issues**: `Docker Documentation <https://docs.docker.com/>`_
- **Python Issues**: `Python Documentation <https://docs.python.org/>`_
- **Jupyter Issues**: `Jupyter Documentation <https://jupyter.org/documentation>`_
- **enVector Issues**: `enVector Repository Issues <https://github.com/cryptolab/pyenvector-msa/issues>`_
