SDK Installation
=====================

This step installs and configures the enVector SDK for interacting with the deployed services.

Overview
--------

The enVector SDK provides a Python interface for interacting with enVector Self-Hosted services. It handles encryption, key management, and API communication.

Prerequisites
-------------

- enVector services running (from :doc:`04-service-deployment`)
- Python 3.12 installed
- pip package manager


Step 1: Install enVector SDK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You will receive the enVector SDK wheel file directly. Place it in your project directory:

.. code-block:: bash

   # Install SDK from the provided wheel file
   pip install pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl

   # Verify installation
   python -c "import pyenvector as ev; print(ev.__version__)"

Step 2: Test SDK Connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Test SDK installation
   python -c "import pyenvector as ev; ev.init_connect(host='localhost', port=50050); print(ev.is_connected())"

Troubleshooting
---------------

SDK Installation Issues
~~~~~~~~~~~~~~~~~~~~~~~

**Import error:**

.. code-block:: bash

   # Check Python version
   python --version

   # Reinstall SDK
   pip uninstall pyenvector
   pip install pyenvector-1.0.0-cp312-cp312-linux_x86_64.whl

   # Check installation
   pip list | grep pyenvector


Next Steps
----------

Once SDK is installed and configured, proceed to:

1. `examples/quick-start <../../examples/00-quick-start.html>`_ - Quick start with encrypted vector search
2. `examples/api-flow <../../examples/01-api-flow.html>`_ - Understand enVector API flow and usage
3. `examples/rag-demo <../../examples/02-encrypted-rag.html>`_ - Test RAG functionality
4. :doc:`06-troubleshooting` - Common issues and solutions

Important Notes
---------------

- **Key Management**: Keep encryption keys secure
- **Service Dependencies**: Ensure all services are running
- **Network Access**: Verify localhost connectivity
- **Resource Usage**: Monitor memory and CPU usage
- **Error Handling**: Implement proper error handling in your code
