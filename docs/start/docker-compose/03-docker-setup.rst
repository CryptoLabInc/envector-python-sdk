Docker Environment Setup
=============================

This step configures your Docker environment for running enVector Self-Hosted services.

Overview
------------

We'll set up Docker Compose to run all enVector services locally. This approach provides:

- **Simplicity**: Single command to start all services
- **Isolation**: Each service runs in its own container
- **Consistency**: Same environment across different machines
- **Easy Management**: Simple start/stop/restart commands

Prerequisites
----------------

- Docker Engine running
- Docker Compose v2.0+ installed
- 64GB+ RAM available
- 50GB+ free disk space
- Docker Hub access token (for pulling private images)

Step 1: Verify Docker Environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Check Docker version
   docker --version

   # Check Docker Compose version
   docker compose version

   # Verify Docker daemon is running
   docker info

   # Test with a simple container
   docker run hello-world

Step 2: Check and Download enVector Docker Images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, check if the required images are already available locally:

.. code-block:: bash

   # Check for existing enVector images
   docker images | grep pyenvector

   # Check for specific images
   docker images | grep pyenvectore
   docker images | grep pyenvectorb
   docker images | grep pyenvectors
   docker images | grep pyenvectorc

If images are not available, you'll need to pull them from Docker Hub. This requires a Docker Hub access token for private repositories:

Login with Provided Access Token
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You will receive a temporary Docker Hub access token for this guide. Use your personal Docker Hub account with the provided token:

.. code-block:: bash

   # Login with your personal account and provided token
   docker login -u your-username --password-stdin provided-access-token

   # Pull enVector service images
   docker pull cryptolabinc/es2e:latest
   docker pull cryptolabinc/es2b:latest
   docker pull cryptolabinc/es2s:latest
   docker pull cryptolabinc/es2c:latest

   # Verify all images are downloaded
   docker images | grep cryptolabinc

**Note**: The provided access token is temporary and will be revoked after the guide.

Step 3: Create Project Directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Create project directory
   mkdir pyenvector-self-hosted
   cd pyenvector-self-hosted

   # Create docker compose directory
   mkdir docker-compose
   cd docker-compose

Step 4: Copy Configuration Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copy the provided ``docker-compose.yml`` file to your project directory.
The file can be found in the  `pyenvector-deployment <https://github.com/CryptoLabInc/pyenvector-deployment/tree/release/v1.0>`_ repository.

.. code-block:: bash

   # Copy docker-compose.yml from the hands-on guide directory
   cp /path/to/hands-on-guide/docker-compose.yml .
   cp /path/to/hands-on-guide/.env .

   # Verify the file
   ls -la docker-compose.yml

Step 5: Verify Docker Compose Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``docker-compose.yml`` file includes default configurations for all services. Verify the configuration:

.. code-block:: bash

   # Validate docker-compose.yml
   docker compose config

   # Check service definitions
   docker compose ps

   # Test pulling images
   docker compose pull

Step 6: Verify Network Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Check Docker networks
   docker network ls

   # Test network connectivity
   docker run --rm alpine ping -c 3 google.com

Troubleshooting
------------------

Docker Daemon Issues
~~~~~~~~~~~~~~~~~~~~~~~~~

**Docker not running:**

.. code-block:: bash

   # Ubuntu
   sudo systemctl start docker
   sudo systemctl enable docker

**Permission denied:**

.. code-block:: bash

   # Add user to docker group
   sudo usermod -aG docker $USER
   # Log out and log back in

Resource Issues
~~~~~~~~~~~~~~~~~~~

**Out of memory:**

.. code-block:: bash

   # Check available memory
   free -h

   # Ensure sufficient memory is available (64GB+ recommended)
   # Check Docker daemon configuration
   sudo cat /etc/docker/daemon.json

**Disk space issues:**

.. code-block:: bash

   # Check disk space
   df -h

   # Clean up Docker
   docker system prune -a

Network Issues
~~~~~~~~~~~~~~~~~~~

**Cannot pull images:**

.. code-block:: bash

   # Test internet connectivity
   ping 8.8.8.8

   # Test Docker Hub
   docker pull hello-world

   # Check DNS
   nslookup docker.io

Next Steps
-----------------

Once Docker environment is configured, proceed to:

1. `examples/quick-start <../../examples/00-quick-start.html>`_ - Quick start with encrypted vector search
2. `examples/api-flow <../../examples/01-api-flow.html>`_ - Understand enVector API flow and usage
3. `examples/rag-demo <../../examples/02-encrypted-rag.html>`_ - Test RAG functionality

Important Notes
---------------------

- **Resource Monitoring**: Monitor Docker resource usage
- **Network Access**: Ensure containers can communicate with each other
- **Data Persistence**: Volumes are used for data persistence
- **Cleanup**: Use ``docker compose down`` to clean up after use
