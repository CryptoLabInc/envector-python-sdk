enVector Service Deployment
===========================

This step deploys all enVector Self-Hosted services using Docker Compose.

Overview
-----------

We'll start all enVector services using Docker Compose. This will create a complete encrypted vector search environment running locally.

Prerequisites
-------------------

- Docker environment configured (from :doc:`03-docker-setup`)
- ``docker-compose.yml`` file in your project directory
- 64GB+ RAM available

Step 1: Start enVector Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Navigate to your project directory
   cd pyenvector-self-hosted/docker-compose

   # Start all services in detached mode
   docker compose -p es2 up -d

   # Check service status
   docker compose -p es2 ps

Step 2: Monitor Service Startup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Watch service logs
   docker compose -p es2 logs -f

   # Or watch specific service
   docker compose -p es2 logs -f es2e
   docker compose -p es2 logs -f es2b
   docker compose -p es2 logs -f es2s
   docker compose -p es2 logs -f es2c

Step 3: Verify Service Health
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Check if all containers are running
   docker compose -p es2 ps

   # Test endpoint connectivity
   curl http://localhost:50050/health

Step 4: Check Service Details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # View running containers
   docker ps

   # Check container resources
   docker stats

   # View container logs
   docker logs es2e
   docker logs es2b
   docker logs es2s
   docker logs es2c

Step 5: Verify Network Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Check Docker networks
   docker network ls

   # Inspect enVector network
   docker network inspect pyenvector-network

   # Test inter-service communication
   docker exec es2e ping -c 3 es2b
   docker exec es2b ping -c 3 es2s
   docker exec es2s ping -c 3 es2c

Step 6: Access Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once all services are running, you can access:

- **enVector Endpoint API**: http://localhost:50050

Service Management Commands
--------------------------------

Start Services
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker compose -p es2 --compatibility up -d

Stop Services
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker compose -p es2 down


Restart Services
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker compose -p es2 restart

Troubleshooting
-------------------

**Common issues:**

.. code-block:: bash

   # Port already in use
   sudo lsof -i :50050
   sudo kill -9 <PID>

   # Insufficient memory
   docker stats

   # Network issues
   docker network ls
   docker network inspect pyenvector-network

Resource Issues
~~~~~~~~~~~~~~~~~~~

**Check resource usage:**

.. code-block:: bash

   # Monitor resource usage
   docker stats

   # Check disk space
   df -h

   # Check memory usage
   free -h

Cleanup
----------

When you're done with the service:

.. code-block:: bash

   # Stop all services
   docker compose -p es2 down

Next Steps
-------------

Once services are deployed and running, proceed to:

1. :doc:`05-sdk-installation` - Install and configure SDK
2. `examples/quick-start <../../examples/00-quick-start.html>`_ - Quick start with encrypted vector search
3. `examples/api-flow <../../examples/01-api-flow.html>`_ - Understand enVector API flow and usage
4. `examples/rag-demo <../../examples/02-encrypted-rag.html>`_ - Test RAG functionality

Important Notes
-------------------

- **Service Dependencies**: Services start in dependency order
- **Health Checks**: Wait for all services to be healthy before proceeding
- **Resource Monitoring**: Monitor system resources
- **Logs**: Keep logs open to monitor for issues
- **Cleanup**: Always clean up after use to free resources
