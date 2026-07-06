Troubleshooting Guide
=======================

This guide covers common issues and solutions when running enVector Self-Hosted with Docker Compose.

Quick Diagnostics
-------------------

Check System Status
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Check Docker status
   docker info

   # Check running containers
   docker compose ps

   # Check service logs
   docker compose logs

   # Check resource usage
   docker stats

Check Network Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Test localhost connectivity
   curl http://localhost:50050/health

   # Test inter-container communication
   docker exec es2e ping -c 3 es2b

   # Check Docker networks
   docker network ls

Common Issues and Solutions
----------------------------

1. Docker Daemon Issues
~~~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Docker daemon not running

**Symptoms**:

- ``docker: command not found``
- ``Cannot connect to the Docker daemon``

**Solutions**:

**Ubuntu:**

.. code-block:: bash

   # Start Docker service
   sudo systemctl start docker
   sudo systemctl enable docker

   # Check status
   sudo systemctl status docker

2. Port Conflicts
~~~~~~~~~~~~~~~~~

**Problem**: Port already in use

**Symptoms**:

- ``Bind for 0.0.0.0:50050 failed: port is already allocated``
- ``Address already in use``

**Solutions**:

.. code-block:: bash

   # Find process using port
   sudo lsof -i :50050

   # Kill process
   sudo kill -9 <PID>

   # Or change port in docker-compose.yml
   ports:
     - "50051:50050"  # Change from 50051 to 50050

3. Insufficient Resources
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Not enough memory or CPU

**Symptoms**:

- ``Out of memory``
- ``Container killed``
- Slow performance

**Solutions**:

**Check current usage:**

.. code-block:: bash

   # Check system resources
   free -h
   htop

   # Check Docker resource usage
   docker stats

**Linux optimization:**

.. code-block:: bash

   # Optimize Docker daemon
   sudo tee /etc/docker/daemon.json << EOF
   {
     "storage-driver": "overlay2",
     "log-driver": "json-file",
     "log-opts": {
       "max-size": "10m",
       "max-file": "3"
     }
   }
   EOF

   # Restart Docker
   sudo systemctl restart docker

4. Service Startup Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Services fail to start

**Symptoms**:

- Containers exit immediately
- Health checks fail
- Service dependencies not met

**Solutions**:

**Check service logs:**

.. code-block:: bash

   # View all logs
   docker compose logs

   # View specific service logs
   docker compose logs es2e

   # Follow logs in real-time
   docker compose logs -f

**Check service dependencies:**

.. code-block:: bash

   # Verify all services are running
   docker compose ps

   # Check service health
   curl http://localhost:50050/health

**Restart services:**

.. code-block:: bash

   # Restart all services
   docker compose restart

   # Restart specific service
   docker compose restart es2e

5. Network Issues
~~~~~~~~~~~~~~~~~~

**Problem**: Services can't communicate

**Symptoms**:

- Connection refused errors
- Timeout errors
- Services can't reach each other

**Solutions**:

**Check network configuration:**

.. code-block:: bash

   # List networks
   docker network ls

   # Inspect enVector network
   docker network inspect pyenvector-network

   # Test connectivity between containers
   docker exec es2e ping -c 3 es2b
   docker exec es2b ping -c 3 es2s
   docker exec es2s ping -c 3 es2c

**Recreate network:**

.. code-block:: bash

   # Remove and recreate network
   docker compose down
   docker network prune
   docker compose up -d

6. SDK Connection Issues
~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem**: SDK can't connect to services

**Symptoms**:

- ``Connection refused``
- ``Timeout error``
- ``Service unavailable``

**Solutions**:

**Test service connectivity:**

.. code-block:: bash

   # Test from host
   curl http://localhost:50050/health

**Check SDK configuration:**

.. code-block:: python

   # Test with explicit configuration
   import pyenvector as ev

   ev.init_connect(host='localhost', port=50050)

7. Performance Issues
~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Slow response times

**Symptoms**:

- Long response times
- High CPU/memory usage
- Timeout errors

**Solutions**:

**Monitor performance:**

.. code-block:: bash

   # Real-time monitoring
   docker stats

   # Check service response times
   time curl http://localhost:50050/health

**Optimize resources:**

.. code-block:: bash

   # Scale workers
   docker compose up -d --scale es2c=4

   # Increase memory limits in docker-compose.yml
   deploy:
     resources:
       limits:
         memory: 4G

**Check for bottlenecks:**

.. code-block:: bash

   # Monitor logs for performance issues
   docker compose logs -f | grep -i "slow\|timeout\|error"

   # Check system resources
   htop
   df -h

8. Data Persistence Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Data lost after container restart

**Symptoms**:

- Encrypted documents disappear
- Keys not persisted
- Volumes not mounted

**Solutions**:

**Check volume mounts:**

.. code-block:: bash

   # List volumes
   docker volume ls

   # Inspect volume
   docker volume inspect pyenvector-self-hosted_pyenvector-data

   # Check volume contents
   docker run --rm -v pyenvector-self-hosted_pyenvector-data:/data alpine ls -la /data

**Verify volume configuration:**

.. code-block:: yaml

   # In docker-compose.yml
   volumes:
     - pyenvector-data:/app/data

9. Image Pull Issues
~~~~~~~~~~~~~~~~~~~~

**Problem**: Can't pull Docker images

**Symptoms**:

- ``Image not found``
- ``Pull failed``
- Network timeout

**Solutions**:

**Check internet connectivity:**

.. code-block:: bash

   # Test internet connection
   ping 8.8.8.8

   # Test Docker Hub
   docker pull hello-world

**Use alternative registry:**

.. code-block:: bash

   # Pull from alternative source
   docker pull cryptolabinc/es2e:latest

**Build images locally:**

.. code-block:: bash

   # Build from source
   docker compose build


.. storage_issues:

10. Storage Issues
~~~~~~~~~~~~~~~~~~~~~~

**Problem**: Not enough disk space to insert data

**Symptoms**:

- Server: ``No space left on device``
- Server: ``postgresql | terminated with user request``
- Server: ``Error: The operation was canceled.``
- Client: ``pq: could not extend file "base/.../...": No space left on device``
- Client: ``UNKNOWN:Error received from peer  {grpc_status:14, grpc_message:"Socket closed"}``
- Client: ``No data found: %!w(<nil>)`` (This can be caused by various problems as well)

**Solutions**:

**Check disk usage**:

.. code-block:: bash

   # Check disk space
   df -h

   # Check Docker disk usage
   docker system df

**Check Docker volumes**:

.. code-block:: bash

   # List volumes
   docker volume ls

   # Inspect specific volume
   docker volume inspect pyenvector-self-hosted_pyenvector-data

**Check maximum data points meeting your disk space**:

.. list-table:: Maximum data points based on disk space
   :widths: 10 9 9 10 10 12
   :header-rows: 1

   * - Vector Dimension
     - Storage (GB)
     - Memory (GB)
     - Storage Limited
     - Memory Limited
     - Max Row Count
   * - 256
     - 50
     - 8
     - 90112
     - 1904640
     - 90112
   * - 512
     - 50
     - 8
     - 45056
     - 950272
     - 45056
   * - 1024
     - 50
     - 8
     - 20480
     - 475136
     - 20480
   * - 1536
     - 50
     - 8
     - 12288
     - 315392
     - 12288
   * - 4096
     - 50
     - 8
     - 8192
     - 118784
     - 8192


Recovery Procedures
--------------------

Complete Reset
~~~~~~~~~~~~~~~

.. code-block:: bash

   # Stop all services
   docker compose down

   # Remove all containers and volumes
   docker compose down -v

   # Remove all images
   docker compose down --rmi all

   # Clean up Docker system
   docker system prune -a

   # Restart services
   docker compose up -d

Partial Reset
~~~~~~~~~~~~~~

.. code-block:: bash

   # Restart specific service
   docker compose restart es2e

   # Recreate specific service
   docker compose up -d --force-recreate es2e

Data Recovery
~~~~~~~~~~~~~~

.. code-block:: bash

   # Backup volumes
   docker run --rm -v pyenvector-self-hosted_pyenvector-data:/data -v $(pwd):/backup alpine tar czf /backup/pyenvector-data-backup.tar.gz -C /data .

   # Restore volumes
   docker run --rm -v pyenvector-self-hosted_pyenvector-data:/data -v $(pwd):/backup alpine tar xzf /backup/pyenvector-data-backup.tar.gz -C /data

Monitoring and Logging
-----------------------

Enable Debug Logging
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Set debug level
   export LOG_LEVEL=DEBUG

   # Restart services with debug logging
   docker compose down
   docker compose up -d

Monitor System Resources
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Real-time monitoring
   docker stats

   # System monitoring
   htop
   df -h
   free -h

Log Analysis
~~~~~~~~~~~~~

.. code-block:: bash

   # Search for errors
   docker compose logs | grep ERROR

   # Search for warnings
   docker compose logs | grep WARN

   # Follow logs in real-time
   docker compose logs -f

Support Resources
------------------

Documentation
~~~~~~~~~~~~~~
- `Docker Documentation <https://docs.docker.com/>`_
- `Docker Compose Documentation <https://docs.docker.com/compose/>`_
- `enVector Repository <https://github.com/cryptolab/pyenvector-msa>`_

Community Support
~~~~~~~~~~~~~~~~~~
- `Docker Community <https://forums.docker.com/>`_
- `enVector Issues <https://github.com/cryptolab/pyenvector-msa/issues>`_

Emergency Contacts
~~~~~~~~~~~~~~~~~~~
- **Technical Support**: support@cryptolab.com
- **Documentation**: docs.cryptolab.com
- **GitHub Issues**: github.com/cryptolab/pyenvector-msa/issues
