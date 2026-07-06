.. envector documentation master file, created by
   sphinx-quickstart on Mon Jul 14 03:47:13 2025.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

enVector Self-Hosted
=====================

**Version: 1.0.0**

Welcome to the enVector Self-Hosted 1.0 Python SDK documentation powered by `pyenvector`.
This SDK provides encrypted vector search and management APIs for secure, privacy-preserving machine learning and search applications.

Introduction
---------------

.. toctree::
   :maxdepth: 1
   :caption: Introduction

   start/docker-compose/01-overview
   start/docker-compose/02-prerequisites
   start/docker-compose/03-docker-setup
   start/docker-compose/04-service-deployment
   start/docker-compose/05-sdk-installation
   start/docker-compose/06-troubleshooting


SDK Examples
----------------------------------

.. toctree::
   :maxdepth: 1
   :caption: Examples

   examples/00-quick-start.ipynb
   examples/01-api-flow.ipynb
   examples/02-encrypted-rag.ipynb


pyenvector Python SDK API Reference
----------------------------------

.. toctree::
   :maxdepth: 1
   :caption: pyenvector Python SDK API Reference

   sdk/client
   sdk/index
   sdk/keygen
   sdk/cipher
