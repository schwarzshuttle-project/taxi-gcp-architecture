# Taxi GCP Architecture Deployment

This repository contains a Python script to automate the deployment of a secure Google Cloud Platform (GCP) architecture for the SchwarzShuttle taxi business data platform.

## Overview
- **Purpose**: Deploys Pub/Sub topics, a BigQuery dataset, and basic IAM permissions with security features.
- **Security**: Includes Customer-Managed Encryption Keys (CMEK) for data at rest and IAM for access control.
- **Logging**: Uses Python's `logging` module for detailed status output.

## Prerequisites
- **GCP Account**: Must have billing enabled and a Project ID.
- **Python**: Version 3.7+ installed.
- **GCP SDK**: Install the `gcloud` CLI and authenticate:
  ```bash
  gcloud auth application-default login
