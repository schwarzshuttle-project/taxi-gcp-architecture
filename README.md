# Taxi GCP Architecture Deployment

This repository contains a Python script (`deploy.py`) that automates the deployment of a secure Google Cloud Platform (GCP) architecture for the SchwarzShuttle taxi business data platform. The script provisions essential GCP resources to support a scalable and secure data pipeline for processing taxi trip data and enabling communication with taxis, along with architecture diagrams and a vision presentation.

## Overview
- **Purpose**: Automates the setup of GCP resources for a taxi business data platform, including data ingestion, storage, and messaging.
- **Key Features**:
  - Creates Pub/Sub topics and subscriptions for real-time data ingestion and responses.
  - Sets up an encrypted BigQuery dataset using Customer-Managed Encryption Keys (CMEK).
  - Configures IAM permissions for secure resource access.
  - Includes logging for deployment status tracking.
- **Target Use Case**: Supports the SchwarzShuttle taxi business by providing a secure and scalable data infrastructure.

## Prerequisites
- **GCP Account**: A GCP project with billing enabled.
- **Python**: Version 3.7 or higher installed.
- **Google Cloud SDK**: Installed and authenticated using `gcloud auth login`.
- **Service Account Key**: A JSON key file for a service account with the "Editor" role (or equivalent permissions to create resources).
- **Dependencies**: Install the required Python libraries:
  ```bash
  pip install google-cloud-pubsub google-cloud-bigquery google-cloud-iam google-cloud-resource-manager google-cloud-kms google-auth
  ```
## Setup and Usage

### Clone the Repository
```bash
git clone https://github.com/SchwarzShuttle/taxi-gcp-architecture.git
cd taxi-gcp-architecture
```

### Configure the Script
1. Open `deploy.py` in a text editor.
2. Update `PROJECT_ID` with your GCP Project ID (default: `taxipoc-2025`).
3. Ensure the service account key file exists and update `SERVICE_ACCOUNT_KEY_PATH` if different from `taxipoc-2025-83c7b01c8c2e.json`.

### Enable Required APIs
Enable the following APIs via GCP Console or CLI:
```bash
gcloud services enable pubsub.googleapis.com \
    bigquery.googleapis.com \
    cloudkms.googleapis.com \
    cloudresourcemanager.googleapis.com \
    dataflow.googleapis.com --project=<PROJECT_ID>
```

### Set Up the Dataflow Service Account
Create the Dataflow service account if it does not exist:
```bash
gcloud iam service-accounts create dataflow --project=<PROJECT_ID>
```
Assign required roles:
```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:dataflow@<PROJECT_ID>.iam.gserviceaccount.com" \
    --role="roles/dataflow.worker"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:dataflow@<PROJECT_ID>.iam.gserviceaccount.com" \
    --role="roles/pubsub.subscriber"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:dataflow@<PROJECT_ID>.iam.gserviceaccount.com" \
    --role="roles/pubsub.publisher"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
    --member="serviceAccount:dataflow@<PROJECT_ID>.iam.gserviceaccount.com" \
    --role="roles/bigquery.dataEditor"
```

### Run the Deployment Script
```bash
python deploy.py
```
The script logs progress in the console (e.g., `INFO - Created topic: taxi-trips`).

### Post-Run KMS Permissions (if needed)
If BigQuery dataset creation fails due to KMS permissions, grant the **Cloud KMS CryptoKey Encrypter/Decrypter** role:
```bash
gcloud kms keys add-iam-policy-binding taxi-key \
    --keyring=taxi-keyring --location=global --project=<PROJECT_ID> \
    --member=serviceAccount:bq-<PROJECT_NUMBER>@bigquery-encryption.iam.gserviceaccount.com \
    --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```

## Deployed Resources

### Pub/Sub
- **Topics:**
  - `taxi-trips`: Receives taxi trip data.
  - `taxi-response`: Sends responses to taxis.
- **Subscriptions:**
  - `taxi-trips-sub`: Subscribed to `taxi-trips`.
  - `taxi-response-sub`: Subscribed to `taxi-response`.

### BigQuery
- **Dataset:** `taxi_dataset`, encrypted with a CMEK.

### Cloud KMS
- **Keyring:** `taxi-keyring` (global location)
- **Key:** `taxi-key` (for encrypting BigQuery data)

### IAM Roles
- **Dataflow Service Account**
  - `roles/bigquery.dataEditor`
  - `roles/pubsub.publisher`
  - `roles/pubsub.subscriber`
  - `roles/dataflow.worker`
- **BigQuery Service Account**
  - `roles/cloudkms.cryptoKeyEncrypterDecrypter`

## Security Features
| Security Type | Description | Implementation |
|--------------|-------------|----------------|
| **Encryption in Transit** | Secures data moving between components with TLS | Used for Pub/Sub, Dataflow, and BigQuery |
| **Encryption at Rest** | BigQuery data encrypted with CMEK | Uses `projects/<project_id>/locations/global/keyRings/taxi-keyring/cryptoKeys/taxi-key` |
| **IAM Access Control** | Defines access permissions | Role-based access for Pub/Sub, Dataflow, and BigQuery |

## Project Details
- **Customer:** SchwarzShuttle
- **Purpose:** Real-time taxi data processing pipeline on GCP
- **Deadline:** March 26, 2025
- **Development Environment:** `taxipoc-2025` GCP project
- **Scope:** Architecture includes Pub/Sub, Dataflow, BigQuery, IAM, and KMS

## Architecture Diagrams
- **High-Level Diagram:** `architecture-high-level.drawio`
- **Low-Level Diagram:** `architecture-low-level.drawio`
- **Security Diagram:** `architecture-security.drawio`

## Files
- `deploy.py`: Deployment script
- `requirements.txt`: Python dependencies (Google Cloud SDK libraries)
- `vision-presentation.pptx`: Future vision for the data platform

## Troubleshooting
### API Not Enabled
Ensure all required APIs are enabled:
```bash
gcloud services list --enabled --project=<PROJECT_ID>
```

### Service Account Key Issues
- Verify the key file path in `deploy.py`

### Permission Errors
- Ensure service accounts have the required IAM roles.
- For KMS-related errors, re-run the post-run KMS permissions step.

### Dataflow Issues
- Ensure `dataflow@<PROJECT_ID>.iam.gserviceaccount.com` exists and has required roles.

### Logging
Check the console output for messages prefixed with `ERROR` or `WARNING`.

## Notes
- This script is for initial deployment; production setup may require further configurations.
- Contact **[Your Fiverr Username]** for support before the delivery deadline.
- Update your GitHub password post-delivery for security.

---

This project is designed for secure, scalable taxi data processing using GCP services. 🚖
