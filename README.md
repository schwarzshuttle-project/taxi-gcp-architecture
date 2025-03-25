# SchwarzShuttle: City Taxi Business Deployment on Google Cloud Platform

## Overview
SchwarzShuttle is a city taxi business application deployed on Google Cloud Platform (GCP), designed to manage trip revenue, optimize fleet operations, prevent fraud, provide executive dashboards, and analyze operational efficiency. The system leverages various GCP services to ingest, process, and analyze real-time trip and telemetry data, ensuring secure and efficient operations.

## Key Features
- **Trip Revenue Management:** Ingests real-time trip data, processes fares, generates receipts, and provides revenue metrics via BigQuery and Looker dashboards.
- **Fleet Optimization:** Processes vehicle telemetry data, predicts demand using Vertex AI, and optimizes vehicle placement.
- **Fraud Prevention:** Analyzes trip data for anomalies using Vertex AI, with automated investigation workflows.
- **Executive Dashboards & Analytics:** Offers KPI monitoring and forecasting via Looker, covering revenue, trip statistics, vehicle utilization, and fraud detection.
- **Operational Efficiency:** Tracks vehicle maintenance, fuel consumption, driver behavior, and route optimization effectiveness.

## Architecture
The deployment uses the following GCP services:
- **Pub/Sub:** For real-time messaging of trip and telemetry data.
- **Cloud Functions:** For processing trips, generating receipts, and handling fraud alerts.
- **Dataflow:** For streaming telemetry and fraud detection data processing.
- **App Engine:** Hosts the optimizer service for fleet placement recommendations.
- **Vertex AI:** Trains and runs ML models for demand prediction and anomaly detection.
- **BigQuery:** Stores and analyzes trip and telemetry data.
- **Looker:** Provides dashboards for revenue, fleet, and efficiency metrics.
- **Cloud KMS:** Manages Customer-Managed Encryption Keys (CMEK) for data encryption.
- **Cloud Logging:** Exports audit logs to BigQuery for monitoring and compliance.

## Security Measures
- **IAM Policies:** Restrict access to BigQuery and Vertex AI resources, ensuring only authorized service accounts and users have necessary permissions.
- **Network Firewall Rules:** Limit ingress and egress traffic to trusted IP ranges, reducing exposure of resources.
- **Service Account Permissions:** Follow the principle of least privilege, granting minimal roles to service accounts.
- **Data Encryption:** Uses CMEK with Cloud KMS for BigQuery, ensuring control over encryption keys.
- **Audit Logging:** Exports Cloud Audit Logs to BigQuery for monitoring and compliance.
  - *Note:* VPC Service Controls setup is skipped as it requires an organization, which is not available for this project. Alternative security measures are implemented to protect resources.

## Prerequisites
- **Google Cloud Project:** A GCP project (e.g., "taxipoc-2025") with billing enabled.
- **Google Cloud SDK:** Download and install the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) to use `gcloud` commands.
- **Service Account Setup:**
  *Note* Make sure to replace ALL occurences of <taxipoc-2025> strings in the below commands with your GCP project ID!!!
  1. **Create the Service Account:**
     ```bash
     gcloud iam service-accounts create schwarzshuttle-deployer --display-name="SchwarzShuttle Deployer" --description="Service account for deploying SchwarzShuttle infrastructure"  --project=<taxipoc-2025>
     ```
     This creates a service account with the ID `schwarzshuttle-deployer@<taxipoc-2025>.iam.gserviceaccount.com`.
  2. **Grant the Owner Role:**
     ```bash
     gcloud projects add-iam-policy-binding <taxipoc-2025> --member="serviceAccount:schwarzshuttle-deployer@<taxipoc-2025>.iam.gserviceaccount.com" --role="roles/owner"
     ```
     This grants the service account full access to the project, including the ability to enable APIs and manage resources.
  3. **Create and Download the JSON Key:**
     ```bash
     gcloud iam service-accounts keys create <taxipoc-2025>-83c7b01c8c2e.json --iam-account=schwarzshuttle-deployer@<taxipoc-2025>.iam.gserviceaccount.com --project=<taxipoc-2025>
     ```
     This creates the JSON key file `<taxipoc-2025>-83c7b01c8c2e.json` in your current directory. Move it to a secure location accessible by your script (e.g., `E:\taxi-gcp-architecture\<taxipoc-2025>-83c7b01c8c2e.json`).
  4. **Secure the JSON Key File:**
     Store the JSON key file securely, as it provides full access to your project. Avoid committing it to version control (e.g., add it to `.gitignore`).
     Set file permissions to restrict access (e.g., on Unix: `chmod 600 taxipoc-2025-83c7b01c8c2e.json`).
- **Python 3.10:** Ensure Python 3.10 is installed, as the script is compatible with this version.
- **Dependencies:** Install required Python libraries listed in `requirements.txt`.

## Setup Instructions
### Clone the Repository:
```bash
git clone [<repository-url>](https://github.com/SchwarzShuttle/taxi-gcp-architecture.git)
cd taxi-gcp-architecture
```

### Set Up a Virtual Environment:
#### On Unix/Linux/MacOS:
```bash
python -m venv venv
source venv/bin/activate
```

#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

### Install Dependencies:
```bash
pip install -r requirements.txt
```

### Update `deploy.py`:
Open deploy.py and Set the following variables:
```bash
PROJECT_ID = "<taxipoc-2025>"  # Update to your project ID
LOCATION = "global" # Update to your location
SERVICE_ACCOUNT_KEY_PATH = "<taxipoc-2025>-83c7b01c8c2e.json"  # Update to your service account key path
ORGANIZATION_ID = ""  # Set to empty string if no organization; VPC Service Controls requires an organization
```

## Usage
Run the deployment script to set up the infrastructure:
```bash
python deploy.py
```

The script will:
- Create Pub/Sub topics and subscriptions for trip and telemetry data.
- Set up a BigQuery dataset with CMEK for data storage.
- Deploy Cloud Functions for trip processing, receipt generation, and fraud alerts.
- Create an App Engine application for the optimizer service.
- Initialize Vertex AI for ML model training and inference.
- Attempt to set up VPC Service Controls (skipped if no organization).
- Configure security monitoring with log sinks to BigQuery (Security Command Center source creation skipped due to no organization).

