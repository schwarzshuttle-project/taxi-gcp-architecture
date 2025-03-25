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
- **Service Account Key:** A JSON key file for a service account with necessary permissions (e.g., roles/bigquery.admin, roles/cloudfunctions.admin, roles/appengine.admin, roles/aiplatform.admin, roles/logging.admin).
- **Python 3.10:** Ensure Python 3.10 is installed, as the script is compatible with this version.
- **Dependencies:** Install required Python libraries listed in `requirements.txt`.

## Setup Instructions
### Clone the Repository:
```bash
git clone <repository-url>
cd schwarzshuttle
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

#### `requirements.txt` Includes:
```text
google-cloud-pubsub==2.21.1
google-cloud-bigquery==3.20.1
google-cloud-iam==2.15.0
google-cloud-resource-manager==1.12.3
google-auth==2.29.0
google-cloud-kms==2.22.0
google-cloud-functions==1.16.3
google-cloud-appengine-admin==1.8.4
google-cloud-aiplatform==1.60.0
google-cloud-securitycenter==1.28.0
google-cloud-logging==3.10.0
google-api-python-client==2.149.0
```

### Update `deploy.py`:
Ensure `deploy.py` reflects your project ID, dataset ID, and other configurations. The script will skip VPC Service Controls setup if `ORGANIZATION_ID` is not set.

## Usage
Run the deployment script to set up the infrastructure:
```bash
python deploy.py
```

The script will:
- Enable all required services in GCP
- Create Pub/Sub topics and subscriptions for trip and telemetry data.
- Set up a BigQuery dataset with CMEK for data storage.
- Deploy Cloud Functions for trip processing, receipt generation, and fraud alerts.
- Create an App Engine application for the optimizer service.
- Initialize Vertex AI for ML model training and inference.
- Attempt to set up VPC Service Controls (skipped if no organization).
- Configure security monitoring with log sinks to BigQuery (Security Command Center source creation skipped due to no organization).

## Limitations
- **VPC Service Controls:** Requires an organization, which is not available for this project. Alternative security measures (IAM policies, firewall rules, etc.) are used instead.
- **Security Command Center:** Source creation is skipped as it requires an organization. Project-level monitoring via audit logs in BigQuery is used instead.
- **IoT Core:** Replaced with ClearBlade due to Google Cloud IoT Core retirement on August 16, 2023. Ensure ClearBlade or another IoT solution is configured separately.

## Troubleshooting
- **Import Errors:** Ensure all dependencies are installed in the correct virtual environment (`pip install -r requirements.txt`).
- **Permission Errors:** Verify the service account has necessary roles (`roles/bigquery.admin`, `roles/cloudfunctions.admin`, etc.) in "IAM & Admin" > "IAM".
- **API Enablement:** Ensure all required APIs are enabled in `REQUIRED_APIS` within the script, such as `bigquery.googleapis.com`, `aiplatform.googleapis.com`, etc.
- **Logs:** Check logs for detailed error messages, which are logged with `logging` to help diagnose issues.

## Future Improvements
- **Organization Setup:** Consider creating an organization in GCP to enable VPC Service Controls and Security Command Center source creation for enhanced security.
- **IoT Integration:** Fully integrate ClearBlade or another IoT solution for device management, replacing the retired IoT Core functionality.
- **Monitoring Enhancements:** Explore additional monitoring tools like Cloud Monitoring for more comprehensive observability.

