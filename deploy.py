"""
deploy.py - Automates the deployment of a secure GCP architecture for a taxi business data platform.

This script sets up Pub/Sub topics, a BigQuery dataset with encryption, and basic IAM permissions.
Security features include Customer-Managed Encryption Keys (CMEK) and restricted access.
Uses logging for status updates and a service account JSON key for authentication.
"""

import logging
from google.cloud import pubsub_v1, bigquery, kms_v1
from google.cloud.resourcemanager_v3 import ProjectsClient
from google.iam.v1 import iam_policy_pb2, policy_pb2
from google.oauth2 import service_account

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Configuration variables
PROJECT_ID = "taxipoc-2025"  # Will update to client's Project ID later
LOCATION = "global"
KEYRING_NAME = "taxi-keyring"
KEY_NAME = "taxi-key"
DATASET_ID = "taxi_dataset"
SERVICE_ACCOUNT_KEY_PATH = "taxipoc-2025-83c7b01c8c2e.json"  # Generic name, update as needed

# Load credentials from the JSON key file
try:
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_KEY_PATH,
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    logger.info(f"Loaded credentials from {SERVICE_ACCOUNT_KEY_PATH}")
except Exception as e:
    logger.error(f"Failed to load service account key: {e}")
    raise

# Initialize GCP service clients with explicit credentials
pubsub_publisher = pubsub_v1.PublisherClient(credentials=credentials)
pubsub_subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
bq_client = bigquery.Client(project=PROJECT_ID, credentials=credentials)
kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)
resource_client = ProjectsClient(credentials=credentials)


def create_pubsub_resources():
    """Creates Pub/Sub topics and subscriptions for taxi data."""
    for topic_id in ["taxi-trips", "taxi-response"]:
        topic_path = pubsub_publisher.topic_path(PROJECT_ID, topic_id)
        try:
            pubsub_publisher.create_topic(request={"name": topic_path})
            logger.info(f"Created topic: {topic_id}")
        except Exception as e:
            logger.warning(f"Topic {topic_id} exists or error: {e}")
        sub_path = pubsub_subscriber.subscription_path(PROJECT_ID, f"{topic_id}-sub")
        try:
            pubsub_subscriber.create_subscription(request={"name": sub_path, "topic": topic_path})
            logger.info(f"Created subscription: {topic_id}-sub")
        except Exception as e:
            logger.warning(f"Subscription {topic_id}-sub exists or error: {e}")


def create_kms_key():
    """Creates a KMS keyring and key for BigQuery encryption."""
    keyring_path = kms_client.key_ring_path(PROJECT_ID, LOCATION, KEYRING_NAME)
    try:
        kms_client.create_key_ring(request={"parent": f"projects/{PROJECT_ID}/locations/{LOCATION}", "key_ring_id": KEYRING_NAME})
        logger.info(f"Created keyring: {KEYRING_NAME}")
    except Exception as e:
        logger.warning(f"Keyring exists or error: {e}")
    key_path = kms_client.crypto_key_path(PROJECT_ID, LOCATION, KEYRING_NAME, KEY_NAME)
    try:
        kms_client.create_crypto_key(request={
            "parent": keyring_path,
            "crypto_key_id": KEY_NAME,
            "crypto_key": {"purpose": kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT}
        })
        logger.info(f"Created key: {KEY_NAME}")
    except Exception as e:
        logger.warning(f"Key exists or error: {e}")
    return key_path


def create_bigquery_dataset(key_path):
    """Creates a BigQuery dataset with CMEK."""
    dataset = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
    dataset.default_encryption_configuration = bigquery.EncryptionConfiguration(kms_key_name=key_path)
    try:
        bq_client.create_dataset(dataset)
        logger.info(f"Created dataset: {DATASET_ID} with CMEK")
    except Exception as e:
        logger.warning(f"Dataset exists or error: {e}")


def set_iam_policy():
    """Grants Dataflow write access to BigQuery."""
    policy = resource_client.get_iam_policy(resource=f"projects/{PROJECT_ID}")
    new_binding = policy_pb2.Binding(
        role="roles/bigquery.dataEditor",
        members=[f"serviceAccount:dataflow@{PROJECT_ID}.iam.gserviceaccount.com"]
    )
    if not any(b.role == new_binding.role and set(b.members) == set(new_binding.members) for b in policy.bindings):
        policy.bindings.append(new_binding)
    try:
        request = iam_policy_pb2.SetIamPolicyRequest(
            resource=f"projects/{PROJECT_ID}",
            policy=policy
        )
        response = resource_client.set_iam_policy(request=request)
        logger.info("Set IAM policy for Dataflow")
    except Exception as e:
        logger.error(f"IAM policy error: {e}")


if __name__ == "__main__":
    logger.info("Starting deployment...")
    create_pubsub_resources()
    key_path = create_kms_key()
    create_bigquery_dataset(key_path)
    set_iam_policy()
    logger.info("Deployment completed.")
