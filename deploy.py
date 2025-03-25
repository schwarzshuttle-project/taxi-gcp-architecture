"""
deploy.py - Automates the deployment of a secure GCP architecture for SchwarzShuttle taxi business data platform.

This script sets up Pub/Sub, BigQuery with CMEK, Cloud Functions, App Engine, Vertex AI, and monitoring with log sinks.
Security features include IAM, CMEK, and alternative measures since VPC Service Controls requires an organization.
Uses logging for status updates and a service account JSON key for authentication.
"""

import logging
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.cloud import pubsub_v1, bigquery, kms_v1, iot_v1, functions_v1, appengine_admin_v1, logging_v2
from google.cloud.aiplatform import init as vertexai_init
from google.cloud.resourcemanager_v3 import ProjectsClient
from google.cloud.securitycenter_v1 import SecurityCenterClient
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
from google.cloud import logging as gc_logging
from google.cloud import service_usage_v1
from google.cloud.service_usage_v1.types.resources import Service, State
from google.cloud.service_usage_v1.types import GetServiceRequest
from google.iam.v1 import iam_policy_pb2, policy_pb2
from google.oauth2 import service_account

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Configuration variables
PROJECT_ID = "taxipoc-2025"  # Update to your project ID
LOCATION = "global" # Update to your region
KEYRING_NAME = "schwarzshuttle-keyring"
KEY_NAME = "schwarzshuttle-key"
DATASET_ID = "schwarzshuttle_dataset"
SERVICE_ACCOUNT_KEY_PATH = "taxipoc-2025-83c7b01c8c2e.json"  # Update to your service account key path
ORGANIZATION_ID = ""  # Set to empty string if no organization; VPC Service Controls requires an organization
VPC_PERIMETER_NAME = "schwarzshuttle_perimeter"

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
functions_client = functions_v1.CloudFunctionsServiceClient(credentials=credentials)
appengine_client = appengine_admin_v1.ApplicationsClient(credentials=credentials)
resource_client = ProjectsClient(credentials=credentials)
securitycenter_client = SecurityCenterClient(credentials=credentials)
logging_client = ConfigServiceV2Client(credentials=credentials)

REQUIRED_APIS = [
    "serviceusage.googleapis.com",
    "cloudfunctions.googleapis.com",
    "appengine.googleapis.com",
    "aiplatform.googleapis.com",
    "bigquery.googleapis.com",
    "pubsub.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "securitycenter.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "storage.googleapis.com",
    "cloudbuild.googleapis.com",
]


def enable_required_apis():
    serviceusage_client = service_usage_v1.ServiceUsageClient(credentials=credentials)
    for api in REQUIRED_APIS:
        service_name = f"projects/{PROJECT_ID}/services/{api}"
        try:
            request = GetServiceRequest(name=service_name)
            service = serviceusage_client.get_service(request)
            if service.state == State.ENABLED:
                logger.info(f"API {api} already enabled")
            else:
                request = service_usage_v1.EnableServiceRequest(name=service_name)
                operation = serviceusage_client.enable_service(request=request)
                operation.result()  # Wait for operation to complete
                logger.info(f"Enabled API: {api}")
        except Exception as e:
            logger.warning(f"Error enabling API {api}: {e}")


def create_pubsub_resources():
    """Creates Pub/Sub topics and subscriptions for SchwarzShuttle data flows."""
    topics = ["trip_data", "telemetry_data", "trip_completed", "recommendations", "alerts"]
    for topic_id in topics:
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
    """Creates a KMS keyring and key for encryption."""
    keyring_path = kms_client.key_ring_path(PROJECT_ID, LOCATION, KEYRING_NAME)
    try:
        kms_client.create_key_ring(
            request={"parent": f"projects/{PROJECT_ID}/locations/{LOCATION}", "key_ring_id": KEYRING_NAME})
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


def deploy_cloud_functions():
    """Deploys placeholder Cloud Functions for trip processing, receipt generation, and alerts."""
    functions = [
        ("trip_processor", "trip_data-sub", "process_trips.py"),
        ("receipt_generator", "trip_completed-sub", "generate_receipts.py"),
        ("alert_handler", "alerts-sub", "handle_alerts.py")
    ]
    for name, trigger_sub, source_file in functions:
        function_path = functions_client.cloud_function_path(PROJECT_ID, LOCATION, name)
        try:
            functions_client.create_function(request={
                "location": f"projects/{PROJECT_ID}/locations/{LOCATION}",
                "function": {
                    "name": function_path,
                    "source_archive_url": f"gs://{PROJECT_ID}-functions/{source_file}",
                    "entry_point": name,
                    "event_trigger": {
                        "event_type": "google.pubsub.topic.publish",
                        "resource": pubsub_publisher.topic_path(PROJECT_ID, trigger_sub.split('-')[0])
                    },
                    "runtime": "python39"
                }
            })
            logger.info(f"Deployed Cloud Function: {name}")
        except Exception as e:
            logger.warning(f"Function {name} exists or error: {e}")


def setup_app_engine():
    """Sets up App Engine for the optimizer service."""
    try:
        application = {"id": PROJECT_ID, "location_id": LOCATION}
        appengine_client.create_application(
            request={"application": application})
        logger.info("Created App Engine application")
    except Exception as e:
        logger.warning(f"App Engine exists or error: {e}")


def setup_vertex_ai():
    """Initializes Vertex AI (basic setup, no model deployment here)."""
    vertexai_init(project=PROJECT_ID, location=LOCATION, credentials=credentials)
    logger.info("Initialized Vertex AI")


def create_vpc_service_controls():
    """Sets up VPC Service Controls perimeter for BigQuery and Vertex AI using googleapiclient."""
    if not ORGANIZATION_ID:
        logger.info("ORGANIZATION_ID is not set. VPC Service Controls requires an organization.")
        return

    acm_service = discovery.build('accesscontextmanager', 'v1', credentials=credentials)
    parent = f"accessPolicies/{ORGANIZATION_ID}"
    perimeter_path = f"{parent}/servicePerimeters/{VPC_PERIMETER_NAME}"
    body = {
        "name": perimeter_path,
        "title": VPC_PERIMETER_NAME,
        "resources": [f"projects/{PROJECT_ID}"],
        "restrictedServices": ["bigquery.googleapis.com", "aiplatform.googleapis.com"]
    }
    try:
        response = acm_service.servicePerimeters().create(parent=parent, body=body).execute()
        logger.info(f"Created VPC Service Controls perimeter: {VPC_PERIMETER_NAME}")
    except Exception as e:
        logger.warning(f"VPC Service Controls perimeter exists or error: {e}")


def setup_security_monitoring():
    """Configures Security Command Center and Log Sinks to BigQuery."""
    # Enable Security Command Center
    if ORGANIZATION_ID:
        try:
            securitycenter_client.create_source(
                request={
                    "parent": f"organizations/{ORGANIZATION_ID}",
                    "source": {"display_name": "SchwarzShuttle Security Source"}
                }
            )
            logger.info("Created Security Command Center source")
        except Exception as e:
            logger.warning(f"Security Command Center source exists or error: {e}")
    else:
        logger.info("Skipping Security Command Center source creation as no organization is set")
    # Create Log Sink to BigQuery
    try:
        client = gc_logging.Client(credentials=credentials)
        sink = client.sink("schwarzshuttle_logs")
        sink.filter_ = f'logName:"projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%"'
        sink.destination = f"bigquery.googleapis.com/projects/{PROJECT_ID}/datasets/{DATASET_ID}"
        sink.create()
        logger.info("Created Log Sink to BigQuery")
    except Exception as e:
        logger.warning(f"Log Sink exists or error: {e}")


def set_iam_policy():
    """Grants necessary IAM permissions for services."""
    policy = resource_client.get_iam_policy(resource=f"projects/{PROJECT_ID}")
    bindings = [
        policy_pb2.Binding(role="roles/bigquery.dataEditor",
                           members=[f"serviceAccount:dataflow@{PROJECT_ID}.iam.gserviceaccount.com"]),
        policy_pb2.Binding(role="roles/cloudfunctions.invoker",
                           members=[f"serviceAccount:{PROJECT_ID}@appspot.gserviceaccount.com"]),
        policy_pb2.Binding(role="roles/aiplatform.user",
                           members=[f"serviceAccount:{PROJECT_ID}@appspot.gserviceaccount.com"])
    ]
    for new_binding in bindings:
        if not any(b.role == new_binding.role and set(b.members) == set(b.members) for b in policy.bindings):
            policy.bindings.append(new_binding)
    try:
        request = iam_policy_pb2.SetIamPolicyRequest(resource=f"projects/{PROJECT_ID}", policy=policy)
        resource_client.set_iam_policy(request=request)
        logger.info("Set IAM policy for Dataflow, Cloud Functions, and Vertex AI")
    except Exception as e:
        logger.error(f"IAM policy error: {e}")


if __name__ == "__main__":
    logger.info("Starting deployment...")
    enable_required_apis()
    create_pubsub_resources()
    key_path = create_kms_key()
    create_bigquery_dataset(key_path)
    deploy_cloud_functions()
    setup_app_engine()
    setup_vertex_ai()
    create_vpc_service_controls()
    setup_security_monitoring()
    set_iam_policy()
    logger.info("Deployment completed.")
