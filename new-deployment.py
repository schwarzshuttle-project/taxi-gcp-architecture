import os
import time
import logging
import subprocess
from typing import Optional
from google.cloud import run_v2, iam_admin_v1
from google.cloud.iam_admin_v1 import types
from google.oauth2 import service_account
from google.auth import credentials as google_auth_credentials
from google.cloud import pubsub_v1 , kms_v1 , bigquery
from google.cloud import service_usage_v1
from google.cloud.aiplatform import init as vertexai_init
from google.cloud.service_usage_v1.types.resources import Service, State
from google.cloud.service_usage_v1.types import GetServiceRequest
from google.cloud.aiplatform import init as vertexai_init
from typing import Optional, List
from google.cloud import iam_admin_v1
from google.api_core import exceptions
from google.cloud import storage
from google.api_core.exceptions import Conflict
from google.api_core.exceptions import AlreadyExists, GoogleAPICallError


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)  


# Configuration
PROJECT_ID = "schwarzshuttle"  
LOCATION = "europe-west1"      
SERVICE_ACCOUNT_FILE = "service-account.json" 
SERVICE_ACCOUNT_KEY_PATH = "service-account.json" 
KEYRING_NAME = "new-keyring"
key_path_sql = f"projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/f{KEYRING_NAME}/cryptoKeys/cloudsql-key"
key_path_bucket = f"projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{KEYRING_NAME}/cryptoKeys/bucket-key"
key_path_dataset = f"projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{KEYRING_NAME}/cryptoKeys/dataset-key"
key_path_pubsub = f"projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{KEYRING_NAME}/cryptoKeys/pubsub-key"


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
serviceusage_client = service_usage_v1.ServiceUsageClient(credentials=credentials)
pubsub_publisher = pubsub_v1.PublisherClient(credentials=credentials)
pubsub_subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
client = run_v2.ServicesClient(credentials=credentials)
kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)
bq_client = bigquery.Client(project=PROJECT_ID, credentials=credentials)


REQUIRED_APIS = [
    "serviceusage.googleapis.com",
    "aiplatform.googleapis.com",
    "bigquery.googleapis.com",
    "pubsub.googleapis.com",
    "cloudkms.googleapis.com",
    "logging.googleapis.com",
    "securitycenter.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "storage.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "run.googleapis.com",          
    "iam.googleapis.com",          
    "artifactregistry.googleapis.com", 
    "cloudbuild.googleapis.com" 
]
# Enable Required APIs
def enable_required_apis():
    """Enables required APIs in GCP needed to create resources on"""
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


# Create Service Accounts 
service_names = [
        # "trip-processing",
        # "driver-performance",
        # "payment-processing"
        # "telemetry-processing",
        "receipt-generator"
    ]
def create_service_accounts() -> None:
    """Creates multiple service accounts for predefined services with rate limiting."""
    project_id = "schwarzshuttle"

    iam_admin_client = iam_admin_v1.IAMClient()
    
    for account_id in service_names:
        try:
            request = types.CreateServiceAccountRequest()
            request.account_id = account_id
            request.name = f"projects/{project_id}"

            service_account = types.ServiceAccount()
            service_account.display_name = account_id.replace("-", " ").title()
            request.service_account = service_account
            
            account = iam_admin_client.create_service_account(request=request)
            print(f"✅ Successfully created service account: {account.email}")
            
            # Add delay to avoid quota limits (100 per minute)
            time.sleep(1)  # 1 second delay between creations
        
        except exceptions.ResourceExhausted as e:
            print(f"⚠️ Rate limit exceeded for {account_id}. Waiting 30 seconds before retry...")
            time.sleep(30)
            try:
                # Retry once after delay
                account = iam_admin_client.create_service_account(request=request)
                print(f"✅ Successfully created service account after retry: {account.email}")
            except Exception as retry_error:
                print(f"❌ Failed to create {account_id} after retry: {retry_error}")
        
        except Exception as e:
            print(f"❌ Error creating {account_id}: {e}")
        
        print()  # Empty line for readability




#Create Cloud Runs 

# Image to deploy
IMAGE_URL = "gcr.io/cloudrun/hello"

def create_cloud_run_services():
    # Authenticate with service account
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    
    
    # Parent resource path
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    
    for service_name in service_names:
        # Build the service account email for this service
        service_account_email = f"{service_name}@{PROJECT_ID}.iam.gserviceaccount.com"
        
        # Define the service configuration
        service = run_v2.Service(
            template=run_v2.RevisionTemplate(
                containers=[
                    run_v2.Container(
                        image=IMAGE_URL,
                        ports=[run_v2.ContainerPort(container_port=8080)],
                        resources=run_v2.ResourceRequirements(
                            limits={
                                "cpu": "1",
                                "memory": "512Mi"
                            }
                        )
                    )
                ],
                service_account=service_account_email,
                max_instance_request_concurrency=80
            )
        )
        
        # Create the service
        try:
            operation = client.create_service(
                parent=parent,
                service=service,
                service_id=service_name
            )
            print(f"Creating Cloud Run service: {service_name} with SA: {service_account_email}")
            operation.result()  # Wait for operation to complete
            print(f"✅ Successfully created service: {service_name}")
        except Exception as e:
            print(f"❌ Failed to create service {service_name}: {e}")
        print()  # Empty line for readability


# Create 7 PubSubs with their subscriptions
def create_pubsub_resources():
    """Creates Pub/Sub topics and subscriptions for SchwarzShuttle data flows."""
    topics = ["trip_data", "trip_completed","payment_success","driver_performance", "telemetry_data", "recommendations", "alerts"]
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



# Create KMS Keys
def create_kms_key():
    """Creates a KMS keyring and key for encryption."""
    location = "europe-west1"
    keyring_path = kms_client.key_ring_path(PROJECT_ID, location, KEYRING_NAME)
    try:
        kms_client.create_key_ring(
            request={"parent": f"projects/{PROJECT_ID}/locations/{location}", "key_ring_id": KEYRING_NAME})
        logger.info(f"Created keyring: {KEYRING_NAME}")
    except Exception as e:
        logger.warning(f"Keyring exists or error: {e}")
    
    keys_names=["pubsub-key","bucket-key","dataset-key"]
    for key in keys_names:
        key_path = kms_client.crypto_key_path(PROJECT_ID, location, KEYRING_NAME, key )
        try:
            kms_client.create_crypto_key(
                request={
                "parent": keyring_path,
                "crypto_key_id": key,
                "crypto_key": {"purpose": kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT}
            })
            logger.info(f"Created key: {key}")
        except Exception as e:
            logger.warning(f"Key exists or error: {e}")
            print(f"{key_path}")
    return key_path


#Create Bigquery Datasets

def create_bigquery_dataset(key_path_dataset):
    """Creates a BigQuery dataset with CMEK in europe-west1 location."""
    DATASETS = ["schwarzshuttle_dataset", "logs_dataset", "trip_dataset", "driver_performance_dataset"]
    
    for dataset_name in DATASETS:
        dataset = bigquery.Dataset(f"{PROJECT_ID}.{dataset_name}")
        dataset.location = "europe-west1"  # Set the location
        dataset.default_encryption_configuration = bigquery.EncryptionConfiguration(kms_key_name=key_path_dataset)
        
        try:
            bq_client.create_dataset(dataset)
            logger.info(f"Created dataset: {dataset_name} with CMEK in europe-west1")
        except Exception as e:
            logger.warning(f"Dataset exists or error: {e}")


#Create buckets 
def create_gcs_buckets():
    """Creates two GCS buckets with CMEK encryption."""
    BUCKETS = ["schwarzshuttle-data-bucket", "receipt-generator-bucket"]
    KEYRING_NAME = "your-keyring-name"  # Replace with actual    
    storage_client = storage.Client(project=PROJECT_ID)
    for bucket_name in BUCKETS:
        try:
            # Create bucket with encryption configuration
            bucket = storage_client.bucket(bucket_name)
            bucket.encryption_configuration = {
                "defaultKmsKeyName": key_path_bucket
            }
            
            # Create bucket with location
            bucket.create(location=LOCATION)
            
            print(f"✅ Successfully created bucket {bucket_name} in {LOCATION}")
            print(f"   Encryption Key: {key_path_bucket}")
            
        except Exception as e:
            print(f"❌ Failed to create bucket {bucket_name}: {str(e)}")

#Vertex AI
def setup_vertex_ai():
    """Initializes Vertex AI (basic setup, no model deployment here)."""
    vertexai_init(project=PROJECT_ID, location=LOCATION, credentials=credentials)
    logger.info("Initialized Vertex AI")

#Fucntion To Assign Storage Writer to lsit of SAs
def assign_role_storage_writer():
    SERVICE_ACCOUNTS = ["receipt-generator"]   
    ROLES = [ "roles/storage.objectAdmin" ]
    for sa in SERVICE_ACCOUNTS:
        sa_email = f"{sa}@{PROJECT_ID}.iam.gserviceaccount.com"
        for role in ROLES:
            try:
                # Build the gcloud command
                cmd = [
                    "gcloud", "projects", "add-iam-policy-binding", PROJECT_ID,
                    "--member", f"serviceAccount:{sa_email}",
                    "--role", role
                ]
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                print(f"✅ Successfully assigned {role} to {sa_email}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to assign {role} to {sa_email}")
                print(f"Error: {e.stderr}")

if __name__ == "__main__":
    # assign_role_storage_writer()
    # logger.info("storage writer assigned to the SAs")
    # enable_required_apis()
    # setup_vertex_ai()
    # create_gcs_buckets()
    # logger.info("GCS bucket creation process completed")
    # create_service_accounts()
    # create_cloud_run_services()
    # create_bigquery_dataset(key_path_dataset)
    # logger.info("Datasets Created")
    # create_kms_key()
    # logger.info("Keys Creation Completed")
    # create_services_with_service_accounts()
    # logger.info("Cloud Runs & SAs Deployment Completed")
    # create_pubsub_resources()
    # logger.info("PubSubs & Subscriptions Deployment Completed")





