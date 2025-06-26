import json
import time
import os
import subprocess
import base64
import argparse
# --- Dependencies for the new function
# pip install PyJWT requests cryptography
import requests
import jwt

# Read S3 keys from environment variables for CI/CD environments.
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY")

def add_secret_to_workflow(workflow_file, secret_json_file):
    """
    Reads a workflow JSON and a service account secret key JSON file,
    extracts the private key, and adds secrets to the workflow data in memory.
    """
    try:
        with open(workflow_file, 'r') as f:
            workflow_data = json.load(f)
        print(f"Successfully loaded '{workflow_file}'")

        # The secret_json_file path is now determined dynamically in main()
        with open(secret_json_file, 'r') as f:
            secret_data = json.load(f)
        secret_key = secret_data.get("private_key")
        if not secret_key:
            print(f"Error: Could not find a 'private_key' field in '{secret_json_file}'.")
            return None
        print(f"Successfully loaded secret key from '{secret_json_file}'")

        if "ComputeServers" in workflow_data and "My_GoogleCloud_Account" in workflow_data["ComputeServers"]:
            workflow_data["ComputeServers"]["My_GoogleCloud_Account"]["SecretKey"] = secret_key
            print("Successfully added 'SecretKey' to 'My_GoogleCloud_Account'.")
        else:
            print("Error: Could not find 'ComputeServers' -> 'My_GoogleCloud_Account' in the JSON structure.")
            return None

        # UPDATED: Check if the keys were successfully loaded from the environment
        if S3_ACCESS_KEY and S3_SECRET_KEY:
            if "DataStores" in workflow_data and "My_Minio_Bucket" in workflow_data["DataStores"]:
                workflow_data["DataStores"]["My_Minio_Bucket"]["AccessKey"] = S3_ACCESS_KEY
                workflow_data["DataStores"]["My_Minio_Bucket"]["SecretKey"] = S3_SECRET_KEY
                print("Successfully added 'AccessKey' and 'SecretKey' to 'My_Minio_Bucket'.")
            else:
                print("Warning: Could not find 'DataStores' -> 'My_Minio_Bucket' in the JSON structure.")
        else:
            print("Warning: S3_ACCESS_KEY or S3_SECRET_KEY environment variables not set. Skipping DataStore key injection.")


        return workflow_data
    except FileNotFoundError as e:
        print(f"Error: The file {e.filename} was not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred in add_secret_to_workflow: {e}")
        return None

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# --- --- --- --- --- API-BASED FUNCTIONS --- --- --- --- ---
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

def generate_gcp_access_key(workflow_data, server_name):
    """Generates a GCP access key via API."""
    try:
        print(f"\n--- Generating GCP Access Key for server: {server_name} ---")
        server_config = workflow_data.get("ComputeServers", {}).get(server_name, {})
        client_email = server_config.get("ClientEmail")
        private_key = server_config.get("SecretKey")
        token_uri = server_config.get("TokenUri")

        if not all([client_email, private_key, token_uri]):
            return workflow_data

        issued_at = int(time.time())
        expires_at = issued_at + 3600
        claims = { "iss": client_email, "scope": "https://www.googleapis.com/auth/cloud-platform", "aud": token_uri, "exp": expires_at, "iat": issued_at }
        signed_jwt = jwt.encode(claims, private_key, algorithm="RS256")
        
        response = requests.post(url=token_uri, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": signed_jwt})
        response.raise_for_status()
        access_token = response.json().get("access_token")

        if access_token:
            workflow_data["ComputeServers"][server_name]["AccessKey"] = access_token
            print("Successfully updated and stored AccessKey.")
    except Exception as e:
        print(f"An unexpected error occurred during key generation: {e}")
    return workflow_data

def create_or_update_gcloud_job_api(workflow_data, job_name, memory=512, timeout=600):
    """Creates or updates a GCP job via API."""
    try:
        print(f"\n--- [API] Creating or Updating Google Cloud Job: {job_name} ---")
        server_name = workflow_data.get("FunctionList", {}).get(job_name, {}).get("FaaSServer")
        server_config = workflow_data.get("ComputeServers", {}).get(server_name, {})
        access_token = server_config.get("AccessKey")
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")
        client_email = server_config.get("ClientEmail")
        image = workflow_data.get("ActionContainers", {}).get(job_name, "gcr.io/faasr-project/gcloud-job-tidyverse")

        if not all([access_token, project_id, location, client_email]):
            return False

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        base_api_url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{location}/jobs"
        check_url = f"{base_api_url}/{job_name}"
        check_response = requests.get(check_url, headers=headers)
        
        body = {"template": {"template": {"containers": [{"image": image, "resources": {"limits": {"memory": f"{memory}Mi"}}}], "timeout": f"{timeout}s", "serviceAccount": client_email}}}

        if check_response.status_code == 200:
            response = requests.patch(url=f"{base_api_url}/{job_name}", headers=headers, json=body)
        elif check_response.status_code == 404:
            response = requests.post(url=f"{base_api_url}?jobId={job_name}", headers=headers, json=body)
        else:
            return False

        response.raise_for_status()
        print(f"Successfully created/updated job '{job_name}'.")
        return True
    except Exception as e:
        print(f"An unexpected error in create_or_update_gcloud_job_api for '{job_name}': {e}")
        return False

def trigger_gcloud_job_api(workflow_data):
    """Triggers a GCP job via API, passing a Base64 encoded payload as a command-line argument."""
    try:
        print("\n--- [API] Triggering Google Cloud Job Execution ---")
        job_to_invoke = workflow_data.get("FunctionInvoke")
        server_name = workflow_data.get("FunctionList", {}).get(job_to_invoke, {}).get("FaaSServer")
        server_config = workflow_data.get("ComputeServers", {}).get(server_name, {})
        access_token = server_config.get("AccessKey")
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")

        if not all([access_token, project_id, location]):
            return

        api_url = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{location}/jobs/{job_to_invoke}:run"
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        
        json_string = json.dumps(workflow_data).encode('utf-8')
        encoded_payload = base64.b64encode(json_string).decode('utf-8')

        payload = { "overrides": { "containerOverrides": [ { "args": [ encoded_payload ] } ] } }
        
        response = requests.post(url=api_url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Successfully sent request to run job '{job_to_invoke}'.")
    except Exception as e:
        print(f"An unexpected error in trigger_gcloud_job_api: {e}")

def set_or_unset_scheduler_api(workflow_data, cron_schedule=None, unset=False):
    """Sets, updates, or unsets a Cloud Scheduler job via API."""
    try:
        job_to_schedule = workflow_data.get("FunctionInvoke")
        server_name = workflow_data.get("FunctionList", {}).get(job_to_schedule, {}).get("FaaSServer")
        server_config = workflow_data.get("ComputeServers", {}).get(server_name, {})
        access_token = server_config.get("AccessKey")
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")
        service_account_email = server_config.get("ClientEmail")
        
        scheduler_job_name = f"faasr-scheduler-{job_to_schedule}"
        print(f"\n--- [API] Managing Cloud Scheduler Job: {scheduler_job_name} ---")

        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        scheduler_api_url = f"https://cloudscheduler.googleapis.com/v1/projects/{project_id}/locations/{location}/jobs"

        if unset:
            print(f"Attempting to unset/delete scheduler job '{scheduler_job_name}'...")
            delete_url = f"{scheduler_api_url}/{scheduler_job_name}"
            response = requests.delete(delete_url, headers=headers)
            if response.status_code == 404:
                print(f"Scheduler job '{scheduler_job_name}' not found, nothing to delete.")
            else:
                response.raise_for_status()
                print(f"Successfully deleted scheduler job '{scheduler_job_name}'.")
            return

        json_string = json.dumps(workflow_data).encode('utf-8')
        encoded_payload = base64.b64encode(json_string).decode('utf-8')
        
        target_uri = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{location}/jobs/{job_to_schedule}:run"
        
        scheduler_body = {
            "name": f"projects/{project_id}/locations/{location}/jobs/{scheduler_job_name}",
            "schedule": cron_schedule,
            "timeZone": "UTC",
            "httpTarget": {
                "uri": target_uri,
                "httpMethod": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": base64.b64encode(json.dumps({"overrides": {"containerOverrides": [{"args": [encoded_payload]}]}}).encode('utf-8')).decode('utf-8'),
                "oauthToken": {
                    "serviceAccountEmail": service_account_email
                }
            }
        }

        check_url = f"{scheduler_api_url}/{scheduler_job_name}"
        check_response = requests.get(check_url, headers=headers)

        if check_response.status_code == 200:
            print(f"Scheduler job found. Updating schedule to '{cron_schedule}'...")
            update_mask = "schedule,httpTarget.body"
            response = requests.patch(f"{check_url}?updateMask={update_mask}", headers=headers, json=scheduler_body)
        else:
            print(f"Scheduler job not found. Creating with schedule '{cron_schedule}'...")
            response = requests.post(scheduler_api_url, headers=headers, json=scheduler_body)
        
        response.raise_for_status()
        print(f"Successfully set/updated scheduler job '{scheduler_job_name}'.")

    except Exception as e:
        print(f"An unexpected error occurred in set_or_unset_scheduler_api: {e}")

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# --- --- --- --- --- GCLOUD CLI-BASED FUNCTIONS --- --- ---
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

def authenticate_gcloud_cli(secret_json_file):
    """Authenticates gcloud CLI using a service account key file."""
    try:
        print("\n--- [CLI] Authenticating gcloud ---")
        command = [ "gcloud", "auth", "activate-service-account", f"--key-file={secret_json_file}" ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        print("gcloud CLI authenticated successfully.")
        return True
    except Exception as e:
        print(f"Error authenticating gcloud CLI: {e}")
        return False

def create_or_update_gcloud_job_cli(workflow_data, job_name, memory=512, timeout=600):
    """Creates or updates a GCP job via gcloud CLI."""
    try:
        print(f"\n--- [CLI] Creating or Updating Google Cloud Job: {job_name} ---")
        server_config = workflow_data.get("ComputeServers", {}).get("My_GoogleCloud_Account", {})
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")
        client_email = server_config.get("ClientEmail")
        image = workflow_data.get("ActionContainers", {}).get(job_name, "gcr.io/faasr-project/gcloud-job-tidyverse")

        check_command = ["gcloud", "run", "jobs", "describe", job_name, f"--project={project_id}", f"--region={location}", "--format=json"]
        job_exists = subprocess.run(check_command, capture_output=True, text=True).returncode == 0

        command = ["gcloud", "run", "jobs"]
        command.append("update" if job_exists else "create")
        command.extend([ job_name, f"--project={project_id}", f"--region={location}", f"--image={image}", f"--service-account={client_email}", f"--memory={memory}Mi", f"--task-timeout={timeout}" ])
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Successfully created/updated job '{job_name}'.")
        return True
    except Exception as e:
        print(f"An unexpected error in create_or_update_gcloud_job_cli for '{job_name}': {e}")
        return False

def trigger_gcloud_job_cli(workflow_data):
    """Triggers a GCP job via gcloud CLI, passing a Base64 encoded payload as a command-line argument."""
    try:
        print("\n--- [CLI] Triggering Google Cloud Job Execution ---")
        job_to_invoke = workflow_data.get("FunctionInvoke")
        server_config = workflow_data.get("ComputeServers", {}).get("My_GoogleCloud_Account", {})
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")
        
        json_string = json.dumps(workflow_data).encode('utf-8')
        encoded_payload = base64.b64encode(json_string).decode('utf-8')
        
        command = [ "gcloud", "run", "jobs", "execute", job_to_invoke, f"--project={project_id}", f"--region={location}", "--args", encoded_payload, "--wait" ]

        print(f"Executing command via CLI...")
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Successfully executed job '{job_to_invoke}'.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing job '{job_to_invoke}' with gcloud CLI:")
        print(f"STDERR: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error in trigger_gcloud_job_cli: {e}")

def set_or_unset_scheduler_cli(workflow_data, cron_schedule=None, unset=False):
    """Sets, updates, or unsets a Cloud Scheduler job via gcloud CLI."""
    try:
        job_to_schedule = workflow_data.get("FunctionInvoke")
        server_config = workflow_data.get("ComputeServers", {}).get("My_GoogleCloud_Account", {})
        project_id = server_config.get("Namespace")
        location = server_config.get("Region")
        service_account_email = server_config.get("ClientEmail")

        scheduler_job_name = f"faasr-scheduler-{job_to_schedule}"
        print(f"\n--- [CLI] Managing Cloud Scheduler Job: {scheduler_job_name} ---")

        if unset:
            print(f"Attempting to unset/delete scheduler job '{scheduler_job_name}'...")
            delete_command = ["gcloud", "scheduler", "jobs", "delete", scheduler_job_name, f"--project={project_id}", f"--location={location}", "--quiet"]
            subprocess.run(delete_command, check=True, capture_output=True, text=True)
            print(f"Successfully deleted scheduler job '{scheduler_job_name}'.")
            return

        json_string = json.dumps(workflow_data).encode('utf-8')
        encoded_payload = base64.b64encode(json_string).decode('utf-8')
        
        target_uri = f"https://run.googleapis.com/v2/projects/{project_id}/locations/{location}/jobs/{job_to_schedule}:run"
        message_body = json.dumps({"overrides": {"containerOverrides": [{"args": [encoded_payload]}]}})

        check_command = ["gcloud", "scheduler", "jobs", "describe", scheduler_job_name, f"--project={project_id}", f"--location={location}", "--format=json"]
        job_exists = subprocess.run(check_command, capture_output=True, text=True).returncode == 0
        
        command = ["gcloud", "scheduler", "jobs"]
        if job_exists:
            print(f"Scheduler job found. Updating schedule to '{cron_schedule}'...")
            command.extend(["update", "http", scheduler_job_name])
        else:
            print(f"Scheduler job not found. Creating with schedule '{cron_schedule}'...")
            command.extend(["create", "http", scheduler_job_name])
            
        command.extend([
            f"--project={project_id}",
            f"--location={location}",
            f"--schedule={cron_schedule}",
            f"--uri={target_uri}",
            f"--http-method=POST",
            f"--message-body={message_body}",
            f"--oauth-service-account-email={service_account_email}"
        ])
        
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Successfully set/updated scheduler job '{scheduler_job_name}'.")

    except subprocess.CalledProcessError as e:
        if unset and "NOT_FOUND" in e.stderr:
            print(f"Scheduler job '{scheduler_job_name}' not found, nothing to delete.")
        else:
            print(f"Error managing scheduler job '{scheduler_job_name}' with gcloud CLI:")
            print(f"STDERR: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error in set_or_unset_scheduler_cli: {e}")

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
# --- --- --- --- --- MAIN EXECUTION --- --- --- --- --- ---
# --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy and manage FaaSr workflows on Google Cloud.")
    parser.add_argument('--workflow-file', type=str, required=True, help='Path to the workflow JSON file.')
    parser.add_argument('--mode', type=str, default='CLI', choices=['API', 'CLI'], help='Execution mode: API or CLI.')
    
    subparsers = parser.add_subparsers(dest='action', required=True, help='Action to perform')

    parser_create = subparsers.add_parser('create', help='Create or update the Cloud Run jobs.')
    parser_trigger = subparsers.add_parser('trigger', help='Trigger the workflow for immediate execution.')
    parser_schedule = subparsers.add_parser('schedule', help='Set or unset a cron schedule for the workflow.')
    schedule_group = parser_schedule.add_mutually_exclusive_group(required=True)
    schedule_group.add_argument('--set', metavar='CRON_STRING', type=str, help='Set or update a cron schedule (e.g., "*/5 * * * *").')
    schedule_group.add_argument('--unset', action='store_true', help='Remove the cron schedule.')

    args = parser.parse_args()

    # Determine the secret file path dynamically for GitHub Actions
    secret_json_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "secret.json")
    server = "My_GoogleCloud_Account"

    workflow_data = add_secret_to_workflow(args.workflow_file, secret_json_file)

    if workflow_data:
        if args.mode == 'API':
            print("\n>>> RUNNING IN API MODE <<<")
            workflow_data = generate_gcp_access_key(workflow_data, server)
            if "AccessKey" not in workflow_data.get("ComputeServers", {}).get(server, {}):
                print("\nSkipping execution because AccessKey could not be generated.")
            else:
                if args.action == 'create':
                    all(create_or_update_gcloud_job_api(workflow_data, name) for name, details in workflow_data.get("FunctionList", {}).items() if details.get("FaaSServer") == server)
                elif args.action == 'trigger':
                    trigger_gcloud_job_api(workflow_data)
                elif args.action == 'schedule':
                    all_jobs_defined = all(create_or_update_gcloud_job_api(workflow_data, name) for name, details in workflow_data.get("FunctionList", {}).items() if details.get("FaaSServer") == server)
                    if all_jobs_defined:
                        set_or_unset_scheduler_api(workflow_data, cron_schedule=args.set, unset=args.unset)
                    else:
                         print("\nSkipping schedule action because one or more job definitions failed.")

        elif args.mode == 'CLI':
            print("\n>>> RUNNING IN GCLOUD CLI MODE <<<")
            # In GHA, authentication is handled by the 'google-github-actions/auth' action.
            # Locally, the user should run 'gcloud auth activate-service-account' manually.
            if args.action == 'create':
                all(create_or_update_gcloud_job_cli(workflow_data, name) for name, details in workflow_data.get("FunctionList", {}).items() if details.get("FaaSServer") == server)
            elif args.action == 'trigger':
                trigger_gcloud_job_cli(workflow_data)
            elif args.action == 'schedule':
                all_jobs_defined = all(create_or_update_gcloud_job_cli(workflow_data, name) for name, details in workflow_data.get("FunctionList", {}).items() if details.get("FaaSServer") == server)
                if all_jobs_defined:
                    set_or_unset_scheduler_cli(workflow_data, cron_schedule=args.set, unset=args.unset)
                else:
                    print("\nSkipping schedule action because one or more job definitions failed.")
        
        # print("\n--- Final Workflow Configuration ---")
        # print(json.dumps(workflow_data, indent=4))
        # print("------------------------------------")
