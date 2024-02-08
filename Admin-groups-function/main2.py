#!/usr/bin/env python3
"""
Script to get a list of Google Groups, members, roles, and associated resources.
"""
import os
import json
import csv
import argparse
from googleapiclient import discovery
from googleapiclient import errors
import base64 
from oauth2client.client import GoogleCredentials

def get_all_groups():
    """Retrieves a list of all Google Groups within your domain.
    """

    credentials = GoogleCredentials.get_application_default()
    service = discovery.build('admin', 'directory_v1', credentials=credentials)

    all_groups = []
    next_page_token = None

    while True:
        results = service.groups().list(
            customer='my_customer',  # Replace with your organization identifier
            maxResults=200, 
            pageToken=next_page_token
        ).execute()

        all_groups.extend(results.get('groups', []))
        next_page_token = results.get('nextPageToken')

        if not next_page_token:
            break

    return all_groups

def get_group_memberships(group_key):
    """Retrieves members of a specific Google Group.
    """
    credentials = GoogleCredentials.get_application_default()
    service = discovery.build('admin', 'directory_v1', credentials=credentials)

    all_members = []
    next_page_token = None

    while True:
        results = service.members().list(
            groupKey=group_key,
            maxResults=200,
            pageToken=next_page_token
        ).execute()

        all_members.extend(results.get('members', []))
        next_page_token = results.get('nextPageToken')

        if not next_page_token:
            break

    return all_members


def get_all_iam_policies(org_id=None):
    """
    Given a service account get all the IAM policies attached to
    that service account. This function would need to mirror, as closely
    as possible, the equivalent in your `main.py` file. 
    """
    # ***IMPORTANT: Fill in with IAM retrieval logic from your original 'main.py' ***
    # Placeholder (For illustrative purposes):
    client = asset_v1.AssetServiceClient()
    scope = f"organizations/{org_id}"  
    try:
        response = client.search_all_iam_policies(request={
            "scope": scope
        })
    except (GoogleAPIError, googleapiclient.errors.HttpError) as err:
        print(f'API Error: {err}')
        exit(0)

    return response  # Placeholder 


def get_roles_and_resources(group_members,  org_id, all_iam_policies=None):
    """
    Determines IAM roles assigned to group members along with related resources.

    Args:
        group_members: List of group member objects.
        org_id: The GCP organization ID   
        all_iam_policies: Optional; a list of all IAM policies. Can call 
                          get_all_iam_policies if not provided.

    Returns:
        A dictionary mapping group members to their roles and associated resources.
    """
    member_data = {}

    if all_iam_policies is None:
        all_iam_policies = get_all_iam_policies(org_id)

    for member in group_members:
        member_email = member.get('email')
        if member_email:
            member_data[member_email] = {
                'roles': [],
                'resource': '',  # Placeholder - Adapt  resource logic if needed
                'project': ''    # Placeholder - Adapt  project logic if needed
            }

            for policy in all_iam_policies:
                # Extract resource data - Adjust this to match your IAM Policies
                resource = policy.get('resource')  

                for binding in policy.get('bindings', []):
                    if member_email in binding.get('members', []):
                        role = binding['role']
                        member_data[member_email]['roles'].append(f"{role}_{resource}")

    return member_data


def upload_content_gcp_bucket(gcp_bucket, dest_filename, file_contents):
    """Uploads a file to the bucket by using it's contents"""
    # ... Assume this is identical to your main.py implementation
    pass


def upload_file_gcp_bucket(gcp_bucket, dest_filename, source_file):
    """Uploads a file to the bucket."""
    # ... Assume this is identical to your main.py implementation
    pass


def import_json_as_dictionary(filename):
    """
    Given a json file import it and return the contents as a dictionary
    """
    # ... Assume this is identical to your main.py implementation
    pass 


def parse_and_format_data(all_groups, all_iam_policies, org_id=None):
    """
    Combines Group and IAM information, creating a formatted dictionary output.
    """
    output_dict = {}

    for group in all_groups:
        group_key = group['id']
        group_email = group['email']
        group_name = group['name']

        members = get_group_memberships(group_key)
        member_info = get_roles_and_resources(members, org_id, all_iam_policies)

        output_dict[group_email] = {
            'name': group_name,
            'members': member_info
        }

    return output_dict


def write_dictionary_to_csv(dictionary, filename):
    """Writes data to a CSV file."""
    csv_columns = ['Group Name', 'Group Email', 'Member', 'Roles', 'Resource', 'Project']
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()
        for group_email, group_data in dictionary.items():
            for member, roles_data in group_data['members'].items():
                writer.writerow({
                    'Group Name': group_data['name'],
                    'Group Email': group_email,
                    'Member': member,
                    'Roles': ';'.join(roles_data['roles']),
                    'Resource': roles_data['resource'], 
                    'Project': roles_data['project'] 
                })
def cf_entry_event(event, context):
    """ Event Entry point for the cloudfunction"""
    print(
        """This Function was triggered by messageId {} published at {} to {}""".
        format(context.event_id, context.timestamp, context.resource["name"]))

    if 'data' in event:
        data = base64.b64decode(event['data']).decode('utf-8')
        print(f"data received from trigger: {data}")

    try:
        run_remote()
        return "Remote mode finished successfully"
    except:
        print("Remote mode failed")
        exit(0)


def cf_entry_http(request):
    """ HTTP Entry point for the cloudfunction"""
    print(f"This Function was triggered by request {request}")

    # if 'data' in event:
    #     data = base64.b64decode(event['data']).decode('utf-8')
    #     print(f"data received from trigger: {data}")
    try:
        run_remote()
        return "Remote mode finished successfully"
    except:
        print("Remote mode failed")
        exit(0)


def run_local(iam_json_filename, sas_json_filename, csv_filename, gcs_bucket):
    """
    Execute the script in local mode, this expect json files to be passed in
    """
    print('Script running in local mode')
    ## We are in local mode, read in local json files
    all_iam_policies = import_json_as_dictionary(iam_json_filename)
    all_svc_accts = import_json_as_dictionary(sas_json_filename)

    ## Write out CSV from the Dictionary
    merged_iam_sa_dictionary = parse_assets_output(all_iam_policies,
                                                   all_svc_accts)
    write_dictionary_to_csv(merged_iam_sa_dictionary, csv_filename)
    print(f"Wrote results to {csv_filename}")

    if gcs_bucket:
        upload_file_gcp_bucket(gcs_bucket, csv_filename, csv_filename)
        print(f"Uploaded file {csv_filename} to {gcs_bucket}")


def run_remote():
    """
    Execute the script in remote mode, this gets the data using APIs
    """
    print('Script running in remote mode')
    if os.getenv("GCP_ORG_ID"):
        gcp_org_id = os.getenv("GCP_ORG_ID")
    else:
        print("Pass in GCP ORG ID by setting an env var " +
              "called 'GCP_ORG_ID'")
        exit(0)
    if os.getenv("GCS_BUCKET_NAME"):
        gcs_bucket = os.getenv("GCS_BUCKET_NAME")
    else:
        print("Pass in GCS Bucket by setting an env var " +
              "called 'GCS_BUCKET_NAME'")
        exit(0)

    if os.getenv("CSV_OUTPUT_FILE"):
        csv_filename = os.getenv("CSV_OUTPUT_FILE")
    else:
        print("Pass in output filename by setting an env var " +
              "called 'CSV_OUTPUT_FILE'")
        exit(0)

    all_iam_policies = get_all_iam_policies(gcp_org_id)
    all_svc_accts = get_all_sas(gcp_org_id)
    merged_iam_sa_dictionary = parse_assets_output(all_iam_policies,
                                                   all_svc_accts, gcp_org_id)
    csv_file_full_path = f"/tmp/{csv_filename}"
    write_dictionary_to_csv(merged_iam_sa_dictionary, csv_file_full_path)
    print(f"Wrote results to {csv_file_full_path}")
    upload_file_gcp_bucket(gcs_bucket, csv_filename, csv_file_full_path)
    print(f"Uploaded file {csv_file_full_path} to {gcs_bucket}")


if __name__ == "__main__":
    CMD_DESC = (
        "Script to parse the output of gcloud asset inventory. "
        "It has two modes: remote\n or local. In local mode it expects 2 "
        "input files. The first one is the output\n of `gcloud asset "
        "search-all-iam-policies`. The second one is output of "
        "`gcloud asset search-all-resources "
        "--asset-types='iam.googleapis.com/ServiceAccount'`. In remote mode "
        "it makes the corresponding API calls to get the data. It parses the "
        "input and creates a CSV file with the merged info. It can optionally "
        "upload the results to a GCS Bucket. *NOTE*: Google Managed/Agent "
        "service accounts are not included.")
    parser = argparse.ArgumentParser(description=CMD_DESC)
    ## Create a mutually exclusive parser group
    # to make sure only one mode is used
    # either remote or local, you can't use both
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-r',
                       '--remote',
                       action='store_const',
                       dest='mode',
                       const='remote',
                       help='run in remote mode reading from apis (default)')
    group.add_argument(
        '-l',
        '--local',
        action='store_const',
        dest='mode',
        const='local',
        help='run in local mode reading from passed in json files')
    parser.set_defaults(mode='remote')
    parser.add_argument('-g',
                        '--gcs_bucket',
                        help='upload results to gcs bucket')
    parser.add_argument(
        '-i',
        '--iam_file',
        help='file containing all the iam policies (only in local mode)')
    parser.add_argument(
        '-s',
        '--sas_file',
        help='file containing all the service accounts (only in local mode)')
    parser.add_argument('-o',
                        '--output_file',
                        help='name of file to write results to')
    args = parser.parse_args()

    ## If --remote is passed ignore the local variables
    if args.mode == 'remote' and (args.iam_file or args.sas_file):
        print("-r is specified but local files are passed in " +
              "either switch to local mode or remove the file arguements")
        exit(0)

    if args.mode == 'remote':
        run_remote()

    if args.mode == 'local':
        IAM_JSON_FILENAME = args.iam_file
        SAS_JSON_FILENAME = args.sas_file
        if args.output_file:
            CSV_FILENAME = args.output_file
        else:
            CSV_FILENAME = IAM_JSON_FILENAME.replace('json', 'csv')
        if args.gcs_bucket:
            GCS_BUCKET = args.gcs_bucket
        else:
            GCS_BUCKET = ""
        run_local(IAM_JSON_FILENAME, SAS_JSON_FILENAME, CSV_FILENAME,
                  GCS_BUCKET)