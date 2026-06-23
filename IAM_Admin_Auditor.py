import boto3
from botocore.exceptions import ClientError

def audit_iam_admin_policies():
    """
    Scans IAM policies to find overly permissive 'AdministratorAccess' 
    or wildcards (*) attached directly to users/roles.
    """
    print("Starting IAM Policy Audit...\n")
    iam_client = boto3.client('iam')
    
    try:
        # Grab a list of all custom policies in the account
        response = iam_client.list_policies(Scope='Local')
    except ClientError as e:
        print(f"Error connecting to AWS IAM: {e}")
        return

    # Loop through the list of policies
    for policy in response['Policies']:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        default_version_id = policy['DefaultVersionId']
        
        try:
            # Fetch the actual JSON document (the dictionary) for this specific policy
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            
            # Drill down into the dictionary to get the policy statements
            document = policy_version['PolicyVersion']['Document']
            statements = document.get('Statement', [])
            
            # A policy can have multiple statements, so we make sure it's a list, then loop through it
            if isinstance(statements, dict):
                statements = [statements]
                
            for statement in statements:
                # Check for the dangerous combination: Allow + Action:* + Resource:*
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', '')
                    resources = statement.get('Resource', '')
                    
                    if '*' in actions and '*' in resources:
                        print(f"[ALERT] Overly permissive policy found: {policy_name}")
                        print(f"        ARN: {policy_arn}\n")
                        
        except ClientError as e:
            print(f"[ERROR] Could not read policy {policy_name}: {e}")

if __name__ == "__main__":
    audit_iam_admin_policies()
