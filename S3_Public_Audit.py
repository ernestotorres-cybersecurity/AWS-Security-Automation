import boto3
from botocore.exceptions import ClientError

def audit_s3_buckets():
    """
    Audits all S3 buckets in the AWS account to ensure Public Access Block is enabled.
    """
    print("Starting AWS S3 Public Access Audit...\n")
    s3_client = boto3.client('s3')
    
    try:
        # This returns a dictionary containing a list of buckets
        response = s3_client.list_buckets()
    except ClientError as e:
        print(f"Error connecting to AWS: {e}")
        return

    # Loop through the list of buckets (Section 6: Lists & Section 2: Flow Control)
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        
        try:
            # Ask AWS for the specific bucket's public access settings
            public_block = s3_client.get_public_access_block(Bucket=bucket_name)
            
            # Extract the dictionary of configuration settings (Section 5: Dictionaries)
            config = public_block['PublicAccessBlockConfiguration']
            
            # Check if the critical security blocks are set to True
            if config.get('BlockPublicAcls') and config.get('BlockPublicPolicy'):
                print(f"[SECURE] {bucket_name}: Public access is fully blocked.")
            else:
                print(f"[WARNING] {bucket_name}: Missing core public access blocks!")
                
        except ClientError as e:
            # If the configuration doesn't exist at all, AWS throws an error.
            # No config means it is NOT secure.
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                print(f"[ALERT] {bucket_name}: No Public Access Block found! Highly vulnerable.")
            else:
                print(f"[ERROR] Could not check {bucket_name}: {e}")

if __name__ == "__main__":
    audit_s3_buckets()
