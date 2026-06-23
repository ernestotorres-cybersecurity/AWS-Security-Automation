# AWS-Security-Automation

A collection of Python scripts utilizing the `boto3` SDK to automate security auditing and compliance checks across AWS environments. 

## Projects Included:
1. **S3 Public Bucket Hunter (`s3_public_audit.py`)**: Programmatically audits all S3 buckets in an account to verify `PublicAccessBlock` configurations, flagging any buckets vulnerable to data exposure.
2. **IAM Over-Permissive Auditor (`iam_admin_auditor.py`)**: Scans IAM policies to identify overly broad wildcard permissions (`Action: *`, `Resource: *`), aiding in the enforcement of least privilege.

## Tech Stack
* Python 3.x
* AWS Boto3 SDK
* IAM & S3 API Integration
