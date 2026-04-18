import boto3
from botocore.exceptions import ClientError

def check_s3_encryption():
    try:
        s3 = boto3.client("s3", region_name="ap-south-1")
        findings = []

        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                error_code = e.response["Error"]["Code"]

                if error_code in ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"]:
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "resource_name": bucket_name,
                        "issue": "Bucket encryption is not enabled",
                        "severity": "High",
                        "recommendation": "Enable default server-side encryption for this bucket."
                    })
                else:
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "resource_name": bucket_name,
                        "issue": f"Could not verify encryption: {error_code}",
                        "severity": "Medium",
                        "recommendation": "Review bucket permissions and encryption configuration."
                    })

        return findings

    except Exception as e:
        return [{
            "service": "S3",
            "resource": "AWS API",
            "resource_name": "S3",
            "issue": f"AWS access failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check region, IAM permissions, or pod credentials."
        }]


def check_s3_public_access_block():
    try:
        s3 = boto3.client("s3", region_name="ap-south-1")
        findings = []

        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]

                if not all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False)
                ]):
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "resource_name": bucket_name,
                        "issue": "S3 bucket public access block is not fully enabled",
                        "severity": "High",
                        "recommendation": "Enable all four S3 public access block settings."
                    })

            except ClientError as e:
                error_code = e.response["Error"]["Code"]

                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "resource_name": bucket_name,
                        "issue": "S3 bucket has no public access block configuration",
                        "severity": "High",
                        "recommendation": "Enable S3 public access block for this bucket."
                    })
                else:
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "resource_name": bucket_name,
                        "issue": f"Could not verify public access block: {error_code}",
                        "severity": "Medium",
                        "recommendation": "Review bucket public access settings."
                    })

        return findings

    except Exception as e:
        return [{
            "service": "S3",
            "resource": "AWS API",
            "resource_name": "S3",
            "issue": f"AWS access failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check region, IAM permissions, or pod credentials."
        }]