import boto3

def check_cloudtrail_enabled():
    client = boto3.client("cloudtrail")
    findings = []

    trails = client.describe_trails().get("trailList", [])

    if not trails:
        findings.append({
            "service": "CloudTrail",
            "resource": "Account",
            "resource_name": "Account",
            "issue": "CloudTrail is not enabled",
            "severity": "High",
            "recommendation": "Enable CloudTrail for logging all API activity."
        })

    return findings