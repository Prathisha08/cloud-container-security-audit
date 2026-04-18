import boto3

def check_cloudtrail_enabled():
    try:
        client = boto3.client("cloudtrail", region_name="ap-south-1")
        trails = client.describe_trails().get("trailList", [])

        if trails:
            return [{
                "service": "CloudTrail",
                "resource": "Trail",
                "resource_name": "CloudTrail",
                "issue": "CloudTrail is enabled.",
                "severity": "Low",
                "recommendation": "No action needed."
            }]

        return [{
            "service": "CloudTrail",
            "resource": "Trail",
            "resource_name": "CloudTrail",
            "issue": "CloudTrail is not enabled.",
            "severity": "High",
            "recommendation": "Enable CloudTrail for auditing and monitoring."
        }]
    except Exception as e:
        return [{
            "service": "CloudTrail",
            "resource": "AWS API",
            "resource_name": "CloudTrail",
            "issue": f"AWS access failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check IAM permissions or pod credentials."
        }]