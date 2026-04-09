import boto3

def check_config_enabled():
    client = boto3.client("config")
    findings = []

    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])

    if not recorders:
        findings.append({
            "service": "AWS Config",
            "resource": "Account",
            "resource_name": "Account",
            "issue": "AWS Config is not enabled",
            "severity": "Medium",
            "recommendation": "Enable AWS Config to monitor and record resource configurations."
        })

    return findings