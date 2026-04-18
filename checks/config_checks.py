# checks/config_checks.py
import boto3
from botocore.exceptions import ClientError

def check_config_enabled():
    findings = []
    client = boto3.client("config", region_name="ap-south-1")

    try:
        recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", str(e))
        findings.append({
            "service": "AWS Config",
            "status": "ERROR",
            "severity": "Medium",
            "title": "Unable to read AWS Config configuration recorders",
            "details": f"{code}: {msg}"
        })
        return findings

    if not recorders:
        findings.append({
            "service": "AWS Config",
            "status": "FAIL",
            "severity": "High",
            "title": "AWS Config is not enabled",
            "details": "No configuration recorder was found."
        })
    else:
        findings.append({
            "service": "AWS Config",
            "status": "PASS",
            "severity": "Info",
            "title": "AWS Config recorder exists",
            "details": f"Found {len(recorders)} configuration recorder(s)."
        })
