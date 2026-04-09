import boto3
from botocore.exceptions import ClientError

def check_iam_mfa():
    iam = boto3.client("iam")
    findings = []

    response = iam.list_users()
    users = response.get("Users", [])

    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

        if not mfa_devices:
            findings.append({
                "service": "IAM",
                "resource": username,
                "resource_name": username,
                "issue": "IAM user does not have MFA enabled",
                "severity": "Medium",
                "recommendation": "Enable MFA for this IAM user."
            })

    return findings


def check_iam_password_policy():
    iam = boto3.client("iam")
    findings = []

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MinimumPasswordLength", 0) < 8:
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "Password policy minimum length is less than 8",
                "severity": "Medium",
                "recommendation": "Set minimum password length to at least 8."
            })

        if not policy.get("RequireSymbols", False):
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "Password policy does not require symbols",
                "severity": "Medium",
                "recommendation": "Require at least one symbol in passwords."
            })

        if not policy.get("RequireNumbers", False):
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "Password policy does not require numbers",
                "severity": "Medium",
                "recommendation": "Require at least one number in passwords."
            })

        if not policy.get("RequireUppercaseCharacters", False):
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "Password policy does not require uppercase characters",
                "severity": "Medium",
                "recommendation": "Require uppercase letters in passwords."
            })

        if not policy.get("RequireLowercaseCharacters", False):
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "Password policy does not require lowercase characters",
                "severity": "Medium",
                "recommendation": "Require lowercase letters in passwords."
            })

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchEntity":
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": "No IAM account password policy is configured",
                "severity": "High",
                "recommendation": "Configure a strong IAM password policy."
            })
        else:
            findings.append({
                "service": "IAM",
                "resource": "Account",
                "resource_name": "PasswordPolicy",
                "issue": f"Could not verify password policy: {error_code}",
                "severity": "Medium",
                "recommendation": "Review IAM password policy settings."
            })

    return findings