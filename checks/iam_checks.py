import boto3

def check_iam_mfa():
    try:
        iam = boto3.client("iam", region_name="ap-south-1")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)

        if mfa_enabled:
            return [{
                "service": "IAM",
                "resource": "Root Account",
                "resource_name": "AWS Account",
                "issue": "Root account MFA is enabled.",
                "severity": "Low",
                "recommendation": "No action needed."
            }]

        return [{
            "service": "IAM",
            "resource": "Root Account",
            "resource_name": "AWS Account",
            "issue": "Root account MFA is NOT enabled.",
            "severity": "Critical",
            "recommendation": "Enable MFA on the root account immediately."
        }]

    except Exception as e:
        return [{
            "service": "IAM",
            "resource": "AWS API",
            "resource_name": "IAM",
            "issue": f"AWS access failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check IAM permissions or pod credentials."
        }]


def check_iam_password_policy():
    try:
        iam = boto3.client("iam", region_name="ap-south-1")
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        issues = []

        if policy.get("MinimumPasswordLength", 0) < 8:
            issues.append("Minimum password length is less than 8")

        if not policy.get("RequireSymbols", False):
            issues.append("Password policy does not require symbols")

        if not policy.get("RequireNumbers", False):
            issues.append("Password policy does not require numbers")

        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Password policy does not require uppercase letters")

        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Password policy does not require lowercase letters")

        if issues:
            return [{
                "service": "IAM",
                "resource": "Password Policy",
                "resource_name": "Account Password Policy",
                "issue": ", ".join(issues),
                "severity": "Medium",
                "recommendation": "Update IAM password policy to enforce strong passwords."
            }]

        return [{
            "service": "IAM",
            "resource": "Password Policy",
            "resource_name": "Account Password Policy",
            "issue": "Password policy is strong.",
            "severity": "Low",
            "recommendation": "No action needed."
        }]

    except iam.exceptions.NoSuchEntityException:
        return [{
            "service": "IAM",
            "resource": "Password Policy",
            "resource_name": "Account Password Policy",
            "issue": "No password policy is set.",
            "severity": "High",
            "recommendation": "Set a strong IAM password policy."
        }]

    except Exception as e:
        return [{
            "service": "IAM",
            "resource": "AWS API",
            "resource_name": "IAM",
            "issue": f"AWS access failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check IAM permissions or pod credentials."
        }]