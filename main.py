import argparse
import os

from checks.ec2_checks import check_open_security_groups
from checks.s3_checks import check_s3_encryption, check_s3_public_access_block
from checks.iam_checks import check_iam_mfa, check_iam_password_policy
from checks.cloudtrail_checks import check_cloudtrail_enabled
from checks.config_checks import check_config_enabled

from scans.docker_scan import scan_docker_image
from scans.ecr_scan import scan_ecr_repository

from utils.report import save_report, print_summary
from core.aggregator import severity_summary
from alerts.alert_manager import print_alerts
from alerts.email_alert import send_email_alert


def main():
    parser = argparse.ArgumentParser(description="AWS Security Audit Tool")

    parser.add_argument(
        "--service",
        help="Run specific check: ec2, s3, iam, cloudtrail, config, docker, ecr"
    )

    parser.add_argument(
        "--image",
        nargs="+",
        help="One or more Docker images to scan",
        default=["nginx:latest"]
    )

    parser.add_argument(
        "--repo",
        help="ECR repository name for ECR scan"
    )

    args = parser.parse_args()

    findings = []

    print("Running Security Audit...\n")

    if args.service == "ec2":
        findings.extend(check_open_security_groups())

    elif args.service == "s3":
        findings.extend(check_s3_encryption())
        findings.extend(check_s3_public_access_block())

    elif args.service == "iam":
        findings.extend(check_iam_mfa())
        findings.extend(check_iam_password_policy())

    elif args.service == "cloudtrail":
        findings.extend(check_cloudtrail_enabled())

    elif args.service == "config":
        findings.extend(check_config_enabled())

    elif args.service == "docker":
        for image in args.image:
            print(f"Scanning Docker image: {image}")
            findings.extend(scan_docker_image(image))

    elif args.service == "ecr":
        if not args.repo:
            print("Please provide --repo for ECR scan")
            return

        print(f"Scanning ECR repository: {args.repo}")
        findings.extend(scan_ecr_repository(args.repo))

    else:
        findings.extend(check_open_security_groups())
        findings.extend(check_s3_encryption())
        findings.extend(check_s3_public_access_block())
        findings.extend(check_iam_mfa())
        findings.extend(check_iam_password_policy())
        findings.extend(check_cloudtrail_enabled())
        findings.extend(check_config_enabled())

        print("\nRunning Docker scans...")
        for image in args.image:
            print(f"Scanning Docker image: {image}")
            findings.extend(scan_docker_image(image))

    print("\n=== Results ===")
    print(f"Total Findings: {len(findings)}")

    for f in findings:
        print(f"[{f['severity']}] {f['service']} | {f['resource']} | {f['issue']}")

    print_summary(findings)

    summary = severity_summary(findings)
    print("\n=== Severity Summary ===")
    for sev, count in summary.items():
        print(f"{sev}: {count}")

    print_alerts(findings)

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")
    recipient_email = os.getenv("RECIPIENT_EMAIL")

    if all([smtp_server, smtp_port, sender_email, sender_password, recipient_email]):
        send_email_alert(
            findings=findings,
            smtp_server=smtp_server,
            smtp_port=int(smtp_port),
            sender_email=sender_email,
            sender_password=sender_password,
            recipient_email=recipient_email
        )
    else:
        print("Email alert settings not configured. Skipping email alerts.")

    save_report(findings)


if __name__ == "__main__":
    main()