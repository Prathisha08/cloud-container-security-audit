# AWS Cloud Security Audit Tool (CIS-Inspired)

## Overview
This project is a Python-based cloud security auditing tool that scans AWS resources and identifies common security misconfigurations based on CIS-inspired best practices.

## Features
- Detects open EC2 security groups (0.0.0.0/0)
- Checks S3 bucket encryption
- Verifies IAM users with MFA
- Ensures CloudTrail is enabled
- Checks AWS Config status
- Generates structured JSON compliance reports

## Tech Stack
- Python
- Boto3 (AWS SDK)
- AWS Services: EC2, S3, IAM, CloudTrail, Config

## Project Structure