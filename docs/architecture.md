# 🏗️ Architecture

## Overview
The Cloud & Container Security Audit Tool follows a DevSecOps-based architecture that integrates cloud security checks and container vulnerability scanning.

## Components

### 1. User Interface
- Built using Streamlit
- Allows users to trigger audits and view results

### 2. Security Checks Module
- AWS resource auditing:
  - EC2 (security groups)
  - S3 (encryption, public access)
  - IAM (MFA, password policy)
  - CloudTrail
  - AWS Config

### 3. Container Scanning
- Uses Trivy for vulnerability scanning
- Supports Docker images and ECR repositories

### 4. Aggregation Engine
- Collects findings from all modules
- Categorizes by severity

### 5. Reporting System
- Generates reports in:
  - JSON
  - CSV
  - Excel
  - PDF

### 6. Deployment Layer
- Docker containerization
- AWS ECR for image storage
- AWS EKS for orchestration

## Architecture Flow

User → Streamlit UI → Security Checks + Docker Scan → Aggregation → Dashboard + Reports