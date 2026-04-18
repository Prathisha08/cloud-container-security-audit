# 🔐 Cloud & Container Security Audit Tool  
## 🚀 DevSecOps Platform with Zero Trust Principles

A comprehensive cloud security auditing platform that automates security checks across AWS resources and container workloads using DevSecOps practices and Zero Trust-aligned principles.

---

## 📌 Overview

This project provides an end-to-end security auditing solution:

- AWS resource security checks  
- Docker & ECR vulnerability scanning  
- Deployment using AWS ECR + EKS  
- Interactive dashboard (Streamlit)  
- Automated report generation  

---

## 🚀 Features

### ☁️ AWS Security Checks
- EC2 Security Group audit  
- S3 encryption & public access checks  
- IAM MFA & password policy validation  
- CloudTrail monitoring  
- AWS Config verification  

---

### 🐳 Container Security
- Trivy vulnerability scanning  
- Multi-image scanning  
- Severity classification  

---

### 📊 Dashboard
- Interactive UI  
- Charts & filters  
- Findings visualization  

---

### 📄 Reports
- JSON  
- CSV  
- Excel  
- PDF  

---

### 🚨 Alerts
- Console alerts  
- Email alerts  

---

## 🔐 Zero Trust Alignment

- Continuous security validation  
- No implicit trust  
- Identity & access awareness (IAM checks)  
- Secure CI/CD pipeline  

---

## 🔄 Workflow

### DevSecOps Pipeline
Code → Docker Build → Push to ECR → Deploy to EKS → Run App

### Application Flow
User → Dashboard → Run Audit → AWS + Docker Scan → Results → Reports

---

## 🛠️ Installation

```bash
git clone https://github.com/Prathisha08/cloud-container-security-audit.git
cd cloud-container-security-audit
pip install -r requirements.txt