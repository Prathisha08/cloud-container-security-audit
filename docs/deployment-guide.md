# 🚀 Deployment Guide

## Prerequisites
- AWS CLI configured
- Docker installed
- kubectl installed
- eksctl installed

## Step 1: Build Docker Image

```bash
docker build -t cloud-audit-tool .

Step 2: Push to ECR
aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.ap-south-1.amazonaws.com

docker tag cloud-audit-tool:latest <account>.dkr.ecr.ap-south-1.amazonaws.com/cloud-audit-tool:latest
docker push <account>.dkr.ecr.ap-south-1.amazonaws.com/cloud-audit-tool:latest

Step 3: Create EKS Cluster
eksctl create cluster --name devsecops-cluster --region ap-south-1 --node-type t3.small --nodes 1

Step 4: Deploy Application
kubectl apply -f deployment.yaml
kubectl get pods
kubectl get svc

Step 5: Access Application
Open the LoadBalancer EXTERNAL-IP in browser.

---

