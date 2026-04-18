# 🔄 Workflow

## DevSecOps Pipeline

1. Developer writes code
2. Docker image is built
3. Image is pushed to AWS ECR
4. Application is deployed on AWS EKS
5. Service exposed via LoadBalancer

## Application Workflow

1. User opens Streamlit dashboard
2. Inputs Docker images (optional)
3. Clicks "Run Audit"
4. System performs:
   - AWS security checks
   - Docker/ECR vulnerability scans
5. Findings are aggregated
6. Results displayed in dashboard
7. Reports generated

## Output

- Dashboard visualization
- JSON / CSV / Excel / PDF reports