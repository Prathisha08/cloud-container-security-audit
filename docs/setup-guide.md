# ⚙️ Setup Guide

## Clone Repository

```bash
git clone https://github.com/<your-username>/cloud-container-security-audit.git

cd cloud-container-security-audit

Install Dependencies:
Bash
pip install -r requirements.txt

Run Locally
Bash
streamlit run app.py


Run via Docker
Bash
docker build -t cloud-audit-tool .
docker run -p 8501:8501 cloud-audit-tool