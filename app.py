import streamlit as st
import pandas as pd
from collections import Counter

from checks.ec2_checks import check_open_security_groups
from checks.s3_checks import check_s3_encryption, check_s3_public_access_block
from checks.iam_checks import check_iam_mfa, check_iam_password_policy
from checks.cloudtrail_checks import check_cloudtrail_enabled
from checks.config_checks import check_config_enabled

from scans.docker_scan import scan_docker_image
from utils.report import save_report

st.set_page_config(page_title="Cloud Security Dashboard", layout="wide")

st.title("CloudSec + DevSecOps Dashboard")
st.write("AWS + Docker Security Auditing Tool")

if "findings" not in st.session_state:
    st.session_state.findings = None


def safe_run(func):
    try:
        result = func()
        if result is None:
            return []
        if isinstance(result, list):
            return result
        return [{
            "service": "Internal",
            "resource": func.__name__,
            "resource_name": func.__name__,
            "issue": f"Check returned invalid type: {type(result).__name__}",
            "severity": "High",
            "recommendation": "Ensure every check function returns a list of findings."
        }]
    except Exception as e:
        return [{
            "service": "Internal",
            "resource": func.__name__,
            "resource_name": func.__name__,
            "issue": f"Check failed: {str(e)}",
            "severity": "High",
            "recommendation": "Check AWS permissions or function logic."
        }]


def run_all_checks(images):
    findings = []

    check_functions = [
        check_open_security_groups,
        check_s3_encryption,
        check_s3_public_access_block,
        check_iam_mfa,
        check_iam_password_policy,
        check_cloudtrail_enabled,
        check_config_enabled,
    ]

    for func in check_functions:
        findings.extend(safe_run(func))

    for image in images:
        try:
            docker_result = scan_docker_image(image)
            if docker_result is None:
                docker_result = []
            elif not isinstance(docker_result, list):
                docker_result = [{
                    "service": "Docker",
                    "resource": image,
                    "resource_name": image,
                    "issue": f"Docker scan returned invalid type: {type(docker_result).__name__}",
                    "severity": "Medium",
                    "recommendation": "Ensure scan_docker_image returns a list."
                }]
            findings.extend(docker_result)
        except Exception as e:
            findings.append({
                "service": "Docker",
                "resource": image,
                "resource_name": image,
                "issue": f"Docker scan failed: {str(e)}",
                "severity": "Medium",
                "recommendation": "Check Docker image or scanner setup."
            })

    return findings


image_input = st.text_area(
    "Docker Images (one per line)",
    "nginx:latest\npython:3.12\nnode:20"
)

if st.button("Run Audit"):
    images = [img.strip() for img in image_input.splitlines() if img.strip()]
    st.session_state.findings = run_all_checks(images)
    save_report(st.session_state.findings)

findings = st.session_state.findings

if findings is not None:
    st.subheader("Audit Summary")
    st.write(f"Total Findings: {len(findings)}")

    for f in findings:
        f["severity"] = str(f.get("severity", "UNKNOWN")).upper()

    counter = Counter(f["severity"] for f in findings)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Critical", counter.get("CRITICAL", 0))
    col2.metric("High", counter.get("HIGH", 0))
    col3.metric("Medium", counter.get("MEDIUM", 0))
    col4.metric("Low", counter.get("LOW", 0))

    if findings:
        df = pd.DataFrame(findings)

        st.subheader("Filters")

        service_filter = st.selectbox(
            "Service",
            ["All"] + sorted(df["service"].dropna().unique().tolist())
        )

        severity_filter = st.selectbox(
            "Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        )

        if service_filter != "All":
            df = df[df["service"] == service_filter]

        if severity_filter != "All":
            df = df[df["severity"] == severity_filter]

        st.subheader("Findings Table")
        st.dataframe(df, use_container_width=True)

        st.subheader("Findings by Severity")
        st.bar_chart(df["severity"].value_counts())

        st.subheader("Findings by Service")
        st.bar_chart(df["service"].value_counts())

        st.subheader("🚨 High / Critical Alerts")
        alerts_df = df[df["severity"].isin(["HIGH", "CRITICAL"])]

        if alerts_df.empty:
            st.success("No critical issues detected")
        else:
            st.dataframe(alerts_df, use_container_width=True)

        try:
            with open("output/report.json", "rb") as f:
                st.download_button("Download JSON", f, "report.json")
        except FileNotFoundError:
            st.info("JSON report not found.")

        try:
            with open("output/report.csv", "rb") as f:
                st.download_button("Download CSV", f, "report.csv")
        except FileNotFoundError:
            st.info("CSV report not found.")

        try:
            with open("output/report.xlsx", "rb") as f:
                st.download_button("Download Excel", f, "report.xlsx")
        except FileNotFoundError:
            st.info("Excel report not found.")

        try:
            with open("output/report.pdf", "rb") as f:
                st.download_button("Download PDF", f, "report.pdf")
        except FileNotFoundError:
            st.info("PDF report not found.")
    else:
        st.success("No findings detected.")