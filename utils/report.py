import json
import os
import csv
import pandas as pd
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def save_pdf_report(findings, filename="output/report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    y = height - 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "AWS Cloud Security Audit Report")

    y -= 30
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Total Findings: {len(findings)}")

    y -= 25
    for item in findings:
        line = (
            f"[{item.get('severity', '')}] "
            f"{item.get('service', '')} | "
            f"{item.get('resource', '')} | "
            f"{item.get('issue', '')}"
        )

        if y < 50:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 10)

        c.drawString(50, y, line[:110])
        y -= 18

    c.save()


def save_report(findings):
    os.makedirs("output", exist_ok=True)

    with open("output/report.json", "w") as f:
        json.dump(findings, f, indent=4)

    with open("output/report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "Resource", "Resource Name", "Issue", "Severity", "Recommendation"])

        for item in findings:
            writer.writerow([
                item.get("service", ""),
                item.get("resource", ""),
                item.get("resource_name", ""),
                item.get("issue", ""),
                item.get("severity", ""),
                item.get("recommendation", "")
            ])

    df = pd.DataFrame(findings)
    df.to_excel("output/report.xlsx", index=False)

    save_pdf_report(findings)

    print("\nReports saved:")
    print("→ output/report.json")
    print("→ output/report.csv")
    print("→ output/report.xlsx")
    print("→ output/report.pdf")


def print_summary(findings):
    print("\n=== Severity Summary ===")

    counter = Counter(f["severity"] for f in findings)

    for sev in ["Critical", "High", "Medium", "Low"]:
        if sev in counter:
            print(f"{sev}: {counter[sev]}")