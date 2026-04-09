from typing import List, Dict


def get_high_critical_findings(findings: List[Dict]) -> List[Dict]:
    alert_levels = {"HIGH", "CRITICAL"}
    return [f for f in findings if f.get("severity", "").upper() in alert_levels]


def print_alerts(findings: List[Dict]) -> None:
    risky_findings = get_high_critical_findings(findings)

    print("\n=== Alerts ===")

    if not risky_findings:
        print("No HIGH or CRITICAL findings detected.")
        return

    print(f"High/Critical Findings: {len(risky_findings)}")

    for finding in risky_findings:
        severity = finding.get("severity", "UNKNOWN")
        service = finding.get("service", "Unknown")
        resource = finding.get("resource", "Unknown")
        issue = finding.get("issue", "No issue provided")

        print(f"[ALERT] [{severity}] {service} | {resource} | {issue}")