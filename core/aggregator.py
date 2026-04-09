from typing import List, Dict, Any


def normalize_severity(severity: str) -> str:
    if not severity:
        return "UNKNOWN"

    sev = severity.strip().upper()

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "UNKNOWN",
    }

    return mapping.get(sev, "UNKNOWN")


def validate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "service": finding.get("service", "Unknown"),
        "resource_name": finding.get("resource_name", "Unknown"),
        "issue": finding.get("issue", "No issue provided"),
        "severity": normalize_severity(finding.get("severity", "UNKNOWN")),
        "recommendation": finding.get("recommendation", "No recommendation provided"),
        "description": finding.get("description", ""),
    }


def aggregate_findings(*finding_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_findings = []

    for finding_list in finding_lists:
        if not finding_list:
            continue

        for finding in finding_list:
            all_findings.append(validate_finding(finding))

    return all_findings


def severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in findings:
        severity = normalize_severity(finding.get("severity", "UNKNOWN"))
        summary[severity] += 1

    return summary