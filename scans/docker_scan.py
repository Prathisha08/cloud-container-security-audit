import json
import subprocess
from typing import List, Dict, Any

TRIVY_PATH = r"C:\Users\prath\AppData\Local\Microsoft\WinGet\Packages\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\trivy.exe"


def scan_docker_image(image_name: str) -> List[Dict[str, Any]]:
    findings = []

    command = [
        TRIVY_PATH,
        "image",
        "--scanners",
        "vuln",
        "--timeout",
        "15m",
        "--cache-backend",
        "memory",
        "--format",
        "json",
        image_name,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            print("Trivy scan failed:")
            print(result.stderr)
            return findings

        if not result.stdout.strip():
            print("Trivy returned empty output.")
            return findings

        data = json.loads(result.stdout)

        for target in data.get("Results", []):
            target_name = target.get("Target", image_name)
            vulnerabilities = target.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                findings.append({
                    "service": "Docker",
                    "resource": target_name,
                    "issue": vuln.get("Title") or vuln.get("VulnerabilityID", "Unknown vulnerability"),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "recommendation": vuln.get("FixedVersion", "No fixed version provided"),
                    "description": vuln.get("Description", ""),
                })

    except json.JSONDecodeError:
        print("Failed to parse Trivy JSON output.")
    except Exception as e:
        print(f"Unexpected error during Docker scan: {e}")

    return findings