"""
SARIF 2.1.0 Exporter — Static Analysis Results Interchange Format.
Standard industri yang digunakan GitHub Security, VS Code, dan CI/CD tools.
"""
import json
from typing import List
from agent.models import Finding, SeverityLevel


SEVERITY_MAP = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH:     "error",
    SeverityLevel.MEDIUM:   "warning",
    SeverityLevel.LOW:      "note",
}

LEVEL_MAP = {
    SeverityLevel.CRITICAL: "9.0",
    SeverityLevel.HIGH:     "7.0",
    SeverityLevel.MEDIUM:   "5.0",
    SeverityLevel.LOW:      "3.0",
}


def export_sarif(filename: str, findings: List[Finding]) -> str:
    """
    Export findings ke format SARIF 2.1.0 JSON string.
    Bisa diimport ke GitHub Security tab atau VS Code Problems panel.
    """
    rules = {}
    results = []

    for f in findings:
        rule_id = f.owasp_category.value.split(":")[0].replace(":", "").replace(" ", "_")

        # Tambah rule jika belum ada
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.owasp_category.value,
                "shortDescription": {"text": f.owasp_category.value},
                "fullDescription":  {"text": f.description},
                "helpUri": f"https://owasp.org/Top10/",
                "properties": {
                    "security-severity": LEVEL_MAP.get(f.severity, "5.0"),
                    "tags": ["security", "owasp"]
                }
            }

        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"{f.title}: {f.description}\nRekomendasi: {f.recommendation}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": filename,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": max(1, f.line_number),
                        "snippet": {"text": f.vulnerable_code or ""}
                    }
                }
            }],
            "properties": {
                "severity": f.severity.value,
                "owasp_category": f.owasp_category.value
            }
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP Security Audit Agent",
                    "version": "1.0.0",
                    "informationUri": "https://owasp.org/Top10/",
                    "rules": list(rules.values())
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits"
        }]
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
