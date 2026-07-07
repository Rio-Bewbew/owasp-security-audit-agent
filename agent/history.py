"""
Scan History — simpan dan baca riwayat hasil audit ke file JSON lokal.
"""
import json
import os
from datetime import datetime
from typing import List, Dict, Any
from agent.models import Finding, SeverityLevel

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "..", "scan_history.json")


def _finding_to_dict(f: Finding) -> Dict:
    return {
        "title":          f.title,
        "severity":       f.severity.value,
        "owasp_category": f.owasp_category.value,
        "line_number":    f.line_number,
        "description":    f.description,
        "recommendation": f.recommendation,
        "vulnerable_code": f.vulnerable_code or "",
    }


def save_scan(filename: str, findings: List[Finding], summary: str) -> None:
    """Simpan hasil scan ke history file."""
    history = load_all()

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename":  filename,
        "total":     len(findings),
        "critical":  sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
        "high":      sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
        "medium":    sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM),
        "low":       sum(1 for f in findings if f.severity == SeverityLevel.LOW),
        "summary":   summary,
        "findings":  [_finding_to_dict(f) for f in findings],
    }

    history.append(entry)

    # Simpan maksimum 20 scan terakhir
    if len(history) > 20:
        history = history[-20:]

    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as fp:
            json.dump(history, fp, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_all() -> List[Dict[str, Any]]:
    """Load semua riwayat scan."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return []


def clear_history() -> None:
    """Hapus semua riwayat scan."""
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
