"""
Dependency Scanner — cek requirements.txt terhadap versi library yang diketahui rentan.
Menggunakan PyPI JSON API untuk mendapatkan versi terbaru.
"""
import re
import json
import urllib.request
from typing import List, Dict
from dataclasses import dataclass


# Daftar library yang diketahui punya CVE di versi tertentu
# Format: {nama_package: {"safe_version": "x.y.z", "cve": "CVE-XXXX", "desc": "..."}}
KNOWN_VULNERABLE = {
    "django": {
        "safe_below": "4.2.0",
        "cve": "CVE-2023-36053",
        "desc": "Django < 4.2.0 rentan terhadap ReDoS pada EmailValidator",
        "fix": "Upgrade ke Django >= 4.2.0"
    },
    "flask": {
        "safe_below": "2.3.0",
        "cve": "CVE-2023-30861",
        "desc": "Flask < 2.3.0 rentan cookie session tidak ter-expire",
        "fix": "Upgrade ke Flask >= 2.3.0"
    },
    "requests": {
        "safe_below": "2.31.0",
        "cve": "CVE-2023-32681",
        "desc": "requests < 2.31.0 bocorkan header Proxy-Authorization ke redirect",
        "fix": "Upgrade ke requests >= 2.31.0"
    },
    "pillow": {
        "safe_below": "10.0.0",
        "cve": "CVE-2023-44271",
        "desc": "Pillow < 10.0.0 rentan DoS via ImageFont",
        "fix": "Upgrade ke Pillow >= 10.0.0"
    },
    "cryptography": {
        "safe_below": "41.0.0",
        "cve": "CVE-2023-38325",
        "desc": "cryptography < 41.0.0 rentan Bleichenbacher timing attack",
        "fix": "Upgrade ke cryptography >= 41.0.0"
    },
    "pyyaml": {
        "safe_below": "6.0",
        "cve": "CVE-2020-14343",
        "desc": "PyYAML < 6.0 rentan arbitrary code execution via yaml.load()",
        "fix": "Upgrade ke PyYAML >= 6.0 dan gunakan yaml.safe_load()"
    },
    "paramiko": {
        "safe_below": "3.3.0",
        "cve": "CVE-2023-48795",
        "desc": "Paramiko < 3.3.0 rentan Terrapin SSH prefix truncation attack",
        "fix": "Upgrade ke paramiko >= 3.3.0"
    },
    "sqlalchemy": {
        "safe_below": "2.0.0",
        "cve": "CVE-2019-7164",
        "desc": "SQLAlchemy < 2.0 rentan SQL injection via order_by() dengan input user",
        "fix": "Upgrade ke SQLAlchemy >= 2.0.0"
    },
    "urllib3": {
        "safe_below": "2.0.7",
        "cve": "CVE-2023-45803",
        "desc": "urllib3 < 2.0.7 bocorkan request body saat redirect ke method yang berbeda",
        "fix": "Upgrade ke urllib3 >= 2.0.7"
    },
    "aiohttp": {
        "safe_below": "3.9.0",
        "cve": "CVE-2023-49081",
        "desc": "aiohttp < 3.9.0 rentan HTTP request smuggling",
        "fix": "Upgrade ke aiohttp >= 3.9.0"
    },
}


@dataclass
class DepFinding:
    package: str
    installed_version: str
    safe_version: str
    cve: str
    description: str
    fix: str
    severity: str = "HIGH"


def _parse_version(v: str):
    """Parse versi string jadi tuple int untuk perbandingan."""
    try:
        return tuple(int(x) for x in re.split(r'[.\-]', v.strip()) if x.isdigit())
    except Exception:
        return (0,)


def _is_vulnerable(installed: str, safe_below: str) -> bool:
    """Return True jika installed < safe_below."""
    return _parse_version(installed) < _parse_version(safe_below)


def _get_latest_version(package: str) -> str:
    """Ambil versi terbaru dari PyPI JSON API."""
    try:
        url = f"https://pypi.org/pypi/{package}/json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except Exception:
        return "unknown"


def scan_requirements(content: str) -> List[DepFinding]:
    """
    Scan isi requirements.txt dan deteksi dependency yang rentan.
    content: string isi file requirements.txt
    """
    findings = []
    lines = content.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse nama package dan versi
        # Format: package==x.y.z atau package>=x.y.z atau package
        match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=<>!~]{1,2}\s*([0-9][^\s,;]*)', line)
        if not match:
            # Package tanpa versi
            pkg_name = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
            if pkg_name:
                pkg = pkg_name.group(1).lower().replace("-", "_").replace(".", "_")
                if pkg in KNOWN_VULNERABLE:
                    info = KNOWN_VULNERABLE[pkg]
                    findings.append(DepFinding(
                        package=pkg_name.group(1),
                        installed_version="unspecified",
                        safe_version=info["safe_below"],
                        cve=info["cve"],
                        description=info["desc"] + " — Versi tidak dispesifikasi, tidak bisa verifikasi keamanan.",
                        fix=info["fix"],
                        severity="MEDIUM"
                    ))
            continue

        pkg_raw  = match.group(1)
        version  = match.group(2).split(",")[0].strip()
        pkg_key  = pkg_raw.lower().replace("-", "_").replace(".", "_")

        # Cek nama alternatif (pyyaml → pyyaml)
        pkg_lookup = pkg_key
        if pkg_key not in KNOWN_VULNERABLE:
            # Coba tanpa underscore
            pkg_lookup = pkg_raw.lower().replace("_", "").replace("-", "")
            candidates = [k for k in KNOWN_VULNERABLE if k.replace("_","").replace("-","") == pkg_lookup]
            pkg_lookup = candidates[0] if candidates else None

        if pkg_lookup and pkg_lookup in KNOWN_VULNERABLE:
            info = KNOWN_VULNERABLE[pkg_lookup]
            if _is_vulnerable(version, info["safe_below"]):
                findings.append(DepFinding(
                    package=pkg_raw,
                    installed_version=version,
                    safe_version=info["safe_below"],
                    cve=info["cve"],
                    description=info["desc"],
                    fix=info["fix"],
                    severity="HIGH"
                ))

    return findings
