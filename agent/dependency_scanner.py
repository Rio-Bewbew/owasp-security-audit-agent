"""
Dependency Scanner — deteksi dependency rentan pada requirements.txt.

Dua sumber data:
  1. OSV.dev (default, online) — database kerentanan open-source dari Google yang
     mencakup ribuan advisory PyPI dan selalu diperbarui. Setiap paket+versi
     dicek ke https://api.osv.dev.
  2. Daftar bawaan KNOWN_VULNERABLE (fallback) — dipakai bila jaringan tidak
     tersedia, query OSV gagal, atau `online=False`.

Publik: scan_requirements(content, *, online=True, timeout=8) -> List[DepFinding]
"""
import json
import re
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Tuple

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Fallback offline — dipakai jika OSV tidak bisa dihubungi.
KNOWN_VULNERABLE = {
    "django": {"safe_below": "4.2.0", "cve": "CVE-2023-36053",
               "desc": "Django < 4.2.0 rentan ReDoS pada EmailValidator",
               "fix": "Upgrade ke Django >= 4.2.0"},
    "flask": {"safe_below": "2.3.0", "cve": "CVE-2023-30861",
              "desc": "Flask < 2.3.0 rentan cookie session tidak ter-expire",
              "fix": "Upgrade ke Flask >= 2.3.0"},
    "requests": {"safe_below": "2.31.0", "cve": "CVE-2023-32681",
                 "desc": "requests < 2.31.0 bocorkan header Proxy-Authorization ke redirect",
                 "fix": "Upgrade ke requests >= 2.31.0"},
    "pillow": {"safe_below": "10.0.0", "cve": "CVE-2023-44271",
               "desc": "Pillow < 10.0.0 rentan DoS via ImageFont",
               "fix": "Upgrade ke Pillow >= 10.0.0"},
    "cryptography": {"safe_below": "41.0.0", "cve": "CVE-2023-38325",
                     "desc": "cryptography < 41.0.0 rentan Bleichenbacher timing attack",
                     "fix": "Upgrade ke cryptography >= 41.0.0"},
    "pyyaml": {"safe_below": "6.0", "cve": "CVE-2020-14343",
               "desc": "PyYAML < 6.0 rentan arbitrary code execution via yaml.load()",
               "fix": "Upgrade ke PyYAML >= 6.0 dan gunakan yaml.safe_load()"},
    "paramiko": {"safe_below": "3.3.0", "cve": "CVE-2023-48795",
                 "desc": "Paramiko < 3.3.0 rentan Terrapin SSH prefix truncation attack",
                 "fix": "Upgrade ke paramiko >= 3.3.0"},
    "sqlalchemy": {"safe_below": "2.0.0", "cve": "CVE-2019-7164",
                   "desc": "SQLAlchemy < 2.0 rentan SQL injection via order_by() input user",
                   "fix": "Upgrade ke SQLAlchemy >= 2.0.0"},
    "urllib3": {"safe_below": "2.0.7", "cve": "CVE-2023-45803",
                "desc": "urllib3 < 2.0.7 bocorkan request body saat redirect",
                "fix": "Upgrade ke urllib3 >= 2.0.7"},
    "aiohttp": {"safe_below": "3.9.0", "cve": "CVE-2023-49081",
                "desc": "aiohttp < 3.9.0 rentan HTTP request smuggling",
                "fix": "Upgrade ke aiohttp >= 3.9.0"},
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
    source: str = "builtin"     # "osv" | "builtin"
    vuln_id: str = ""


def _parse_version(v: str):
    try:
        return tuple(int(x) for x in re.split(r'[.\-]', v.strip()) if x.isdigit())
    except Exception:
        return (0,)


def _is_vulnerable(installed: str, safe_below: str) -> bool:
    return _parse_version(installed) < _parse_version(safe_below)


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def parse_requirements(content: str) -> List[Tuple[str, Optional[str]]]:
    """Kembalikan list (nama_paket, versi_atau_None) dari isi requirements.txt."""
    result: List[Tuple[str, Optional[str]]] = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*[=<>!~]{1,2}\s*([0-9][^\s,;]*)', line)
        if m:
            result.append((m.group(1), m.group(2).split(",")[0].strip()))
            continue
        m2 = re.match(r'^([A-Za-z0-9_.\-]+)', line)
        if m2:
            result.append((m2.group(1), None))
    return result


# ── OSV.dev (online) ─────────────────────────────────────────────────────────

def _query_osv(name: str, version: str, timeout: float) -> Optional[list]:
    """Query OSV untuk satu paket+versi. Return list vuln, [] jika aman,
    atau None jika jaringan gagal (memicu fallback)."""
    body = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": "PyPI"},
    }).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return data.get("vulns", []) or []
    except Exception:
        return None


def _osv_fixed_version(vuln: dict, name: str) -> str:
    norm = _normalize(name)
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if _normalize(pkg.get("name", "")) != norm:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if ev.get("fixed"):
                    return ev["fixed"]
    return "lihat advisory"


def _map_severity(label: str) -> str:
    s = (label or "").upper()
    if "CRIT" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MOD" in s or "MED" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return "HIGH"


def _osv_severity(vuln: dict) -> str:
    for aff in vuln.get("affected", []):
        sev = aff.get("database_specific", {}).get("severity")
        if sev:
            return _map_severity(sev)
    ds = vuln.get("database_specific", {})
    if ds.get("severity"):
        return _map_severity(ds["severity"])
    return "HIGH"


def _cve_alias(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if str(alias).upper().startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def _finding_from_osv(name: str, version: str, vuln: dict) -> DepFinding:
    desc = (vuln.get("summary") or vuln.get("details") or "Kerentanan diketahui.").strip()
    if len(desc) > 300:
        desc = desc[:297] + "..."
    fixed = _osv_fixed_version(vuln, name)
    return DepFinding(
        package=name,
        installed_version=version,
        safe_version=fixed,
        cve=_cve_alias(vuln),
        description=desc,
        fix=f"Upgrade {name} ke versi {fixed} atau lebih baru." if fixed != "lihat advisory"
            else f"Upgrade {name} ke versi yang sudah diperbaiki.",
        severity=_osv_severity(vuln),
        source="osv",
        vuln_id=vuln.get("id", ""),
    )


# ── Fallback offline ─────────────────────────────────────────────────────────

def _scan_offline_one(raw_name: str, version: Optional[str]) -> List[DepFinding]:
    key = _normalize(raw_name)
    if key not in KNOWN_VULNERABLE:
        stripped = raw_name.lower().replace("_", "").replace("-", "")
        cand = [k for k in KNOWN_VULNERABLE if k.replace("_", "").replace("-", "") == stripped]
        key = cand[0] if cand else None
    if not key or key not in KNOWN_VULNERABLE:
        return []
    info = KNOWN_VULNERABLE[key]
    if version is None:
        return [DepFinding(raw_name, "unspecified", info["safe_below"], info["cve"],
                           info["desc"] + " — versi tidak dispesifikasi.", info["fix"],
                           "MEDIUM", "builtin")]
    if _is_vulnerable(version, info["safe_below"]):
        return [DepFinding(raw_name, version, info["safe_below"], info["cve"],
                           info["desc"], info["fix"], "HIGH", "builtin")]
    return []


# ── Public API ───────────────────────────────────────────────────────────────

def scan_requirements(content: str, *, online: bool = True, timeout: float = 8.0) -> List[DepFinding]:
    """
    Scan isi requirements.txt dan deteksi dependency rentan.

    online=True  -> query OSV.dev (fallback ke daftar bawaan jika jaringan gagal).
    online=False -> hanya pakai daftar bawaan KNOWN_VULNERABLE.
    """
    findings: List[DepFinding] = []
    use_online = online
    for raw_name, version in parse_requirements(content):
        if use_online and version:
            vulns = _query_osv(raw_name, version, timeout)
            if vulns is None:
                use_online = False              # jaringan gagal → offline utk sisanya
            else:
                findings.extend(_finding_from_osv(raw_name, version, v) for v in vulns)
                continue
        findings.extend(_scan_offline_one(raw_name, version))
    return findings
