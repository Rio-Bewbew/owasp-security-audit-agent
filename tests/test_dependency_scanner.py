"""Test dependency scanner: parsing, mode offline, parsing respons OSV, fallback."""
import agent.dependency_scanner as ds
from agent.dependency_scanner import parse_requirements, scan_requirements


def test_parse_requirements():
    content = "flask==2.0.0\n# komentar\n\nrequests>=2.28.0\nnumpy\n-r other.txt\n"
    parsed = parse_requirements(content)
    assert ("flask", "2.0.0") in parsed
    assert ("requests", "2.28.0") in parsed
    assert ("numpy", None) in parsed
    assert all(not n.startswith("-") for n, _ in parsed)


def test_offline_flags_known_vulnerable():
    findings = scan_requirements("flask==2.0.0\nurllib3==2.0.5\n", online=False)
    pkgs = {f.package for f in findings}
    assert "flask" in pkgs and "urllib3" in pkgs
    assert all(f.source == "builtin" for f in findings)


def test_offline_ignores_safe_and_unknown():
    findings = scan_requirements("flask==2.3.0\nnumpy==1.26.0\n", online=False)
    assert findings == []          # flask aman, numpy tak dikenal


def test_offline_unspecified_version_is_medium():
    findings = scan_requirements("django\n", online=False)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].installed_version == "unspecified"


def test_osv_response_parsed(monkeypatch):
    fake_vuln = {
        "id": "GHSA-xxxx",
        "aliases": ["CVE-2099-0001"],
        "summary": "Contoh kerentanan pada flask.",
        "affected": [{
            "package": {"name": "flask", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}],
            "database_specific": {"severity": "HIGH"},
        }],
    }
    monkeypatch.setattr(ds, "_query_osv", lambda name, version, timeout: [fake_vuln])
    findings = scan_requirements("flask==2.0.0\n", online=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "osv"
    assert f.cve == "CVE-2099-0001"
    assert f.safe_version == "2.3.0"
    assert f.severity == "HIGH"
    assert f.vuln_id == "GHSA-xxxx"


def test_osv_network_failure_falls_back_to_builtin(monkeypatch):
    # _query_osv mengembalikan None (jaringan gagal) -> pakai daftar bawaan
    monkeypatch.setattr(ds, "_query_osv", lambda name, version, timeout: None)
    findings = scan_requirements("flask==2.0.0\n", online=True)
    assert len(findings) == 1
    assert findings[0].source == "builtin"


def test_osv_no_vulns_means_clean(monkeypatch):
    monkeypatch.setattr(ds, "_query_osv", lambda name, version, timeout: [])
    findings = scan_requirements("flask==2.0.0\n", online=True)
    assert findings == []
