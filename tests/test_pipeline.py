"""Smoke test pipeline: deteksi checker & kompilasi graph (tanpa memanggil LLM)."""
from agent.registry import CheckerRegistry
from agent.graph import build_graph, run_checkers

VULNERABLE = '''
password = "admin123"
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
import os
os.system("ls " + user_input)
'''


def test_all_checkers_importable():
    # semua modul checker bisa di-import & diinstansiasi via discovery
    r = CheckerRegistry()
    assert r.discover_local("agent.tools") == 10


def test_run_checkers_detects_vulnerabilities():
    # gunakan registry global lewat build_graph agar terisi
    build_graph()
    out = run_checkers({"code": VULNERABLE, "filename": "t.py"})
    findings = out["findings"]
    assert len(findings) >= 3
    cats = {f.owasp_category.name for f in findings}
    # setidaknya deteksi crypto (hardcoded pwd), injection, insecure design
    assert {"A04", "A05"}.issubset(cats)


def test_build_graph_compiles():
    graph = build_graph()
    # objek graph terkompilasi punya method invoke
    assert hasattr(graph, "invoke")


def test_clean_code_no_findings():
    out = run_checkers({"code": "x = 1 + 1\n", "filename": "ok.py"})
    assert out["escalated"] is False
