from langgraph.graph import StateGraph, START, END
from dotenv import load_dotenv
from agent.state import AuditState
from agent.registry import registry
from agent.rule_fixer import RuleBasedFixer
from agent.models import SeverityLevel
from agent.config import AuditConfig
from agent.llm import build_llm

load_dotenv()

# Konfigurasi runtime (audit.toml + env). Menggantikan nilai hardcoded.
config = AuditConfig.load()

# Dipertahankan untuk kompatibilitas; kini bersumber dari config.
MAX_FIX_ITERATIONS = config.max_fix_iterations

# LLM dibuat lazy: baru diinstansiasi saat pertama dibutuhkan, sehingga
# `import agent` tidak memaksa adanya API key / paket provider. Provider
# dipilih dari config.llm_provider (groq/openai/anthropic/google/ollama atau
# provider kustom terdaftar). Lihat agent/llm.py.
_llm = None


def get_llm():
    """Kembalikan instance LLM (dibuat sekali, lalu di-cache)."""
    global _llm
    if _llm is None:
        _llm = build_llm(config)
    return _llm


def run_checkers(state: AuditState) -> dict:
    """Jalankan semua 10 OWASP checker. Set escalated=True jika critical > 3."""
    all_findings = []
    for checker in registry.get_all():
        findings = checker.analyze(state["code"], state["filename"])
        all_findings.extend(findings)

    critical_count = sum(1 for f in all_findings if f.severity == SeverityLevel.CRITICAL)

    return {
        "findings": all_findings,
        "escalated": critical_count > config.escalation_threshold,
        "fix_iterations": 0,
        "verification_findings": [],
        "verified": False,
        "escalation_message": "",
    }


def escalate_alert(state: AuditState) -> dict:
    """Node eskalasi — dipanggil saat critical findings > 3."""
    critical = [f for f in state["findings"] if f.severity == SeverityLevel.CRITICAL]
    msg = (
        f"ESKALASI KEAMANAN: Ditemukan {len(critical)} kerentanan CRITICAL. "
        "Kode ini SANGAT BERBAHAYA dan harus segera diperbaiki sebelum deployment."
    )
    return {"escalation_message": msg}


def llm_analysis(state: AuditState) -> dict:
    """Executive summary dari LLM. Prompt lebih tegas jika eskalasi."""
    findings = state["findings"]

    if not findings:
        return {"summary": "Tidak ditemukan vulnerability. Kode relatif aman."}

    findings_text = "\n".join([
        f"- [{f.severity.value}] {f.title} (Baris {f.line_number}): {f.description}"
        for f in findings
    ])

    prefix = ""
    if state.get("escalated"):
        prefix = f"PERINGATAN KRITIS: {state.get('escalation_message', '')}\n\n"

    prompt = f"""{prefix}Kamu adalah security expert. Temuan security audit kode Python:

{findings_text}

Berikan:
1. Executive summary (2-3 kalimat) kondisi keamanan kode ini
2. Prioritas utama yang harus segera diperbaiki
3. Estimasi risiko keseluruhan (Rendah/Sedang/Tinggi/Kritis)

Jawab dalam Bahasa Indonesia, singkat dan jelas."""

    response = get_llm().invoke(prompt)
    return {"summary": response.content}


def auto_fix(state: AuditState) -> dict:
    """
    Rule-based fixer — deterministik.
    Hanya berjalan jika fix_approved = True (human-in-the-loop).
    Pada iterasi ke-2+, fix dari kode yang sudah pernah di-fix.
    """
    if not config.auto_fix:
        return {"fixed_code": state["code"]}

    if not state.get("fix_approved", True):
        return {"fixed_code": state["code"]}

    if not state["findings"]:
        return {"fixed_code": state["code"]}

    source = state.get("fixed_code") or state["code"]
    fixer = RuleBasedFixer()
    fixed_code, _ = fixer.fix(source)

    return {
        "fixed_code": fixed_code,
        "fix_iterations": state.get("fix_iterations", 0) + 1,
    }


def verify_fixes(state: AuditState) -> dict:
    """Re-scan fixed_code untuk verifikasi. Hasil disimpan di verification_findings."""
    fixed_code = state.get("fixed_code", "")
    if not fixed_code or fixed_code == state["code"]:
        return {"verification_findings": [], "verified": True}

    results = []
    for checker in registry.get_all():
        results.extend(checker.analyze(fixed_code, state["filename"]))

    return {"verification_findings": results, "verified": True}


# ── Conditional routing ────────────────────────────────────────────────────

def route_after_checkers(state: AuditState) -> str:
    return "escalate" if state.get("escalated") else "analyze"


def route_after_verify(state: AuditState) -> str:
    vf = state.get("verification_findings", [])
    iterations = state.get("fix_iterations", 0)
    still_risky = any(
        f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        for f in vf
    )
    if still_risky and iterations < config.max_fix_iterations:
        return "loop_fix"
    return "done"


# ── Build ──────────────────────────────────────────────────────────────────

def build_graph():
    """
    LangGraph workflow:
      START → run_checkers
        → [conditional] escalate_alert? → llm_analysis
        → auto_fix → verify_fixes
        → [conditional loop] auto_fix (max 2x) atau END
    """
    # Auto-discovery: pindai checker internal di agent/tools/ dan muat plugin
    # pihak ketiga via entry points. Tambah checker baru cukup dengan menaruh
    # file baru di agent/tools/ — tanpa menyentuh fungsi ini.
    registry.discover()
    # Terapkan seleksi checker dari config (enabled/disabled).
    registry.apply_config(config)

    wf = StateGraph(AuditState)
    wf.add_node("run_checkers",   run_checkers)
    wf.add_node("escalate_alert", escalate_alert)
    wf.add_node("llm_analysis",   llm_analysis)
    wf.add_node("auto_fix",       auto_fix)
    wf.add_node("verify_fixes",   verify_fixes)

    wf.add_edge(START, "run_checkers")

    wf.add_conditional_edges(
        "run_checkers",
        route_after_checkers,
        {"escalate": "escalate_alert", "analyze": "llm_analysis"}
    )
    wf.add_edge("escalate_alert", "llm_analysis")
    wf.add_edge("llm_analysis",   "auto_fix")
    wf.add_edge("auto_fix",       "verify_fixes")

    wf.add_conditional_edges(
        "verify_fixes",
        route_after_verify,
        {"loop_fix": "auto_fix", "done": END}
    )

    return wf.compile()


def audit_code(code: str, filename: str = "input.py") -> dict:
    """
    Entry point tingkat tinggi: jalankan audit lengkap atas sepotong kode
    Python dan kembalikan state akhir (findings, summary, fixed_code, dll).

    Contoh:
        from agent import audit_code
        result = audit_code(open("app.py").read(), "app.py")
        for f in result["findings"]:
            print(f.severity, f.title, f.line_number)
    """
    graph = build_graph()
    return graph.invoke({"code": code, "filename": filename})
