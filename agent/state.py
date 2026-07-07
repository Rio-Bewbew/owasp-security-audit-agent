from typing import TypedDict, List, Optional
from agent.models import Finding


class AuditState(TypedDict):
    # Input
    code: str
    filename: str

    # Checkers output
    findings: List[Finding]

    # LLM output
    summary: str

    # Auto-fix output
    fixed_code: str
    fix_iterations: int        # Jumlah iterasi fix yang sudah dilakukan

    # Verification (re-scan setelah fix)
    verification_findings: List[Finding]
    verified: bool             # True jika sudah melewati verify_fixes node

    # Conditional routing
    escalated: bool            # True jika critical findings > 3
    escalation_message: str    # Pesan khusus saat eskalasi

    # Human-in-the-loop
    fix_approved: bool         # True jika user sudah approve fix
