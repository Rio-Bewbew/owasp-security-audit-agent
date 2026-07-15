"""
owasp-audit-agent — framework audit keamanan kode Python berbasis OWASP Top 10 (2025).

API publik yang stabil:

    from agent import audit_code, build_graph, registry
    from agent import BaseChecker, Finding, OWASPCategory, SeverityLevel

Menulis checker baru: subclass `BaseChecker`, taruh file di `agent/tools/`
(otomatis ditemukan), atau distribusikan sebagai plugin lewat entry point
group "owasp_audit_agent.checkers".
"""

from agent.base_checker import BaseChecker
from agent.models import Finding, AuditResult, OWASPCategory, SeverityLevel
from agent.registry import CheckerRegistry, registry
from agent.config import AuditConfig
from agent.llm import build_llm, register_provider, available_providers
from agent.graph import build_graph, audit_code

__version__ = "0.4.0"

__all__ = [
    "audit_code",
    "build_graph",
    "build_llm",
    "register_provider",
    "available_providers",
    "registry",
    "CheckerRegistry",
    "AuditConfig",
    "BaseChecker",
    "Finding",
    "AuditResult",
    "OWASPCategory",
    "SeverityLevel",
    "__version__",
]
