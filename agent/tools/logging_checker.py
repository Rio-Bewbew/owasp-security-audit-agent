import ast
import re
from typing import List

from agent.ast_utils import ASTChecker
from agent.models import Finding, OWASPCategory, SeverityLevel

LOG_METHODS = {"info", "debug", "warning", "error", "critical", "exception"}
LOG_BASES = {"log", "logger", "logging"}


def _is_log_call(node: ast.Call) -> bool:
    f = node.func
    if not isinstance(f, ast.Attribute) or f.attr not in LOG_METHODS:
        return False
    base = f.value
    name = base.id if isinstance(base, ast.Name) else (base.attr if isinstance(base, ast.Attribute) else "")
    return name in LOG_BASES


def _arg_text(node: ast.Call) -> str:
    """Gabungan teks literal + nama variabel dari argumen call (lowercased)."""
    parts = []
    for a in node.args:
        for sub in ast.walk(a):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                parts.append(sub.value.lower())
            elif isinstance(sub, ast.Name):
                parts.append(sub.id.lower())
    return " ".join(parts)


class LoggingChecker(ASTChecker):
    """A09 Logging & Alerting Failures — data sensitif ke log, error via print, except senyap."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A09

    @property
    def name(self) -> str:
        return "Security Logging Failures Checker (A09:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if _is_log_call(node):
                    text = _arg_text(node)
                    if "password" in text:
                        findings.append(self._f(SeverityLevel.CRITICAL, "Password Tercatat di Log",
                            "Password/kredensial sensitif muncul dalam pesan log.",
                            node.lineno, "Jangan pernah log password; log hanya identifier non-sensitif."))
                    elif "token" in text or "api_key" in text or "secret" in text:
                        findings.append(self._f(SeverityLevel.HIGH, "Token/API Key Tercatat di Log",
                            "Token/API key sensitif muncul dalam pesan log.",
                            node.lineno, "Mask/hapus data sensitif sebelum logging."))
                elif isinstance(node.func, ast.Name) and node.func.id == "print":
                    text = _arg_text(node)
                    if any(w in text for w in ("error", "exception", "traceback")):
                        findings.append(self._f(SeverityLevel.MEDIUM, "Error Ditampilkan via print()",
                            "print() untuk error dapat mengekspos stack trace ke user.",
                            node.lineno, "Gunakan logging.error(..., exc_info=True) dan pesan generik ke user."))

            # Bare except tanpa logging
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                has_log = any(isinstance(n, ast.Call) and _is_log_call(n) for n in ast.walk(node))
                if not has_log:
                    findings.append(self._f(SeverityLevel.HIGH, "Exception Ditangkap Tanpa Logging",
                        "Exception ditangkap diam-diam tanpa dicatat ke log.",
                        node.lineno, "Selalu log exception: except Exception: logging.error('...', exc_info=True)."))
        return findings

    def _f(self, sev, title, desc, line, rec) -> Finding:
        return Finding(owasp_category=OWASPCategory.A09, severity=sev, title=title,
                       description=desc, line_number=line, recommendation=rec)

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'(log|logger|logging)\.(info|debug|warning|error)\s*\(.*password', SeverityLevel.CRITICAL,
             "Password Tercatat di Log"),
            (r'print\s*\(.*(error|exception|traceback)', SeverityLevel.MEDIUM,
             "Error Ditampilkan via print()"),
            (r'except\s*:\s*$|except\s+Exception\s*:\s*$', SeverityLevel.HIGH,
             "Exception Ditangkap Tanpa Logging"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._f(sev, title, "Masalah logging keamanan.", i,
                                            "Terapkan logging aman tanpa data sensitif."))
        return findings
