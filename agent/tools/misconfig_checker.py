import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, const_str
from agent.models import Finding, OWASPCategory, SeverityLevel


class MisconfigChecker(ASTChecker):
    """A02 Security Misconfiguration — DEBUG, ALLOWED_HOSTS, SECRET_KEY, HTTP via AST."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A02

    @property
    def name(self) -> str:
        return "Security Misconfiguration Checker (A02:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    name = target.id
                    val = node.value
                    if name == "DEBUG" and isinstance(val, ast.Constant) and val.value is True:
                        findings.append(self._f(SeverityLevel.HIGH, "DEBUG Mode Aktif",
                            "DEBUG=True mengekspos stack trace & info sensitif ke user.",
                            node.lineno, "Set DEBUG=False di production via environment variable."))
                    elif name == "ALLOWED_HOSTS" and isinstance(val, (ast.List, ast.Tuple)):
                        if any(const_str(e) == "*" for e in val.elts):
                            findings.append(self._f(SeverityLevel.MEDIUM, "ALLOWED_HOSTS Terlalu Luas",
                                "ALLOWED_HOSTS=['*'] mengizinkan request dari semua host.",
                                node.lineno, "Tentukan host spesifik, mis. ['yourdomain.com']."))
                    elif name == "SECRET_KEY":
                        s = const_str(val)
                        if s is not None and len(s) <= 20:
                            findings.append(self._f(SeverityLevel.CRITICAL,
                                "SECRET_KEY Lemah/Hardcoded",
                                "SECRET_KEY hardcoded & pendek membahayakan keamanan aplikasi.",
                                node.lineno, "Generate kuat: secrets.token_hex(50), simpan di env."))
            # HTTP tidak terenkripsi di string literal
            s = const_str(node) if isinstance(node, ast.Constant) else None
            if s and re.search(r'http://(?!localhost|127\.0\.0\.1)', s):
                findings.append(self._f(SeverityLevel.MEDIUM, "Penggunaan HTTP (Tidak Terenkripsi)",
                    "Koneksi HTTP tidak terenkripsi, rentan man-in-the-middle.",
                    getattr(node, "lineno", None), "Gunakan HTTPS untuk semua koneksi eksternal."))
        return findings

    def _f(self, sev, title, desc, line, rec) -> Finding:
        return Finding(owasp_category=OWASPCategory.A02, severity=sev, title=title,
                       description=desc, line_number=line, recommendation=rec)

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'DEBUG\s*=\s*True', SeverityLevel.HIGH, "DEBUG Mode Aktif"),
            (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]', SeverityLevel.MEDIUM,
             "ALLOWED_HOSTS Terlalu Luas"),
            (r'http://(?!localhost|127\.0\.0\.1)', SeverityLevel.MEDIUM,
             "Penggunaan HTTP (Tidak Terenkripsi)"),
            (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', SeverityLevel.CRITICAL,
             "SECRET_KEY Lemah/Hardcoded"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line):
                    findings.append(self._f(sev, title, "Konfigurasi tidak aman.", i,
                                            "Perbaiki konfigurasi sesuai praktik aman."))
        return findings
