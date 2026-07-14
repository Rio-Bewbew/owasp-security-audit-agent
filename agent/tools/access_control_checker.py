import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, references_names
from agent.models import Finding, OWASPCategory, SeverityLevel

SENSITIVE_PREFIXES = ("delete", "update", "admin", "manage", "remove")
AUTH_MARKERS = ("login_required", "requires_auth", "auth", "permission")
REQUEST_ATTRS = {"args", "form", "json", "data"}


def _deco_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _deco_name(node.func)
    return ""


class AccessControlChecker(ASTChecker):
    """A01 Broken Access Control — path traversal, IDOR, fungsi sensitif tanpa auth."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A01

    @property
    def name(self) -> str:
        return "Broken Access Control Checker (A01:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            # Path traversal di string literal
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "../" in node.value or "..\\" in node.value:
                    findings.append(self._f(SeverityLevel.HIGH, "Path Traversal",
                        "Pola path traversal dapat mengakses file di luar direktori yang diizinkan.",
                        node.lineno, "Validasi path dengan os.path.realpath() dan batasi ke direktori diizinkan."))

            # Role/permission diambil langsung dari request
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id.lower() in ("role", "user_role"):
                        if references_names(node.value, {"request"}):
                            findings.append(self._f(SeverityLevel.HIGH, "Role Diambil dari Request",
                                "Role/permission diambil langsung dari input user tanpa verifikasi server-side.",
                                node.lineno, "Ambil role dari session/database server-side, bukan dari request."))

            # IDOR: request.args[...] / form / json / data
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
                attr = node.value
                if attr.attr in REQUEST_ATTRS and isinstance(attr.value, ast.Name) and attr.value.id == "request":
                    findings.append(self._f(SeverityLevel.MEDIUM, "Potensi IDOR",
                        "Data dari request dipakai langsung tanpa verifikasi otorisasi.",
                        node.lineno, "Verifikasi user yang login berhak atas resource yang diminta."))

            # Fungsi sensitif tanpa dekorator autentikasi
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.lower().startswith(SENSITIVE_PREFIXES):
                    decos = " ".join(_deco_name(d) for d in node.decorator_list).lower()
                    if not any(m in decos for m in AUTH_MARKERS):
                        findings.append(self._f(SeverityLevel.MEDIUM, "Fungsi Sensitif Tanpa Autentikasi",
                            f"Fungsi '{node.name}' tidak terdeteksi punya pengecekan autentikasi.",
                            node.lineno, "Tambahkan @login_required atau cek autentikasi di awal fungsi."))
        return findings

    def _f(self, sev, title, desc, line, rec) -> Finding:
        return Finding(owasp_category=OWASPCategory.A01, severity=sev, title=title,
                       description=desc, line_number=line, recommendation=rec)

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'\.\./|\.\.\\', SeverityLevel.HIGH, "Path Traversal"),
            (r'role\s*=\s*request\.|user_role\s*=\s*request\.', SeverityLevel.HIGH,
             "Role Diambil dari Request"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._f(sev, title, "Masalah kontrol akses terdeteksi.", i,
                                            "Terapkan verifikasi otorisasi server-side."))
        return findings
