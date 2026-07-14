import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, const_str, has_keyword
from agent.models import Finding, OWASPCategory, SeverityLevel


def _is_password_ref(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id.lower() == "password"
    if isinstance(node, ast.Attribute):
        return node.attr.lower() == "password"
    return False


class AuthChecker(ASTChecker):
    """A07 Authentication Failures — perbandingan password plaintext & SSL verify off."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A07

    @property
    def name(self) -> str:
        return "Authentication Failures Checker (A07:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            # password == "literal"
            if isinstance(node, ast.Compare) and any(isinstance(op, ast.Eq) for op in node.ops):
                operands = [node.left, *node.comparators]
                has_pw = any(_is_password_ref(o) for o in operands)
                has_literal = any(const_str(o) is not None for o in operands)
                if has_pw and has_literal:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A07, severity=SeverityLevel.CRITICAL,
                        title="Perbandingan Password Plaintext",
                        description="Password dibandingkan langsung sebagai string literal.",
                        line_number=node.lineno,
                        recommendation="Gunakan bcrypt/argon2 untuk hash & verifikasi password.",
                    ))
            # verify=False pada pemanggilan (requests dll)
            if isinstance(node, ast.Call):
                kw = has_keyword(node, "verify")
                if kw and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A07, severity=SeverityLevel.MEDIUM,
                        title="SSL Verification Dinonaktifkan",
                        description="verify=False menonaktifkan validasi sertifikat SSL (rentan MITM).",
                        line_number=node.lineno,
                        recommendation="Gunakan verify=True atau sediakan path CA certificate.",
                    ))
        return findings

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'password\s*==\s*["\']', SeverityLevel.CRITICAL, "Perbandingan Password Plaintext"),
            (r'verify\s*=\s*False', SeverityLevel.MEDIUM, "SSL Verification Dinonaktifkan"),
            (r'if\s+.*username\s*==.*and\s*.*password\s*==', SeverityLevel.HIGH,
             "Autentikasi dengan Kredensial Hardcoded"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A07, severity=sev, title=title,
                        description="Masalah autentikasi terdeteksi.", line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan hashing password & validasi sertifikat.",
                    ))
        return findings
