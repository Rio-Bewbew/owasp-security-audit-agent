import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, call_name, const_str
from agent.models import Finding, OWASPCategory, SeverityLevel

INSECURE_RANDOM = {"random.random", "random.randint", "random.choice"}


class InsecureDesignChecker(ASTChecker):
    """A06 Insecure Design — random tak aman, sleep hardcoded, SELECT tanpa LIMIT, input sensitif."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A06

    @property
    def name(self) -> str:
        return "Insecure Design Checker (A06:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            # SELECT * tanpa LIMIT — di string biasa maupun bagian literal f-string
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if re.search(r'SELECT\s+\*\s+FROM', v, re.IGNORECASE) and not re.search(r'LIMIT', v, re.IGNORECASE):
                    findings.append(self._f(SeverityLevel.MEDIUM, "Query SELECT * Tanpa LIMIT",
                        "Query tanpa LIMIT dapat mengembalikan seluruh isi tabel (potensi DoS).",
                        node.lineno, "Tambahkan LIMIT pada query."))

            if isinstance(node, ast.Call):
                fn = call_name(node)
                if fn == "time.sleep" and node.args and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, (int, float)):
                    findings.append(self._f(SeverityLevel.LOW, "Hardcoded Sleep/Delay",
                        "Delay hardcoded dapat dimanfaatkan untuk timing attack.",
                        node.lineno, "Gunakan delay konstan yang tidak bergantung input."))
                elif fn in INSECURE_RANDOM:
                    findings.append(self._f(SeverityLevel.MEDIUM, "random untuk Keperluan Keamanan",
                        "Module random tidak aman untuk token/OTP/session ID.",
                        node.lineno, "Gunakan secrets: secrets.token_hex(16) / secrets.randbelow(n)."))
                elif fn == "input" and node.args:
                    prompt = const_str(node.args[0]) or ""
                    if any(w in prompt.lower() for w in ("password", "secret", "token")):
                        findings.append(self._f(SeverityLevel.HIGH, "Input Sensitif Tanpa Masking",
                            "Data sensitif diminta via input() yang menampilkan teks.",
                            node.lineno, "Gunakan getpass.getpass() untuk input rahasia."))
        return findings

    def _f(self, sev, title, desc, line, rec) -> Finding:
        return Finding(owasp_category=OWASPCategory.A06, severity=sev, title=title,
                       description=desc, line_number=line, recommendation=rec)

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'SELECT\s+\*\s+FROM(?!.*LIMIT|.*limit)', SeverityLevel.MEDIUM, "Query SELECT * Tanpa LIMIT"),
            (r'time\.sleep\s*\(\s*\d+\s*\)', SeverityLevel.LOW, "Hardcoded Sleep/Delay"),
            (r'random\.(random|randint|choice)\s*\(', SeverityLevel.MEDIUM, "random untuk Keperluan Keamanan"),
            (r'input\s*\(.*(password|secret|token)', SeverityLevel.HIGH, "Input Sensitif Tanpa Masking"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self._f(sev, title, "Pola desain tidak aman.", i,
                                            "Terapkan praktik desain aman."))
        return findings
