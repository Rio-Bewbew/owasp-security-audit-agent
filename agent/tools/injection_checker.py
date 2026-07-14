import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, call_name, has_keyword, is_dynamic_string
from agent.models import Finding, OWASPCategory, SeverityLevel


class InjectionChecker(ASTChecker):
    """A05 Injection — deteksi command & SQL injection via AST (fallback regex)."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A05

    @property
    def name(self) -> str:
        return "Injection Checker (A05:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = call_name(node)
            line = getattr(node, "lineno", None)

            # Command injection: os.system / eval / exec
            cmd_labels = {"os.system": "os.system()", "eval": "eval()", "exec": "exec()"}
            if fn in cmd_labels:
                findings.append(self._cmd(cmd_labels[fn], line))
                continue

            # subprocess.* dengan shell=True
            if fn.startswith("subprocess."):
                kw = has_keyword(node, "shell")
                if kw and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(self._cmd("subprocess dengan shell=True", line))
                    continue

            # SQL injection: .execute(<f-string / konkatenasi / % format>)
            if fn.endswith("execute") and node.args and is_dynamic_string(node.args[0]):
                findings.append(Finding(
                    owasp_category=OWASPCategory.A05,
                    severity=SeverityLevel.CRITICAL,
                    title="SQL Injection",
                    description="Query SQL dibangun dengan string dinamis (f-string/konkatenasi) yang tidak aman.",
                    line_number=line,
                    vulnerable_code=self._src(code, line),
                    recommendation="Gunakan parameterized query: cursor.execute('... WHERE id = %s', (user_id,))",
                ))
        return findings

    def _cmd(self, label: str, line) -> Finding:
        return Finding(
            owasp_category=OWASPCategory.A05,
            severity=SeverityLevel.HIGH,
            title=f"Command Injection via {label}",
            description=f"Penggunaan {label} dapat memungkinkan eksekusi perintah berbahaya.",
            line_number=line,
            recommendation="Hindari eval/exec. Gunakan subprocess dengan shell=False dan validasi input.",
        )

    @staticmethod
    def _src(code: str, line) -> str:
        if not line:
            return ""
        lines = code.split("\n")
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    # ── Fallback regex (dipakai hanya jika kode gagal di-parse) ───────────────
    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        sql_patterns = [r'execute\s*\(\s*f["\']', r'execute\s*\(\s*["\'].*\+',
                        r'execute\s*\(\s*["\'].*%\s*\w']
        cmd_patterns = [(r'os\.system\s*\(', "os.system()"),
                        (r'subprocess\.[a-z]+\(.*shell\s*=\s*True', "subprocess dengan shell=True"),
                        (r'\beval\s*\(', "eval()"), (r'\bexec\s*\(', "exec()")]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A05, severity=SeverityLevel.CRITICAL,
                        title="SQL Injection",
                        description="Query SQL dibangun dengan string formatting yang tidak aman.",
                        line_number=i, vulnerable_code=line.strip(),
                        recommendation="Gunakan parameterized query.",
                    ))
                    break
            for pattern, label in cmd_patterns:
                if re.search(pattern, line):
                    findings.append(self._cmd(label, i))
        return findings
