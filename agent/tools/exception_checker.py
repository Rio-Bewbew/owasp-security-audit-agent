import ast
import re
from typing import List

from agent.ast_utils import ASTChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


def _is_swallow_body(body: List[ast.stmt]) -> bool:
    """True jika body handler hanya 'pass' atau '...' (exception ditelan)."""
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
        return True
    return False


class ExceptionChecker(ASTChecker):
    """A10 Mishandling of Exceptional Conditions — exception ditelan, return di finally, div by zero."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A10

    @property
    def name(self) -> str:
        return "Mishandling of Exceptional Conditions Checker (A10:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        protected_div = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                # Div di dalam try dianggap sudah tertangani
                for d in ast.walk(node):
                    if isinstance(d, ast.BinOp) and isinstance(d.op, ast.Div):
                        protected_div.add(id(d))
                # return di dalam finally
                for stmt in node.finalbody:
                    if any(isinstance(s, ast.Return) for s in ast.walk(stmt)):
                        findings.append(self._f(SeverityLevel.MEDIUM, "return di dalam finally",
                            "return di finally menelan exception yang sedang diproses.",
                            getattr(node, "lineno", None),
                            "Hindari return di dalam finally block."))
                        break

            if isinstance(node, ast.ExceptHandler) and _is_swallow_body(node.body):
                bare = node.type is None
                findings.append(self._f(SeverityLevel.HIGH,
                    "Exception Ditelan Tanpa Penanganan" + (" (bare except)" if bare else ""),
                    "Exception ditangkap lalu diabaikan tanpa penanganan atau logging.",
                    node.lineno,
                    "Tangkap exception spesifik dan log: except ValueError as e: logging.error(e)."))

        # Division berpotensi ZeroDivisionError, di luar try, dengan pembagi variabel
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) \
                    and isinstance(node.right, ast.Name) and id(node) not in protected_div:
                findings.append(self._f(SeverityLevel.LOW, "Potensi Division by Zero",
                    "Operasi pembagian tanpa penanganan ZeroDivisionError.",
                    node.lineno, "Validasi pembagi > 0 atau bungkus dengan try-except ZeroDivisionError."))
        return findings

    def _f(self, sev, title, desc, line, rec) -> Finding:
        return Finding(owasp_category=OWASPCategory.A10, severity=sev, title=title,
                       description=desc, line_number=line, recommendation=rec)

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r'^\s*except\s*:\s*$', line) or re.search(r'except\s+Exception\s+as\s+\w+\s*:', line):
                nxt = lines[i].strip() if i < len(lines) else ""
                if nxt in ("pass", "..."):
                    findings.append(self._f(SeverityLevel.HIGH, "Exception Ditelan Tanpa Penanganan",
                        "Exception ditangkap dan diabaikan.", i,
                        "Tangkap exception spesifik dan log errornya."))
        return findings
