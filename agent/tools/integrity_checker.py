import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, call_name, is_dynamic_string, references_names
from agent.models import Finding, OWASPCategory, SeverityLevel

EXTERNAL = {"request", "input", "data", "payload", "body", "params"}
SUBPROCESS_FNS = {"subprocess.run", "subprocess.call", "subprocess.Popen"}


class IntegrityChecker(ASTChecker):
    """A08 Software/Data Integrity — eval/exec eksternal, subprocess & open dinamis."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A08

    @property
    def name(self) -> str:
        return "Software & Data Integrity Failures Checker (A08:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = call_name(node)
            line = node.lineno

            # eval/exec dengan data eksternal
            if fn in ("eval", "exec") and node.args and references_names(node.args[0], EXTERNAL):
                findings.append(Finding(
                    owasp_category=OWASPCategory.A08, severity=SeverityLevel.CRITICAL,
                    title=f"{fn}() dengan Data Eksternal",
                    description=f"{fn}() pada data dari request/input memungkinkan eksekusi kode arbitrer.",
                    line_number=line,
                    recommendation="Jangan gunakan eval/exec pada data eksternal; pakai ast.literal_eval().",
                ))
            # subprocess dengan string dinamis
            elif fn in SUBPROCESS_FNS and any(is_dynamic_string(a) for a in node.args):
                findings.append(Finding(
                    owasp_category=OWASPCategory.A08, severity=SeverityLevel.HIGH,
                    title="subprocess dengan String Dinamis",
                    description="Perintah subprocess dibangun dari string dinamis, rentan command injection.",
                    line_number=line,
                    recommendation="Gunakan list argument: subprocess.run(['ls', user_dir], shell=False).",
                ))
            # open() dengan path dinamis / eksternal
            elif fn == "open" and node.args and (
                is_dynamic_string(node.args[0]) or references_names(node.args[0], EXTERNAL)
            ):
                findings.append(Finding(
                    owasp_category=OWASPCategory.A08, severity=SeverityLevel.HIGH,
                    title="File open() dengan Path Dinamis",
                    description="Membuka file dengan path dari input user rentan path traversal.",
                    line_number=line,
                    recommendation="Validasi path dengan os.path.realpath() dan batasi ke direktori diizinkan.",
                ))
        return findings

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'eval\s*\(\s*(request|input|data|payload|body|params)', SeverityLevel.CRITICAL,
             "eval() dengan Data Eksternal"),
            (r'exec\s*\(\s*(request|input|data|payload|body|params)', SeverityLevel.CRITICAL,
             "exec() dengan Data Eksternal"),
            (r'subprocess\.(run|call|Popen)\s*\(.*\+', SeverityLevel.HIGH,
             "subprocess dengan String Dinamis"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A08, severity=sev, title=title,
                        description="Operasi berisiko terhadap integritas kode/data.",
                        line_number=i, vulnerable_code=line.strip(),
                        recommendation="Hindari eksekusi/deserialization data eksternal tanpa validasi.",
                    ))
        return findings
