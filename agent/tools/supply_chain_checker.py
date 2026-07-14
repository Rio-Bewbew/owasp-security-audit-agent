import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, call_name, has_keyword, is_dynamic_string
from agent.models import Finding, OWASPCategory, SeverityLevel

# Fungsi deserialization berbahaya -> (severity, judul)
UNSAFE_DESERIALIZE = {
    "pickle.loads": "pickle", "pickle.load": "pickle",
    "marshal.loads": "marshal", "marshal.load": "marshal",
}


class SupplyChainChecker(ASTChecker):
    """A03 Software Supply Chain Failures — deserialization & dynamic import via AST."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A03

    @property
    def name(self) -> str:
        return "Software Supply Chain Failures Checker (A03:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = call_name(node)
            line = node.lineno

            if fn in UNSAFE_DESERIALIZE:
                lib = UNSAFE_DESERIALIZE[fn]
                findings.append(Finding(
                    owasp_category=OWASPCategory.A03, severity=SeverityLevel.CRITICAL,
                    title=f"Unsafe Deserialization dengan {lib}",
                    description=f"{fn} dapat mengeksekusi kode arbitrer dari data tidak tepercaya.",
                    line_number=line,
                    recommendation="Hindari untuk data eksternal; gunakan json.loads() yang aman.",
                ))
            elif fn == "yaml.load":
                # aman jika ada Loader=SafeLoader/BaseLoader
                loader = has_keyword(node, "Loader")
                safe = loader and isinstance(loader.value, ast.Attribute) and \
                    loader.value.attr in ("SafeLoader", "BaseLoader")
                if not safe:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A03, severity=SeverityLevel.HIGH,
                        title="yaml.load Tanpa SafeLoader",
                        description="yaml.load() tanpa SafeLoader dapat mengeksekusi kode Python arbitrer.",
                        line_number=line,
                        recommendation="Gunakan yaml.safe_load() atau Loader=yaml.SafeLoader.",
                    ))
            elif fn == "__import__" and node.args and not isinstance(node.args[0], ast.Constant):
                findings.append(self._dyn_import("__import__()", line))
            elif fn == "importlib.import_module" and node.args and is_dynamic_string(node.args[0]):
                findings.append(self._dyn_import("importlib.import_module()", line))
        return findings

    def _dyn_import(self, label: str, line) -> Finding:
        return Finding(
            owasp_category=OWASPCategory.A03, severity=SeverityLevel.HIGH,
            title=f"Dynamic Import via {label}",
            description=f"{label} dengan nilai dinamis dapat memuat modul berbahaya.",
            line_number=line,
            recommendation="Whitelist nama modul yang diizinkan sebelum import dinamis.",
        )

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        patterns = [
            (r'pickle\.loads?\s*\(', SeverityLevel.CRITICAL, "Unsafe Deserialization dengan pickle"),
            (r'marshal\.loads?\s*\(', SeverityLevel.CRITICAL, "Unsafe Deserialization dengan marshal"),
            (r'yaml\.load\s*\((?!.*SafeLoader|.*BaseLoader)', SeverityLevel.HIGH, "yaml.load Tanpa SafeLoader"),
        ]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, sev, title in patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A03, severity=sev, title=title,
                        description="Deserialization/import tidak aman.", line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan alternatif yang aman / whitelist.",
                    ))
        return findings
