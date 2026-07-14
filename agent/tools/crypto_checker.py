import ast
import re
from typing import List

from agent.ast_utils import ASTChecker, call_name, const_str
from agent.models import Finding, OWASPCategory, SeverityLevel

SECRET_NAMES = {"password", "secret_key", "api_key", "token"}
WEAK_HASHES = {"md5", "sha1", "hashlib.md5", "hashlib.sha1"}


class CryptoChecker(ASTChecker):
    """A04 Cryptographic Failures — hash lemah & kredensial hardcoded via AST."""

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A04

    @property
    def name(self) -> str:
        return "Cryptographic Failures Checker (A04:2025)"

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            # Kredensial hardcoded: <secret_name> = "literal"
            if isinstance(node, ast.Assign):
                value = const_str(node.value)
                if value is not None and len(value) >= 3:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.lower() in SECRET_NAMES:
                            findings.append(Finding(
                                owasp_category=OWASPCategory.A04,
                                severity=SeverityLevel.CRITICAL,
                                title=f"Kredensial Hardcoded: {target.id}",
                                description=f"Ditemukan nilai '{target.id}' yang ditulis langsung di kode.",
                                line_number=node.lineno,
                                recommendation="Simpan secrets di environment variables dan baca dengan os.getenv().",
                            ))
            # Hash lemah: hashlib.md5(...) / md5(...) / sha1
            if isinstance(node, ast.Call):
                fn = call_name(node)
                if fn in WEAK_HASHES:
                    label = fn if "." in fn else fn.upper()
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A04,
                        severity=SeverityLevel.HIGH,
                        title=f"Algoritma Hash Lemah: {label}",
                        description=f"{label} tidak aman dan rentan collision attack.",
                        line_number=node.lineno,
                        recommendation="Gunakan SHA-256/SHA-3: hashlib.sha256(data).hexdigest().",
                    ))
        return findings

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        weak = [(r'\bmd5\b', "MD5"), (r'\bsha1\b', "SHA1"),
                (r'hashlib\.md5', "hashlib.md5"), (r'hashlib\.sha1', "hashlib.sha1")]
        secrets = [(r'password\s*=\s*["\'][^"\']{3,}["\']', "password"),
                   (r'secret_key\s*=\s*["\'][^"\']{3,}["\']', "secret_key"),
                   (r'api_key\s*=\s*["\'][^"\']{3,}["\']', "api_key"),
                   (r'token\s*=\s*["\'][^"\']{3,}["\']', "token")]
        for i, line in enumerate(code.split("\n"), 1):
            for pattern, label in weak:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A04, severity=SeverityLevel.HIGH,
                        title=f"Algoritma Hash Lemah: {label}",
                        description=f"{label} tidak aman.", line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan SHA-256.",
                    ))
                    break
            for pattern, label in secrets:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A04, severity=SeverityLevel.CRITICAL,
                        title=f"Kredensial Hardcoded: {label}",
                        description=f"Ditemukan {label} hardcoded.", line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan environment variables.",
                    ))
        return findings
