import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class CryptoChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A04

    @property
    def name(self) -> str:
        return "Cryptographic Failures Checker (A04:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        weak_algos = [
            (r'\bmd5\b', "MD5"),
            (r'\bsha1\b', "SHA1"),
            (r'hashlib\.md5', "hashlib.md5"),
            (r'hashlib\.sha1', "hashlib.sha1"),
        ]
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "hardcoded password"),
            (r'secret_key\s*=\s*["\'][^"\']{3,}["\']', "hardcoded secret key"),
            (r'api_key\s*=\s*["\'][^"\']{3,}["\']', "hardcoded API key"),
            (r'token\s*=\s*["\'][^"\']{3,}["\']', "hardcoded token"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, label in weak_algos:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A04,
                        severity=SeverityLevel.HIGH,
                        title=f"Algoritma Hash Lemah: {label}",
                        description=f"{label} sudah tidak aman dan rentan terhadap collision attack.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan SHA-256 atau SHA-3: hashlib.sha256(data).hexdigest()"
                    ))
                    break

            for pattern, label in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A04,
                        severity=SeverityLevel.CRITICAL,
                        title=f"Kredensial Hardcoded: {label}",
                        description=f"Ditemukan {label} yang ditulis langsung di kode.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Simpan secrets di environment variables dan baca dengan os.getenv()"
                    ))

        return findings
