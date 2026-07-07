import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class MisconfigChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A02

    @property
    def name(self) -> str:
        return "Security Misconfiguration Checker (A02:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'DEBUG\s*=\s*True', SeverityLevel.HIGH,
             "DEBUG Mode Aktif",
             "DEBUG=True mengekspos stack trace dan informasi sensitif ke user.",
             "Set DEBUG=False di production dan gunakan environment variable."),

            (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]', SeverityLevel.MEDIUM,
             "ALLOWED_HOSTS Terlalu Luas",
             "ALLOWED_HOSTS=['*'] mengizinkan request dari semua host.",
             "Tentukan host spesifik: ALLOWED_HOSTS=['yourdomain.com']"),

            (r'http://(?!localhost|127\.0\.0\.1)', SeverityLevel.MEDIUM,
             "Penggunaan HTTP (Tidak Terenkripsi)",
             "Koneksi HTTP tidak terenkripsi dan rentan terhadap man-in-the-middle attack.",
             "Gunakan HTTPS untuk semua koneksi external."),

            (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', SeverityLevel.CRITICAL,
             "SECRET_KEY Terlalu Pendek atau Hardcoded",
             "SECRET_KEY yang lemah atau hardcoded membahayakan keamanan aplikasi.",
             "Generate secret key yang kuat: python -c \"import secrets; print(secrets.token_hex(50))\""),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A02,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
