import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class AuthChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A07

    @property
    def name(self) -> str:
        return "Authentication Failures Checker (A07:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'password\s*==\s*["\']', SeverityLevel.CRITICAL,
             "Perbandingan Password Plaintext",
             "Password dibandingkan langsung sebagai string.",
             "Gunakan bcrypt atau argon2 untuk hash dan verifikasi password."),

            (r'md5.*password|password.*md5', SeverityLevel.HIGH,
             "Password di-hash dengan MD5",
             "MD5 tidak aman untuk hashing password.",
             "Gunakan bcrypt: bcrypt.hashpw(password.encode(), bcrypt.gensalt())"),

            (r'if\s+.*username\s*==.*and\s*.*password\s*==', SeverityLevel.HIGH,
             "Autentikasi dengan Kredensial Hardcoded",
             "Username dan password dicek langsung di kode.",
             "Gunakan database dengan password yang di-hash untuk autentikasi."),

            (r'verify\s*=\s*False', SeverityLevel.MEDIUM,
             "SSL Verification Dinonaktifkan",
             "requests dengan verify=False menonaktifkan validasi sertifikat SSL.",
             "Selalu gunakan verify=True atau sediakan path ke CA certificate."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A07,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
