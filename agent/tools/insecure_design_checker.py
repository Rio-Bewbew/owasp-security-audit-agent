import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class InsecureDesignChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A06

    @property
    def name(self) -> str:
        return "Insecure Design Checker (A06:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'SELECT\s+\*\s+FROM(?!.*LIMIT|.*limit)', SeverityLevel.MEDIUM,
             "Query SELECT * Tanpa LIMIT",
             "Query tanpa LIMIT dapat mengembalikan seluruh isi tabel dan menyebabkan DoS.",
             "Selalu tambahkan LIMIT pada query: SELECT * FROM users LIMIT 100."),

            (r'time\.sleep\s*\(\s*\d+\s*\)', SeverityLevel.LOW,
             "Hardcoded Sleep/Delay",
             "Delay hardcoded dapat dimanfaatkan untuk timing attack pada proses autentikasi.",
             "Gunakan delay yang konstan dan tidak bergantung pada kondisi input untuk mencegah timing attack."),

            (r'random\.(random|randint|choice)\s*\(', SeverityLevel.MEDIUM,
             "Penggunaan random untuk Keperluan Keamanan",
             "Module random tidak aman untuk keperluan kriptografi (token, OTP, session ID).",
             "Gunakan secrets module: secrets.token_hex(16) atau secrets.randbelow(n)."),

            (r'input\s*\(.*password|input\s*\(.*secret|input\s*\(.*token', SeverityLevel.HIGH,
             "Input Sensitif Tanpa Masking",
             "Password atau data sensitif diminta menggunakan input() yang menampilkan teks.",
             "Gunakan getpass.getpass() untuk input password agar tidak terlihat saat diketik."),

            (r'except\s+Exception\s+as\s+\w+\s*:\s*\n\s*(return|pass)', SeverityLevel.MEDIUM,
             "Error Details Disembunyikan Sepenuhnya",
             "Menyembunyikan semua error membuat debugging sulit dan dapat menyembunyikan vulnerability.",
             "Log error secara internal dengan logger tapi tampilkan pesan generik ke user."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A06,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
