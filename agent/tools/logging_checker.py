import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class LoggingChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A09

    @property
    def name(self) -> str:
        return "Security Logging Failures Checker (A09:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'(log|logger|logging)\.(info|debug|warning|error)\s*\(.*password', SeverityLevel.CRITICAL,
             "Password Tercatat di Log",
             "Password atau kredensial sensitif ditemukan dalam pesan log.",
             "Jangan pernah log password atau data sensitif. Gunakan placeholder: logger.info('Login attempt for user: %s', username)."),

            (r'(log|logger|logging)\.(info|debug|warning|error)\s*\(.*token|.*(log|logger)\s*\(.*api_key', SeverityLevel.HIGH,
             "Token/API Key Tercatat di Log",
             "Token atau API key sensitif ditemukan dalam pesan log.",
             "Mask atau hapus data sensitif sebelum logging. Log hanya identifier, bukan nilai token."),

            (r'print\s*\(.*error|print\s*\(.*exception|print\s*\(.*traceback', SeverityLevel.MEDIUM,
             "Error Ditampilkan dengan print() ke User",
             "Menggunakan print() untuk menampilkan error dapat mengekspos stack trace ke user.",
             "Gunakan logging module dan tampilkan pesan error generik ke user: logging.error('Error', exc_info=True)."),

            (r'except\s*:\s*$|except\s+Exception\s*:\s*$', SeverityLevel.HIGH,
             "Exception Ditangkap Tanpa Logging",
             "Exception ditangkap secara diam-diam tanpa dicatat ke log, menyembunyikan error keamanan.",
             "Selalu log exception: except Exception as e: logging.error('Unexpected error', exc_info=True)."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A09,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
