import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class InjectionChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A05

    @property
    def name(self) -> str:
        return "Injection Checker (A05:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        sql_patterns = [
            r'execute\s*\(\s*f["\']',
            r'execute\s*\(\s*["\'].*\+',
            r'execute\s*\(\s*["\'].*%\s*\w',
        ]
        cmd_patterns = [
            (r'os\.system\s*\(', "os.system()"),
            (r'subprocess\.[a-z]+\(.*shell\s*=\s*True', "subprocess dengan shell=True"),
            (r'\beval\s*\(', "eval()"),
            (r'\bexec\s*\(', "exec()"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A05,
                        severity=SeverityLevel.CRITICAL,
                        title="SQL Injection",
                        description="Query SQL dibangun dengan string formatting yang tidak aman.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Gunakan parameterized query: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                    ))
                    break

            for pattern, label in cmd_patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A05,
                        severity=SeverityLevel.HIGH,
                        title=f"Command Injection via {label}",
                        description=f"Penggunaan {label} dapat memungkinkan eksekusi perintah berbahaya.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Hindari eval/exec. Gunakan subprocess dengan shell=False dan validasi input."
                    ))

        return findings
