import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class AccessControlChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A01

    @property
    def name(self) -> str:
        return "Broken Access Control Checker (A01:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'\.\./|\.\.\\', SeverityLevel.HIGH,
             "Path Traversal",
             "Ditemukan pola path traversal yang dapat mengakses file di luar direktori yang diizinkan.",
             "Validasi dan sanitasi semua input path. Gunakan os.path.abspath() dan pastikan path berada dalam direktori yang diizinkan."),

            (r'request\.(args|form|json|data)\[.*\](?!.*auth|.*login|.*permission)', SeverityLevel.MEDIUM,
             "Potensi Insecure Direct Object Reference (IDOR)",
             "Data dari request langsung digunakan tanpa verifikasi otorisasi.",
             "Selalu verifikasi bahwa user yang sedang login memiliki hak akses ke resource yang diminta."),

            (r'def\s+(delete|update|admin|manage|remove)\w*\s*\((?!.*login_required|.*auth)', SeverityLevel.MEDIUM,
             "Fungsi Sensitif Tanpa Pengecekan Autentikasi",
             "Fungsi sensitif (delete/update/admin) tidak terdeteksi memiliki pengecekan autentikasi.",
             "Tambahkan decorator @login_required atau pengecekan autentikasi di awal fungsi sensitif."),

            (r'role\s*=\s*request\.|user_role\s*=\s*request\.', SeverityLevel.HIGH,
             "Role Diambil Langsung dari Request",
             "Role atau permission diambil langsung dari request user tanpa verifikasi server-side.",
             "Role dan permission harus diambil dari database/session server-side, bukan dari input user."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A01,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
