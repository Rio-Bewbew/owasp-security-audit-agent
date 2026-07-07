import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class IntegrityChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A08

    @property
    def name(self) -> str:
        return "Software & Data Integrity Failures Checker (A08:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'eval\s*\(\s*(request|input|data|payload|body|params)', SeverityLevel.CRITICAL,
             "eval() dengan Data Eksternal",
             "Menggunakan eval() pada data dari request/input memungkinkan eksekusi kode arbitrer.",
             "Jangan gunakan eval() pada data eksternal. Gunakan ast.literal_eval() untuk parsing data Python yang aman."),

            (r'exec\s*\(\s*(request|input|data|payload|body|params)', SeverityLevel.CRITICAL,
             "exec() dengan Data Eksternal",
             "Menggunakan exec() pada data eksternal sangat berbahaya dan dapat dikompromikan.",
             "Hindari exec() sepenuhnya untuk data eksternal. Desain ulang logika tanpa dynamic code execution."),

            (r'subprocess\.(run|call|Popen)\s*\(.*\+|subprocess\.(run|call|Popen)\s*\(.*f["\']', SeverityLevel.HIGH,
             "subprocess dengan String Dinamis",
             "Membangun perintah subprocess dengan string dinamis rentan terhadap command injection.",
             "Gunakan list argument: subprocess.run(['ls', user_dir], shell=False) bukan string gabungan."),

            (r'open\s*\(\s*(request|input|f["\'].*\+)', SeverityLevel.HIGH,
             "File open() dengan Path Dinamis",
             "Membuka file dengan path dari input user dapat dieksploitasi untuk path traversal.",
             "Validasi path dengan os.path.realpath() dan pastikan berada dalam direktori yang diizinkan."),

            (r'hashlib\.(md5|sha1)\s*\(.*\)\.hexdigest\(\)(?!.*hmac)', SeverityLevel.MEDIUM,
             "Hash Tanpa HMAC untuk Verifikasi Integritas",
             "Hash biasa tanpa HMAC tidak aman untuk verifikasi integritas data karena rentan length extension attack.",
             "Gunakan hmac.new(key, data, hashlib.sha256).hexdigest() untuk verifikasi integritas."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A08,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
