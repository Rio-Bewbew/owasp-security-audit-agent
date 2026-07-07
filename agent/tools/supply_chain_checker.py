import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class SupplyChainChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A03

    @property
    def name(self) -> str:
        return "Software Supply Chain Failures Checker (A03:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        patterns = [
            (r'pickle\.loads?\s*\(', SeverityLevel.CRITICAL,
             "Unsafe Deserialization dengan pickle",
             "pickle.load/loads dapat mengeksekusi kode arbitrer saat deserializing data tidak tepercaya.",
             "Hindari pickle untuk data dari sumber eksternal. Gunakan json.loads() sebagai alternatif yang aman."),

            (r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader|.*Loader\s*=\s*yaml\.BaseLoader)', SeverityLevel.HIGH,
             "yaml.load Tanpa SafeLoader",
             "yaml.load() tanpa SafeLoader dapat mengeksekusi kode Python arbitrer.",
             "Gunakan yaml.safe_load() atau yaml.load(data, Loader=yaml.SafeLoader)."),

            (r'marshal\.loads?\s*\(', SeverityLevel.CRITICAL,
             "Unsafe Deserialization dengan marshal",
             "marshal.load/loads dapat mengeksekusi kode berbahaya dari data yang dimanipulasi.",
             "Jangan gunakan marshal untuk data dari sumber eksternal atau tidak tepercaya."),

            (r'__import__\s*\(\s*(request|input|f["\'])', SeverityLevel.HIGH,
             "Dynamic Import dari Input User",
             "Menggunakan __import__() dengan input user dapat memuat modul berbahaya.",
             "Whitelist modul yang diizinkan dan validasi input sebelum melakukan dynamic import."),

            (r'importlib\.import_module\s*\(.*\+|importlib\.import_module\s*\(.*f["\']', SeverityLevel.HIGH,
             "importlib dengan String Dinamis",
             "import_module() dengan string dinamis dapat memuat modul yang tidak diinginkan.",
             "Gunakan whitelist nama modul yang diizinkan sebelum melakukan import dinamis."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, title, desc, rec in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A03,
                        severity=severity,
                        title=title,
                        description=desc,
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation=rec
                    ))

        return findings
