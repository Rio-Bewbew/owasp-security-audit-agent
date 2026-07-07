import re
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class ExceptionChecker(BaseChecker):

    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A10

    @property
    def name(self) -> str:
        return "Mishandling of Exceptional Conditions Checker (A10:2025)"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):

            # Bare except: pass
            if re.search(r'^\s*except\s*:\s*$', line):
                next_line = lines[i].strip() if i < len(lines) else ""
                if next_line == "pass":
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A10,
                        severity=SeverityLevel.HIGH,
                        title="Bare except: pass (Exception Ditelan)",
                        description="Semua exception ditangkap dan diabaikan tanpa penanganan apapun.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Tangkap exception spesifik dan log errornya: except ValueError as e: logging.error(e)."
                    ))

            # except Exception as e: pass
            elif re.search(r'except\s+Exception\s+as\s+\w+\s*:', line):
                next_line = lines[i].strip() if i < len(lines) else ""
                if next_line in ("pass", "..."):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A10,
                        severity=SeverityLevel.HIGH,
                        title="Exception Umum Ditelan Tanpa Penanganan",
                        description="Exception ditangkap tapi tidak ditangani atau dicatat.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Tambahkan logging: except Exception as e: logging.error('Error occurred', exc_info=True)."
                    ))

            # Division tanpa try-except
            elif re.search(r'\w+\s*/\s*\w+', line) and "try" not in "".join(lines[max(0,i-5):i]):
                if re.search(r'def\s+', "".join(lines[max(0,i-10):i])):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A10,
                        severity=SeverityLevel.LOW,
                        title="Potensi Division by Zero Tidak Ditangani",
                        description="Operasi pembagian tanpa penanganan ZeroDivisionError.",
                        line_number=i,
                        vulnerable_code=line.strip(),
                        recommendation="Bungkus operasi pembagian dengan try-except ZeroDivisionError atau validasi denominator > 0."
                    ))

            # Return di dalam finally
            elif re.search(r'^\s*finally\s*:', line):
                next_line = lines[i].strip() if i < len(lines) else ""
                if next_line.startswith("return"):
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A10,
                        severity=SeverityLevel.MEDIUM,
                        title="return di dalam finally Block",
                        description="return di dalam finally menelan exception yang sedang diproses.",
                        line_number=i + 1,
                        vulnerable_code=next_line,
                        recommendation="Hindari return di dalam finally block karena akan menelan exception yang belum tertangani."
                    ))

        return findings
