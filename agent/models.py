from pydantic import BaseModel
from typing import List, Optional
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class OWASPCategory(str, Enum):
    A01 = "A01:2025 - Broken Access Control"
    A02 = "A02:2025 - Security Misconfiguration"
    A03 = "A03:2025 - Software Supply Chain Failures"
    A04 = "A04:2025 - Cryptographic Failures"
    A05 = "A05:2025 - Injection"
    A06 = "A06:2025 - Insecure Design"
    A07 = "A07:2025 - Authentication Failures"
    A08 = "A08:2025 - Software or Data Integrity Failures"
    A09 = "A09:2025 - Security Logging and Alerting Failures"
    A10 = "A10:2025 - Mishandling of Exceptional Conditions"


class Finding(BaseModel):
    owasp_category: OWASPCategory
    severity: SeverityLevel
    title: str
    description: str
    line_number: Optional[int] = None
    vulnerable_code: Optional[str] = None
    recommendation: str


class AuditResult(BaseModel):
    filename: str
    findings: List[Finding] = []
    summary: str = ""

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)