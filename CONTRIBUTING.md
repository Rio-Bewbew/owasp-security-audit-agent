# Berkontribusi ke owasp-audit-agent

Terima kasih sudah tertarik berkontribusi! Panduan singkat di bawah.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install              # opsional: auto-lint saat commit
```

## Menjalankan test & lint

```bash
pytest              # semua test harus hijau
ruff check .        # lint harus bersih
ruff format .       # format kode
```

CI menjalankan lint + test pada Python 3.10–3.13 untuk setiap PR.

## Menulis checker baru

Sebuah checker adalah subclass `BaseChecker` yang mengimplementasi `category`,
`name`, dan `analyze()`:

```python
# agent/tools/my_checker.py
from typing import List
from agent.base_checker import BaseChecker
from agent.models import Finding, OWASPCategory, SeverityLevel


class MyChecker(BaseChecker):
    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A05

    @property
    def name(self) -> str:
        return "My Checker"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(code.split("\n"), 1):
            if "TODO_pola_berbahaya" in line:
                findings.append(Finding(
                    owasp_category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="Contoh temuan",
                    description="Penjelasan singkat.",
                    line_number=i,
                    vulnerable_code=line.strip(),
                    recommendation="Cara memperbaiki.",
                ))
        return findings
```

Taruh file di `agent/tools/` — **auto-discovery** akan mendaftarkannya otomatis.
Tambahkan test di `tests/` yang memverifikasi deteksi dan bebas false-positive.

Checker eksternal (paket terpisah) dapat didaftarkan lewat entry point group
`owasp_audit_agent.checkers` — lihat README.

## Menambah provider LLM

Daftarkan factory lewat `@register_provider("nama")` di `agent/llm.py` atau paket
kamu sendiri. Lihat provider built-in sebagai contoh.

## Gaya kode

Ikuti aturan `ruff` (E, F, B). Jalankan `ruff check --fix .` sebelum commit.
