# owasp-audit-agent

Framework *agentic AI* untuk audit keamanan kode Python berbasis **OWASP Top 10 (2025)**.
Menganalisis kode sumber, mendeteksi kerentanan di 10 kategori OWASP, menghasilkan
ringkasan eksekutif dari LLM, mencoba memperbaiki secara otomatis, lalu memverifikasi ulang.

Orkestrasi dibangun di atas **LangGraph**; deteksi memakai *checker* modular yang
ditemukan secara otomatis sehingga menambah aturan baru tidak menyentuh kode inti.

## Instalasi

```bash
pip install -e .            # library + CLI
pip install -e ".[ui]"      # + UI Streamlit
pip install -e ".[dev]"     # + pytest
```

Buat file `.env` berisi kredensial LLM:

```
GROQ_API_KEY=your_key_here
```

## Pemakaian sebagai library

```python
from agent import audit_code

result = audit_code(open("app.py").read(), "app.py")

for f in result["findings"]:
    print(f.severity.value, f.owasp_category.value, f.title, f.line_number)

print(result["summary"])
```

## CLI

```bash
owasp-audit app.py               # audit satu file
owasp-audit app.py --json        # keluaran JSON
owasp-audit --list-checkers      # daftar checker terdaftar
```

## UI (Streamlit)

```bash
streamlit run app.py
```

## Konfigurasi

Perilaku audit diatur lewat file `audit.toml` di root project (opsional) dan/atau
environment variable. Salin `audit.example.toml` menjadi `audit.toml` lalu sesuaikan:

```toml
[llm]
provider = "groq"
model = "llama-3.1-8b-instant"
temperature = 0.0

[audit]
escalation_threshold = 3      # eskalasi jika jumlah CRITICAL > nilai ini
max_fix_iterations = 2
auto_fix = true

[checkers]
enabled = []                  # kosong = semua; mis. ["A01","A05","A07"]
disabled = ["A09"]            # kode kategori yang dimatikan
```

Env var menimpa file (berguna untuk CI): `OWASP_LLM_MODEL`,
`OWASP_ESCALATION_THRESHOLD`, `OWASP_MAX_FIX_ITERATIONS`, `OWASP_AUTO_FIX`,
`OWASP_ENABLED_CHECKERS`, `OWASP_DISABLED_CHECKERS`, `OWASP_CONFIG` (path file config).

Dari kode, config bisa dimuat manual:

```python
from agent import AuditConfig
cfg = AuditConfig.load()          # audit.toml + env
print(cfg.escalation_threshold, cfg.llm_model, cfg.is_checker_enabled("A05"))
```

## Provider LLM

Provider dipilih lewat `[llm] provider` di `audit.toml` (atau env `OWASP_LLM_PROVIDER`).
Built-in: `groq` (default, sudah termasuk), `openai`, `anthropic`, `google`, `ollama`.
Paket integrasi di-import lazy — install hanya yang dipakai:

```bash
pip install -e ".[openai]"      # atau .[anthropic] / .[google] / .[ollama]
```

```toml
[llm]
provider = "openai"
model = "gpt-4o-mini"
# base_url = "http://localhost:11434"   # untuk Ollama / endpoint OpenAI-compatible
```

API key dibaca dari env sesuai provider (`GROQ_API_KEY`, `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, dst). Menambah provider kustom:

```python
from agent import register_provider

@register_provider("myllm")
def _build(config):
    from my_pkg import MyChat
    return MyChat(model=config.llm_model, temperature=config.llm_temperature)
```

Lalu set `provider = "myllm"` di config.

## Kategori OWASP yang dicakup

| Kode | Kategori |
|------|----------|
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

## Analisis AST vs regex

**Seluruh 10 checker** memakai **analisis AST** — membaca struktur kode
sungguhan (pemanggilan fungsi, assignment, perbandingan, handler exception),
bukan sekadar mencocokkan teks. Hasilnya jauh lebih akurat: pola seperti
`os.system(...)` atau `except: pass` yang muncul di dalam komentar atau string
**tidak lagi** ditandai sebagai temuan.

Base `ASTChecker` (`agent/ast_utils.py`) otomatis jatuh kembali ke deteksi
regex bila kode gagal di-parse (mode hybrid), sehingga snippet parsial tetap
tertangani. Checker berbasis AST cukup meng-override `check_ast(tree, code, filename)`
dan opsional `check_regex(...)` sebagai fallback.

## Menulis checker baru

Buat subclass `BaseChecker` dan implementasi `category`, `name`, dan `analyze()`:

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
        return "My Custom Checker"

    def analyze(self, code: str, filename: str) -> List[Finding]:
        findings = []
        # ... logika deteksi ...
        return findings
```

Cukup letakkan file di `agent/tools/` — **auto-discovery** akan mendaftarkannya
otomatis saat `registry.discover()` dipanggil. Tidak perlu mengubah `graph.py`
maupun `registry.py`.

### Plugin eksternal (paket terpisah)

Checker juga bisa didistribusikan sebagai paket pihak ketiga tanpa menyentuh
repo ini. Deklarasikan *entry point* pada group `owasp_audit_agent.checkers`:

```toml
# pyproject.toml paket plugin kamu
[project.entry-points."owasp_audit_agent.checkers"]
my_checker = "my_package.my_module:MyChecker"
```

Setelah paket terpasang, `registry.discover_entry_points()` akan memuatnya otomatis.

## Arsitektur

```
agent/
├── base_checker.py     # abstract BaseChecker (kontrak checker)
├── registry.py         # CheckerRegistry + auto-discovery + entry points
├── models.py           # Finding, OWASPCategory, SeverityLevel (Pydantic)
├── state.py            # AuditState (state LangGraph)
├── graph.py            # workflow LangGraph + audit_code()
├── rule_fixer.py       # perbaikan berbasis aturan
├── sarif_exporter.py   # ekspor hasil ke SARIF
├── dependency_scanner.py
├── history.py          # riwayat scan
├── report.py           # laporan PDF
├── cli.py              # command owasp-audit
└── tools/              # satu file per checker (auto-discovered)
```

## Lisensi

MIT — lihat [LICENSE](LICENSE).
