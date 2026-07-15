# owasp-audit-agent

[![PyPI version](https://img.shields.io/pypi/v/owasp-audit-agent.svg)](https://pypi.org/project/owasp-audit-agent/)
[![Python versions](https://img.shields.io/pypi/pyversions/owasp-audit-agent.svg)](https://pypi.org/project/owasp-audit-agent/)
[![CI](https://github.com/Rio-Bewbew/owasp-security-audit-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Rio-Bewbew/owasp-security-audit-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/pypi/l/owasp-audit-agent.svg)](LICENSE)

Framework *agentic AI* untuk audit keamanan kode Python berbasis **OWASP Top 10**.
Ia menganalisis kode sumber lewat **Abstract Syntax Tree (AST)**, mendeteksi kerentanan
di 10 kategori OWASP, menghasilkan ringkasan eksekutif dari LLM, mencoba memperbaiki
secara otomatis, lalu memverifikasi ulang hasilnya — seluruh alur diorkestrasi dengan
**LangGraph**.

Deteksi memakai *checker* modular yang ditemukan secara otomatis, sehingga menambah
aturan baru atau memasang plugin pihak ketiga tidak perlu menyentuh kode inti.

---

## Fitur utama

- **Deteksi OWASP Top 10 berbasis AST** — 10 checker (satu per kategori) yang membaca
  struktur kode sungguhan, bukan sekadar mencocokkan teks; jauh lebih akurat dan minim
  false-positive. Otomatis *fallback* ke regex bila kode gagal di-parse (mode hybrid).
- **Alur agentic (LangGraph)** — jalankan checker → eskalasi otomatis → ringkasan LLM →
  auto-fix → verifikasi ulang berulang.
- **Extensible** — auto-discovery checker dari `agent/tools/` + dukungan plugin eksternal
  via *entry points*.
- **Konfigurasi penuh** — file `audit.toml` atau environment variable: pilih checker,
  ambang eskalasi, iterasi fix, model & provider LLM.
- **LLM multi-provider** — Groq, OpenAI, Anthropic, Google, Ollama (lokal); *lazy-init*;
  bisa tambah provider kustom.
- **Pelaporan & integrasi** — ekspor **SARIF** (GitHub Security / VS Code), laporan **PDF**,
  riwayat scan, dan **dependency scanner** (cek `requirements.txt` terhadap CVE yang dikenal).
- **Tiga antarmuka** — CLI, library Python, dan UI Streamlit.

---

## Instalasi

Dari PyPI:

```bash
pip install owasp-audit-agent
pip install "owasp-audit-agent[ui]"        # + UI Streamlit
```

Dari sumber (untuk pengembangan):

```bash
git clone https://github.com/Rio-Bewbew/owasp-security-audit-agent.git
cd owasp-security-audit-agent
pip install -e ".[dev]"                    # + pytest, ruff, build
```

Provider LLM alternatif (opsional): `pip install "owasp-audit-agent[openai]"`
(atau `[anthropic]`, `[google]`, `[ollama]`).

Siapkan kredensial LLM dalam file `.env` di root project:

```
GROQ_API_KEY=your_key_here
```

---

## Pemakaian

### CLI

```bash
owasp-audit app.py               # audit satu file
owasp-audit app.py --json        # keluaran JSON (cocok untuk CI)
owasp-audit --list-checkers      # tampilkan checker yang terdaftar
```

Contoh keluaran:

```
Ditemukan 3 isu pada app.py:

  [Critical] A04:2025 - Cryptographic Failures (baris 5)
      Kredensial Hardcoded: api_key
  [High] A05:2025 - Injection (baris 12)
      Command Injection via os.system()
  [Medium] A06:2025 - Insecure Design (baris 8)
      Query SELECT * Tanpa LIMIT
```

### Sebagai library

```python
from agent import audit_code

result = audit_code(open("app.py").read(), "app.py")

for f in result["findings"]:
    print(f.severity.value, f.owasp_category.value, f.title, f.line_number)

print(result["summary"])          # ringkasan eksekutif dari LLM
```

### UI (Streamlit)

```bash
streamlit run app.py
```

Buka `http://localhost:8501`, lalu paste kode atau upload file untuk melihat temuan,
tingkat keparahan, dan ringkasannya secara visual.

---

## Cara kerja

Audit dijalankan sebagai *graph* LangGraph:

```
START
  -> run_checkers
       -> (Critical > ambang?) -> escalate_alert -> llm_analysis
       -> (tidak)                                -> llm_analysis
  -> auto_fix
  -> verify_fixes
       -> (masih berisiko & < batas iterasi?) -> kembali ke auto_fix
       -> (selesai)                           -> END
```

1. **run_checkers** — semua checker aktif dijalankan atas kode.
2. **escalate_alert** — dipicu jika jumlah temuan Critical melebihi ambang.
3. **llm_analysis** — LLM menyusun ringkasan eksekutif & prioritas.
4. **auto_fix** — perbaikan berbasis aturan (deterministik).
5. **verify_fixes** — kode hasil perbaikan di-scan ulang; jika masih berisiko dan
   belum melewati batas iterasi, kembali ke auto_fix.

---

## Kategori OWASP yang dicakup

Seluruh checker berbasis **AST** (dengan fallback regex).

| Kode | Kategori | Contoh yang dideteksi |
|------|----------|-----------------------|
| A01 | Broken Access Control | path traversal, IDOR, fungsi sensitif tanpa auth |
| A02 | Security Misconfiguration | `DEBUG=True`, `ALLOWED_HOSTS=['*']`, HTTP, SECRET_KEY lemah |
| A03 | Software Supply Chain Failures | `pickle.loads`, `yaml.load`, import dinamis |
| A04 | Cryptographic Failures | hash lemah (MD5/SHA1), kredensial hardcoded |
| A05 | Injection | `os.system`, `eval`/`exec`, SQL dari f-string/konkatenasi |
| A06 | Insecure Design | `random` untuk keamanan, `SELECT *` tanpa LIMIT, input rahasia |
| A07 | Authentication Failures | perbandingan password plaintext, `verify=False` |
| A08 | Software/Data Integrity Failures | `eval`/`exec` data eksternal, subprocess & open dinamis |
| A09 | Security Logging Failures | password/token di log, error via `print`, except senyap |
| A10 | Mishandling of Exceptional Conditions | `except: pass`, `return` di `finally`, div-by-zero |

### Kenapa AST, bukan regex?

Analisis AST membaca struktur kode (pemanggilan fungsi, assignment, perbandingan),
sehingga pola seperti `os.system(...)` atau `except: pass` yang muncul di **komentar
atau string** tidak lagi keliru ditandai. Base `ASTChecker` otomatis jatuh ke regex
saat kode tidak bisa di-parse, jadi snippet parsial tetap tertangani.

---

## Konfigurasi

Perilaku audit diatur lewat `audit.toml` (opsional) dan/atau environment variable.
Salin `audit.example.toml` menjadi `audit.toml` lalu sesuaikan:

```toml
[llm]
provider = "groq"                 # groq | openai | anthropic | google | ollama
model = "llama-3.1-8b-instant"
temperature = 0.0
# base_url = "http://localhost:11434"   # untuk Ollama / endpoint OpenAI-compatible

[audit]
escalation_threshold = 3          # eskalasi jika jumlah CRITICAL > nilai ini
max_fix_iterations = 2
auto_fix = true

[checkers]
enabled = []                      # kosong = semua; mis. ["A01","A05","A07"]
disabled = ["A09"]                # kode kategori yang dimatikan
```

Environment variable menimpa file (berguna untuk CI): `OWASP_LLM_PROVIDER`,
`OWASP_LLM_MODEL`, `OWASP_LLM_BASE_URL`, `OWASP_ESCALATION_THRESHOLD`,
`OWASP_MAX_FIX_ITERATIONS`, `OWASP_AUTO_FIX`, `OWASP_ENABLED_CHECKERS`,
`OWASP_DISABLED_CHECKERS`, `OWASP_CONFIG` (path file config).

```python
from agent import AuditConfig
cfg = AuditConfig.load()          # audit.toml + env
print(cfg.escalation_threshold, cfg.llm_model, cfg.is_checker_enabled("A05"))
```

---

## Provider LLM

Provider dipilih lewat `[llm] provider`. Paket integrasi di-import *lazy*, jadi cukup
pasang yang dipakai. API key dibaca dari env sesuai provider (`GROQ_API_KEY`,
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, dst).

Menambah provider kustom:

```python
from agent import register_provider

@register_provider("myllm")
def _build(config):
    from my_pkg import MyChat
    return MyChat(model=config.llm_model, temperature=config.llm_temperature)
```

Lalu set `provider = "myllm"` di config.

---

## Menulis checker baru

Cara termudah, subclass `ASTChecker` dan override `check_ast()` (opsional
`check_regex()` sebagai fallback):

```python
# agent/tools/my_checker.py
import ast
from typing import List
from agent.ast_utils import ASTChecker, call_name
from agent.models import Finding, OWASPCategory, SeverityLevel

class MyChecker(ASTChecker):
    @property
    def category(self) -> OWASPCategory:
        return OWASPCategory.A05

    @property
    def name(self) -> str:
        return "My Custom Checker"

    def check_ast(self, tree, code, filename) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and call_name(node) == "os.system":
                findings.append(Finding(
                    owasp_category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="Contoh temuan",
                    description="Penjelasan singkat.",
                    line_number=node.lineno,
                    recommendation="Cara memperbaiki.",
                ))
        return findings
```

Letakkan file di `agent/tools/` — **auto-discovery** mendaftarkannya otomatis, tanpa
mengubah `graph.py` atau `registry.py`.

### Plugin eksternal (paket terpisah)

Checker bisa didistribusikan sebagai paket pihak ketiga lewat *entry point* pada group
`owasp_audit_agent.checkers`:

```toml
# pyproject.toml paket plugin kamu
[project.entry-points."owasp_audit_agent.checkers"]
my_checker = "my_package.my_module:MyChecker"
```

Setelah terpasang, `registry.discover_entry_points()` memuatnya otomatis.

---

## Arsitektur

```
agent/
├── base_checker.py       # abstract BaseChecker (kontrak checker)
├── ast_utils.py          # ASTChecker base + helper AST (call_name, dll)
├── registry.py           # CheckerRegistry + auto-discovery + entry points
├── config.py             # AuditConfig (audit.toml + env)
├── llm.py                # factory LLM multi-provider + register_provider
├── models.py             # Finding, OWASPCategory, SeverityLevel (Pydantic)
├── state.py              # AuditState (state LangGraph)
├── graph.py              # workflow LangGraph + audit_code()
├── rule_fixer.py         # perbaikan berbasis aturan
├── sarif_exporter.py     # ekspor hasil ke SARIF
├── dependency_scanner.py # cek requirements.txt terhadap CVE
├── history.py            # riwayat scan
├── report.py             # laporan PDF
├── cli.py                # command owasp-audit
└── tools/                # satu file per checker (auto-discovered)
```

---

## Pengembangan

```bash
pip install -e ".[dev]"
pytest                 # 56 test
ruff check agent tests # lint
```

CI (GitHub Actions) menjalankan lint + test pada Python 3.10–3.13 di tiap push/PR.
Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan kontribusi dan
[CHANGELOG.md](CHANGELOG.md) untuk riwayat versi.

---

## Lisensi

MIT — lihat [LICENSE](LICENSE).
