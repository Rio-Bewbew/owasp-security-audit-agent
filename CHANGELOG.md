# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/),
dan proyek ini menganut [Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-07-14

### Changed
- Perbaikan URL proyek di metadata (`Homepage`/`Repository`/`Issues`/`Changelog`)
  menunjuk ke repo GitHub yang benar.
- Rilis pertama via GitHub Actions Trusted Publishing (tanpa API token).

## [0.3.0] - 2026-07-14

### Changed
- 4 checker sisanya dikonversi dari regex ke AST: Broken Access Control (A01),
  Insecure Design (A06), Security Logging (A09), Mishandling of Exceptional
  Conditions (A10). Kini **seluruh 10 checker OWASP berbasis AST** dengan
  fallback regex hybrid.

### Added
- Test akurasi untuk keempat checker baru (bare except, division dalam try,
  path traversal, kata sensitif di komentar) — total suite 56 test.

## [0.2.0] - 2026-07-09

### Added
- Infrastruktur analisis **AST** (`agent/ast_utils.py`): base `ASTChecker` yang
  mem-parse kode jadi Abstract Syntax Tree, dengan fallback hybrid ke regex saat
  kode gagal di-parse. Helper: `call_name`, `is_dynamic_string`, `references_names`,
  `const_str`, `has_keyword`.
- Test akurasi AST yang membuktikan pola berbahaya di komentar/string tidak lagi
  menghasilkan false-positive, plus uji fallback saat syntax error.

### Changed
- 6 checker dikonversi dari regex ke analisis AST yang jauh lebih akurat:
  Injection (A05), Cryptographic Failures (A04), Software Supply Chain (A03),
  Software/Data Integrity (A08), Authentication (A07), Security Misconfiguration (A02).
  Masing-masing tetap menyimpan jalur regex sebagai fallback. Checker A01/A06/A09/A10
  masih berbasis regex (rencana konversi berikutnya).

## [0.1.1] - 2026-07-09

### Changed
- Metadata lisensi memakai ekspresi SPDX (`license = "MIT"` + `license-files`)
  menggantikan tabel `{ text = "MIT" }` yang deprecated, dan menghapus classifier
  lisensi yang deprecated. Menghilangkan `SetuptoolsDeprecationWarning` saat build.
- `build-system` kini mensyaratkan `setuptools>=77` (dukungan SPDX license).

### Added
- Workflow GitHub Actions `publish.yml`: rilis otomatis ke PyPI saat membuat
  GitHub Release, memakai Trusted Publishing (OIDC) tanpa API token.

## [0.1.0] - 2026-07-08

Rilis pertama sebagai **framework** (sebelumnya aplikasi).

### Added
- Packaging penuh: `pyproject.toml`, dapat di-`pip install`, extras
  (`ui`, `dev`, `openai`, `anthropic`, `google`, `ollama`), command `owasp-audit`.
- Auto-discovery checker dari `agent/tools/` + dukungan plugin pihak ketiga via
  entry point group `owasp_audit_agent.checkers`.
- Sistem konfigurasi `AuditConfig` (file `audit.toml` + override environment variable):
  pemilihan checker (enabled/disabled), ambang eskalasi, iterasi auto-fix, dan
  pilihan model/provider LLM.
- Abstraksi LLM multi-provider (`agent/llm.py`) dengan registry provider
  extensible; built-in: groq, openai, anthropic, google, ollama.
- API publik stabil di `agent/__init__` (`audit_code`, `build_graph`, `build_llm`,
  `register_provider`, `AuditConfig`, `BaseChecker`, dll).
- CLI `owasp-audit` (`--json`, `--list-checkers`).
- Suite test `pytest` (registry, config, llm, pipeline, per-kategori checker) + CI
  (GitHub Actions, matrix Python 3.10–3.13) + linting `ruff` + pre-commit.
- Dokumentasi: README, CONTRIBUTING, contoh `audit.example.toml`.

### Changed
- LLM kini lazy-init: `import agent` tidak lagi memerlukan API key.
- Nilai yang sebelumnya hardcoded (ambang eskalasi, jumlah iterasi fix, model LLM)
  kini bersumber dari konfigurasi.

### Fixed
- Bug key duplikat pada tabel substitusi karakter di `report.py`.
- Perbaikan lint: import tak terpakai, f-string tanpa placeholder, rantai exception.
