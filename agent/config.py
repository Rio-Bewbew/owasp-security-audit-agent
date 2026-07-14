"""
Konfigurasi runtime untuk owasp-audit-agent.

Sumber konfigurasi (prioritas dari terendah ke tertinggi):
  1. Default di dataclass AuditConfig.
  2. File `audit.toml` (dicari di CWD, lalu parent-nya) atau path eksplisit.
  3. Environment variable (override paling akhir, menang).

Contoh audit.toml:

    [llm]
    provider = "groq"
    model = "llama-3.1-8b-instant"
    temperature = 0.0

    [audit]
    escalation_threshold = 3      # eskalasi jika jumlah CRITICAL > nilai ini
    max_fix_iterations = 2
    auto_fix = true

    [checkers]
    # Kosongkan `enabled` untuk memakai SEMUA checker.
    enabled = []                  # mis. ["A01", "A05", "A07"]
    disabled = ["A09"]            # kode kategori yang dimatikan

Env var yang dikenali:
    OWASP_LLM_PROVIDER, OWASP_LLM_MODEL, OWASP_LLM_TEMPERATURE,
    OWASP_ESCALATION_THRESHOLD, OWASP_MAX_FIX_ITERATIONS, OWASP_AUTO_FIX,
    OWASP_ENABLED_CHECKERS (dipisah koma), OWASP_DISABLED_CHECKERS (dipisah koma),
    OWASP_CONFIG (path ke file config).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None

CONFIG_FILENAMES = ("audit.toml", ".audit.toml")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_code_list(value) -> List[str]:
    """Normalisasi ke list kode kategori uppercase, mis. ['A01','A05']."""
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    else:
        items = list(value)
    return [str(x).strip().upper() for x in items if str(x).strip()]


@dataclass
class AuditConfig:
    # LLM
    llm_provider: str = "groq"
    llm_model: str = "llama-3.1-8b-instant"
    llm_temperature: float = 0.0
    llm_base_url: Optional[str] = None   # untuk model lokal / endpoint OpenAI-compatible

    # Perilaku audit
    escalation_threshold: int = 3      # eskalasi jika jumlah CRITICAL > nilai ini
    max_fix_iterations: int = 2
    auto_fix: bool = True

    # Seleksi checker (kode kategori: "A01".."A10").
    # enabled kosong  -> semua checker aktif (kecuali yang di-disabled).
    enabled_checkers: List[str] = field(default_factory=list)
    disabled_checkers: List[str] = field(default_factory=list)

    # ── Loading ─────────────────────────────────────────────────────────────

    @classmethod
    def find_config_file(cls, start: Optional[Path] = None) -> Optional[Path]:
        """Cari audit.toml mulai dari `start` (default CWD) naik sampai root."""
        env_path = os.getenv("OWASP_CONFIG")
        if env_path:
            p = Path(env_path).expanduser()
            return p if p.is_file() else None
        here = (start or Path.cwd()).resolve()
        for directory in (here, *here.parents):
            for name in CONFIG_FILENAMES:
                candidate = directory / name
                if candidate.is_file():
                    return candidate
        return None

    @classmethod
    def load(cls, path: Optional[os.PathLike | str] = None) -> "AuditConfig":
        cfg = cls()
        cfg._apply_file(path)
        cfg._apply_env()
        return cfg

    def _apply_file(self, path: Optional[os.PathLike | str]) -> None:
        file_path = Path(path) if path else self.find_config_file()
        if not file_path or not file_path.is_file() or _toml is None:
            return
        with open(file_path, "rb") as fh:
            data = _toml.load(fh)

        llm = data.get("llm", {})
        self.llm_provider = llm.get("provider", self.llm_provider)
        self.llm_model = llm.get("model", self.llm_model)
        self.llm_temperature = float(llm.get("temperature", self.llm_temperature))
        self.llm_base_url = llm.get("base_url", self.llm_base_url)

        audit = data.get("audit", {})
        self.escalation_threshold = int(audit.get("escalation_threshold", self.escalation_threshold))
        self.max_fix_iterations = int(audit.get("max_fix_iterations", self.max_fix_iterations))
        if "auto_fix" in audit:
            self.auto_fix = _as_bool(audit["auto_fix"])

        checkers = data.get("checkers", {})
        if "enabled" in checkers:
            self.enabled_checkers = _as_code_list(checkers["enabled"])
        if "disabled" in checkers:
            self.disabled_checkers = _as_code_list(checkers["disabled"])

    def _apply_env(self) -> None:
        env = os.environ
        self.llm_provider = env.get("OWASP_LLM_PROVIDER", self.llm_provider)
        self.llm_model = env.get("OWASP_LLM_MODEL", self.llm_model)
        self.llm_base_url = env.get("OWASP_LLM_BASE_URL", self.llm_base_url)
        if "OWASP_LLM_TEMPERATURE" in env:
            self.llm_temperature = float(env["OWASP_LLM_TEMPERATURE"])
        if "OWASP_ESCALATION_THRESHOLD" in env:
            self.escalation_threshold = int(env["OWASP_ESCALATION_THRESHOLD"])
        if "OWASP_MAX_FIX_ITERATIONS" in env:
            self.max_fix_iterations = int(env["OWASP_MAX_FIX_ITERATIONS"])
        if "OWASP_AUTO_FIX" in env:
            self.auto_fix = _as_bool(env["OWASP_AUTO_FIX"])
        if "OWASP_ENABLED_CHECKERS" in env:
            self.enabled_checkers = _as_code_list(env["OWASP_ENABLED_CHECKERS"])
        if "OWASP_DISABLED_CHECKERS" in env:
            self.disabled_checkers = _as_code_list(env["OWASP_DISABLED_CHECKERS"])

    # ── Helper ────────────────────────────────────────────────────────────────

    def is_checker_enabled(self, code: str) -> bool:
        """True jika checker dengan kode kategori (mis. 'A01') aktif menurut config."""
        code = code.upper()
        if code in self.disabled_checkers:
            return False
        if self.enabled_checkers:  # daftar allow-list non-kosong
            return code in self.enabled_checkers
        return True
