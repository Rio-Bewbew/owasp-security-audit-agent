"""Konfigurasi pytest bersama.

LLM kini lazy, jadi import paket tidak butuh kredensial. Namun kita set
dummy key + bersihkan env OWASP_* agar test config deterministik.
"""
import os
import sys
from pathlib import Path

import pytest

# Pastikan root project ada di sys.path saat dijalankan dari mana pun.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("GROQ_API_KEY", "dummy-key-for-tests")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Hapus semua override OWASP_* agar tiap test mulai dari default bersih."""
    for key in list(os.environ):
        if key.startswith("OWASP_"):
            monkeypatch.delenv(key, raising=False)
    yield
