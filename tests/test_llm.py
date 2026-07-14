"""Test untuk factory LLM multi-provider di agent.llm."""
import pytest

from agent.llm import build_llm, register_provider, available_providers
from agent.config import AuditConfig


def test_builtin_providers_registered():
    provs = available_providers()
    for name in ("groq", "openai", "anthropic", "google", "ollama"):
        assert name in provs


def test_unknown_provider_raises_valueerror():
    cfg = AuditConfig(llm_provider="nope")
    with pytest.raises(ValueError) as exc:
        build_llm(cfg)
    # pesan menyebut daftar provider tersedia
    assert "groq" in str(exc.value)


def test_missing_package_raises_friendly_importerror(monkeypatch):
    # Paksa import gagal untuk simulasi paket tak terpasang.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("langchain_openai"):
            raise ModuleNotFoundError("No module named 'langchain_openai'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    cfg = AuditConfig(llm_provider="openai")
    with pytest.raises(ImportError) as exc:
        build_llm(cfg)
    assert "pip install langchain-openai" in str(exc.value)


def test_register_custom_provider():
    @register_provider("faketest")
    def _factory(config):
        return {"model": config.llm_model, "temp": config.llm_temperature}

    assert "faketest" in available_providers()
    cfg = AuditConfig(llm_provider="faketest", llm_model="m", llm_temperature=0.7)
    result = build_llm(cfg)
    assert result == {"model": "m", "temp": 0.7}


def test_provider_case_insensitive():
    @register_provider("upperx")
    def _f(config):
        return "ok"

    cfg = AuditConfig(llm_provider="UPPERX")
    assert build_llm(cfg) == "ok"
