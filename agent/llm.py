"""
Abstraksi LLM multi-provider untuk owasp-audit-agent.

Provider dipilih lewat konfigurasi (`[llm] provider = "..."`). Setiap provider
adalah factory `callable(config) -> chat model` yang di-import secara lazy,
sehingga paket integrasi yang tidak dipakai tidak perlu terpasang.

Menambah provider baru (titik ekstensi framework):

    from agent.llm import register_provider

    @register_provider("myllm")
    def _build_myllm(config):
        from my_pkg import MyChat
        return MyChat(model=config.llm_model, temperature=config.llm_temperature)

Setelah itu cukup set `provider = "myllm"` di audit.toml.
"""
from __future__ import annotations

from typing import Callable, Dict, List

# name -> factory(config) -> chat model
_PROVIDERS: Dict[str, Callable] = {}


def register_provider(name: str):
    """Decorator untuk mendaftarkan factory provider LLM."""
    def decorator(factory: Callable):
        _PROVIDERS[name.lower()] = factory
        return factory
    return decorator


def available_providers() -> List[str]:
    return sorted(_PROVIDERS)


def _missing(pkg: str, provider: str) -> ImportError:
    return ImportError(
        f"Provider LLM '{provider}' butuh paket '{pkg}' yang belum terpasang. "
        f"Install dengan: pip install {pkg}"
    )


# ── Built-in providers (lazy import) ─────────────────────────────────────────

@register_provider("groq")
def _build_groq(config):
    try:
        from langchain_groq import ChatGroq
    except ModuleNotFoundError as exc:
        raise _missing("langchain-groq", "groq") from exc
    kwargs = {"model": config.llm_model, "temperature": config.llm_temperature}
    if getattr(config, "llm_base_url", None):
        kwargs["base_url"] = config.llm_base_url
    return ChatGroq(**kwargs)


@register_provider("openai")
def _build_openai(config):
    try:
        from langchain_openai import ChatOpenAI
    except ModuleNotFoundError as exc:
        raise _missing("langchain-openai", "openai") from exc
    kwargs = {"model": config.llm_model, "temperature": config.llm_temperature}
    if getattr(config, "llm_base_url", None):
        kwargs["base_url"] = config.llm_base_url
    return ChatOpenAI(**kwargs)


@register_provider("anthropic")
def _build_anthropic(config):
    try:
        from langchain_anthropic import ChatAnthropic
    except ModuleNotFoundError as exc:
        raise _missing("langchain-anthropic", "anthropic") from exc
    return ChatAnthropic(model=config.llm_model, temperature=config.llm_temperature)


@register_provider("google")
def _build_google(config):
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
    except ModuleNotFoundError as exc:
        raise _missing("langchain-google-genai", "google") from exc
    return ChatGoogleGenerativeAI(model=config.llm_model, temperature=config.llm_temperature)


@register_provider("ollama")
def _build_ollama(config):
    """Model lokal via Ollama. Gunakan llm_base_url untuk host non-default."""
    try:
        from langchain_ollama import ChatOllama
    except ModuleNotFoundError as exc:
        raise _missing("langchain-ollama", "ollama") from exc
    kwargs = {"model": config.llm_model, "temperature": config.llm_temperature}
    if getattr(config, "llm_base_url", None):
        kwargs["base_url"] = config.llm_base_url
    return ChatOllama(**kwargs)


# ── Factory ──────────────────────────────────────────────────────────────────

def build_llm(config):
    """
    Bangun instance chat model sesuai `config.llm_provider`.
    Raise ValueError jika provider tidak dikenal.
    """
    provider = (getattr(config, "llm_provider", None) or "groq").lower()
    factory = _PROVIDERS.get(provider)
    if factory is None:
        raise ValueError(
            f"Provider LLM '{provider}' tidak dikenal. "
            f"Tersedia: {', '.join(available_providers())}. "
            f"Provider kustom bisa didaftarkan via register_provider()."
        )
    return factory(config)
