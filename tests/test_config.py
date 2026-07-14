"""Test untuk AuditConfig: default, file TOML, env override, dan prioritas."""
from agent.config import AuditConfig


def test_defaults():
    c = AuditConfig()
    assert c.llm_provider == "groq"
    assert c.escalation_threshold == 3
    assert c.max_fix_iterations == 2
    assert c.auto_fix is True
    assert c.enabled_checkers == []
    assert c.disabled_checkers == []


def test_is_checker_enabled_allowlist():
    c = AuditConfig(enabled_checkers=["A01", "A05"])
    assert c.is_checker_enabled("A01") is True
    assert c.is_checker_enabled("a05") is True  # case-insensitive
    assert c.is_checker_enabled("A02") is False


def test_is_checker_enabled_disabled_wins():
    c = AuditConfig(enabled_checkers=["A01", "A05"], disabled_checkers=["A05"])
    assert c.is_checker_enabled("A05") is False
    assert c.is_checker_enabled("A01") is True


def test_empty_allowlist_enables_all_except_disabled():
    c = AuditConfig(disabled_checkers=["A09"])
    assert c.is_checker_enabled("A03") is True
    assert c.is_checker_enabled("A09") is False


def test_load_from_toml_file(tmp_path):
    cfg_file = tmp_path / "audit.toml"
    cfg_file.write_text(
        "[llm]\n"
        'provider = "openai"\n'
        'model = "gpt-4o-mini"\n'
        "temperature = 0.5\n"
        'base_url = "http://localhost:1234"\n'
        "[audit]\n"
        "escalation_threshold = 1\n"
        "max_fix_iterations = 5\n"
        "auto_fix = false\n"
        "[checkers]\n"
        'enabled = ["A01", "A07"]\n'
        'disabled = ["A07"]\n'
    )
    c = AuditConfig.load(cfg_file)
    assert c.llm_provider == "openai"
    assert c.llm_model == "gpt-4o-mini"
    assert c.llm_temperature == 0.5
    assert c.llm_base_url == "http://localhost:1234"
    assert c.escalation_threshold == 1
    assert c.max_fix_iterations == 5
    assert c.auto_fix is False
    assert c.enabled_checkers == ["A01", "A07"]
    assert c.disabled_checkers == ["A07"]
    # disabled menang
    assert c.is_checker_enabled("A07") is False
    assert c.is_checker_enabled("A01") is True


def test_env_overrides_file(tmp_path, monkeypatch):
    cfg_file = tmp_path / "audit.toml"
    cfg_file.write_text("[audit]\nescalation_threshold = 1\n")
    monkeypatch.setenv("OWASP_ESCALATION_THRESHOLD", "9")
    monkeypatch.setenv("OWASP_ENABLED_CHECKERS", "A02,A03")
    monkeypatch.setenv("OWASP_LLM_MODEL", "env-model")
    c = AuditConfig.load(cfg_file)
    assert c.escalation_threshold == 9          # env menang atas file
    assert c.llm_model == "env-model"
    assert c.enabled_checkers == ["A02", "A03"]
    assert c.is_checker_enabled("A02") is True
    assert c.is_checker_enabled("A01") is False


def test_env_bool_parsing(monkeypatch):
    monkeypatch.setenv("OWASP_AUTO_FIX", "false")
    assert AuditConfig.load().auto_fix is False
    monkeypatch.setenv("OWASP_AUTO_FIX", "yes")
    assert AuditConfig.load().auto_fix is True
