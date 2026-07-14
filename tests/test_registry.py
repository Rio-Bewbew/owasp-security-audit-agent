"""Test untuk CheckerRegistry: registrasi, auto-discovery, dan filter config."""
from agent.registry import CheckerRegistry, ENTRY_POINT_GROUP
from agent.base_checker import BaseChecker
from agent.models import OWASPCategory


class _DummyChecker(BaseChecker):
    @property
    def category(self):
        return OWASPCategory.A05

    @property
    def name(self):
        return "Dummy"

    def analyze(self, code, filename):
        return []


def test_discover_local_finds_all_ten():
    r = CheckerRegistry()
    n = r.discover_local("agent.tools")
    assert n == 10
    assert r.count() == 10
    # semua kategori OWASP terwakili tepat sekali
    cats = {c.category for c in r.get_all()}
    assert cats == set(OWASPCategory)


def test_register_is_idempotent_per_category():
    r = CheckerRegistry()
    assert r.register_class(_DummyChecker) is True
    # kategori sama tidak boleh terdaftar dua kali
    assert r.register_class(_DummyChecker) is False
    assert r.count() == 1


def test_register_class_rejects_non_checker():
    r = CheckerRegistry()
    assert r.register_class(str) is False
    assert r.register_class(BaseChecker) is False  # kelas abstrak
    assert r.count() == 0


def test_discover_is_idempotent():
    r = CheckerRegistry()
    r.discover_local("agent.tools")
    before = r.count()
    r.discover_local("agent.tools")
    assert r.count() == before == 10


def test_discover_entry_points_safe_without_plugins():
    r = CheckerRegistry()
    # tidak ada plugin terpasang -> 0, tidak error
    assert r.discover_entry_points() == 0


def test_entry_point_group_name():
    assert ENTRY_POINT_GROUP == "owasp_audit_agent.checkers"


def test_apply_config_disables_checkers():
    from agent.config import AuditConfig
    r = CheckerRegistry()
    r.discover_local("agent.tools")
    cfg = AuditConfig(enabled_checkers=["A01", "A07"], disabled_checkers=["A05"])
    remaining = r.apply_config(cfg)
    names = sorted(c.category.name for c in r.get_all())
    assert names == ["A01", "A07"]
    assert remaining == 2


def test_apply_config_none_is_noop():
    r = CheckerRegistry()
    r.discover_local("agent.tools")
    assert r.apply_config(None) == 10


def test_get_by_category_raises_when_absent():
    import pytest
    r = CheckerRegistry()
    with pytest.raises(KeyError):
        r.get_by_category(OWASPCategory.A01)
