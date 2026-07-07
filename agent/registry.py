from typing import List, Dict
from agent.base_checker import BaseChecker
from agent.models import OWASPCategory


class CheckerRegistry:
    """
    Registry untuk semua OWASP checker.
    Checker baru cukup didaftarkan di sini tanpa mengubah core system.
    """

    def __init__(self):
        self._checkers: Dict[OWASPCategory, BaseChecker] = {}

    def register(self, checker: BaseChecker) -> None:
        """Daftarkan checker. Skip jika kategori sudah terdaftar (cegah duplikat)."""
        if checker.category not in self._checkers:
            self._checkers[checker.category] = checker

    def get_all(self) -> List[BaseChecker]:
        return list(self._checkers.values())

    def get_by_category(self, category: OWASPCategory) -> BaseChecker:
        if category not in self._checkers:
            raise KeyError(f"No checker registered for {category.value}")
        return self._checkers[category]

    def list_registered(self) -> List[str]:
        return [f"{c.category.value} -> {c.name}" for c in self._checkers.values()]

    def clear(self) -> None:
        """Reset registry (untuk testing atau re-init)."""
        self._checkers = {}

    def count(self) -> int:
        return len(self._checkers)


# Instance global — dipakai seluruh aplikasi
registry = CheckerRegistry()
