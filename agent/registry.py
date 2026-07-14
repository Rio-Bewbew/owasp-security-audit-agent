import importlib
import inspect
import pkgutil
from typing import List, Dict

from agent.base_checker import BaseChecker
from agent.models import OWASPCategory

# Group entry-point yang dipindai untuk plugin checker pihak ketiga.
# Paket eksternal cukup mendeklarasikan:
#   [project.entry-points."owasp_audit_agent.checkers"]
#   my_checker = "my_pkg.module:MyChecker"
ENTRY_POINT_GROUP = "owasp_audit_agent.checkers"


class CheckerRegistry:
    """
    Registry untuk semua OWASP checker.

    Checker bisa didaftarkan dengan tiga cara:
      1. register()            — manual (satu instance).
      2. discover_local()      — auto-scan sebuah package internal
                                 (default: agent.tools) dan daftarkan
                                 semua subclass BaseChecker konkret.
      3. discover_entry_points() — muat plugin pihak ketiga yang
                                 mendeklarasikan entry point pada group
                                 "owasp_audit_agent.checkers".
    Ketiganya tidak menyentuh core system — inilah titik ekstensi framework.
    """

    def __init__(self):
        self._checkers: Dict[OWASPCategory, BaseChecker] = {}

    def register(self, checker: BaseChecker) -> None:
        """Daftarkan checker. Skip jika kategori sudah terdaftar (cegah duplikat)."""
        if checker.category not in self._checkers:
            self._checkers[checker.category] = checker

    def register_class(self, checker_cls: type) -> bool:
        """
        Instansiasi lalu daftarkan sebuah subclass BaseChecker konkret.
        Return True jika berhasil didaftarkan, False jika dilewati.
        """
        if (
            not inspect.isclass(checker_cls)
            or not issubclass(checker_cls, BaseChecker)
            or inspect.isabstract(checker_cls)
            or checker_cls is BaseChecker
        ):
            return False
        before = len(self._checkers)
        self.register(checker_cls())
        return len(self._checkers) > before

    def discover_local(self, package: str = "agent.tools") -> int:
        """
        Pindai semua modul dalam `package`, temukan setiap subclass
        BaseChecker konkret, lalu daftarkan. Return jumlah yang baru terdaftar.
        Tambah checker baru cukup dengan menaruh file di folder tersebut —
        tanpa mengubah kode inti.
        """
        pkg = importlib.import_module(package)
        registered = 0
        for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            module = importlib.import_module(f"{package}.{module_name}")
            for _, obj in inspect.getmembers(module, inspect.isclass):
                # Hanya kelas yang didefinisikan di modul ini (bukan hasil import).
                if obj.__module__ != module.__name__:
                    continue
                if self.register_class(obj):
                    registered += 1
        return registered

    def discover_entry_points(self, group: str = ENTRY_POINT_GROUP) -> int:
        """
        Muat checker plugin pihak ketiga yang terpasang lewat entry points.
        Return jumlah yang baru terdaftar. Aman dipanggil tanpa plugin apa pun.
        """
        from importlib.metadata import entry_points

        registered = 0
        try:
            eps = entry_points(group=group)  # Python 3.10+
        except TypeError:  # fallback API lama
            eps = entry_points().get(group, [])
        for ep in eps:
            try:
                loaded = ep.load()
            except Exception:
                # Plugin rusak tidak boleh menjatuhkan seluruh audit.
                continue
            if self.register_class(loaded):
                registered += 1
        return registered

    def discover(self, package: str = "agent.tools", *, include_plugins: bool = True) -> int:
        """
        Discovery lengkap: checker internal + (opsional) plugin eksternal.
        Return total checker yang baru terdaftar.
        """
        total = self.discover_local(package)
        if include_plugins:
            total += self.discover_entry_points()
        return total

    def apply_config(self, config) -> int:
        """
        Buang checker yang dinonaktifkan config (enabled/disabled by kode kategori,
        mis. 'A01'). Return jumlah checker yang tersisa aktif.
        Aman dipanggil dengan config=None (tidak melakukan apa-apa).
        """
        if config is None:
            return self.count()
        for category in list(self._checkers.keys()):
            if not config.is_checker_enabled(category.name):
                del self._checkers[category]
        return self.count()

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
