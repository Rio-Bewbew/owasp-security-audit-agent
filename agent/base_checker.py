from abc import ABC, abstractmethod
from typing import List
from agent.models import Finding, OWASPCategory


class BaseChecker(ABC):
    """
    Abstract base class untuk semua OWASP checker.
    Setiap checker baru WAJIB mengimplementasi method analyze().
    """

    @property
    @abstractmethod
    def category(self) -> OWASPCategory:
        """Kategori OWASP yang dicek oleh checker ini."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Nama checker yang mudah dibaca."""
        pass

    @abstractmethod
    def analyze(self, code: str, filename: str) -> List[Finding]:
        """
        Analisis kode dan kembalikan list of Finding.

        Args:
            code: Source code Python sebagai string
            filename: Nama file yang dianalisis

        Returns:
            List of Finding yang ditemukan
        """
        pass

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.category.value}>"