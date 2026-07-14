"""
Infrastruktur analisis berbasis AST untuk checker.

`ASTChecker` adalah base class yang mem-parse source code menjadi Abstract
Syntax Tree lalu memanggil `check_ast()`. Analisis struktural (pemanggilan
fungsi, assignment, perbandingan) jauh lebih akurat daripada regex dan tidak
menghasilkan false-positive pada teks di dalam string atau komentar.

Kalau kode gagal di-parse (mis. potongan kode tidak lengkap), checker jatuh
kembali (fallback) ke `check_regex()` — mode hybrid — sehingga tetap berguna
untuk snippet parsial.
"""
from __future__ import annotations

import ast
from typing import List, Optional

from agent.base_checker import BaseChecker
from agent.models import Finding


def call_name(node: ast.Call) -> str:
    """
    Kembalikan nama ber-titik dari target sebuah Call.
    Contoh: os.system -> "os.system", hashlib.md5 -> "hashlib.md5",
    eval -> "eval". Kembalikan "" jika tidak bisa ditentukan.
    """
    parts: List[str] = []
    func = node.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def is_dynamic_string(node: ast.expr) -> bool:
    """
    True jika ekspresi membangun string secara dinamis:
    - f-string (JoinedStr)
    - konkatenasi `a + b` (BinOp Add)
    - format `"..." % x` (BinOp Mod)
    """
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    return False


def references_names(node: ast.expr, names: set[str]) -> bool:
    """True jika di dalam ekspresi ada Name yang cocok dengan salah satu `names`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in names:
            return True
    return False


def const_str(node: ast.expr) -> Optional[str]:
    """Kembalikan nilai string jika node adalah konstanta string, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def has_keyword(node: ast.Call, name: str) -> Optional[ast.keyword]:
    """Cari keyword argument bernama `name` pada sebuah Call."""
    for kw in node.keywords:
        if kw.arg == name:
            return kw
    return None


class ASTChecker(BaseChecker):
    """
    Base untuk checker berbasis AST.

    Subclass mengimplementasikan `check_ast(tree, code, filename)`.
    Opsional: `check_regex(code, filename)` sebagai fallback saat kode gagal
    diparse (default: tidak menghasilkan temuan).
    """

    def analyze(self, code: str, filename: str) -> List[Finding]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self.check_regex(code, filename)
        return self.check_ast(tree, code, filename)

    def check_ast(self, tree: ast.AST, code: str, filename: str) -> List[Finding]:
        raise NotImplementedError

    def check_regex(self, code: str, filename: str) -> List[Finding]:
        return []
