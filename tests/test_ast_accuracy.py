"""Membuktikan analisis AST lebih akurat daripada regex:
tidak menandai pola berbahaya yang muncul di komentar/string, tapi tetap
menandai pemanggilan sungguhan. Juga menguji fallback hybrid ke regex saat
kode gagal di-parse."""
from agent.tools.injection_checker import InjectionChecker
from agent.tools.crypto_checker import CryptoChecker


def test_ast_ignores_os_system_in_string_and_comment():
    checker = InjectionChecker()
    code = (
        'msg = "gunakan os.system(cmd) untuk contoh"  # os.system(x) di komentar\n'
        'help_text = "eval(expr) berbahaya"\n'
    )
    # AST tidak menemukan pemanggilan sungguhan -> tidak ada temuan
    assert checker.analyze(code, "t.py") == []
    # Regex lama (fallback) JUSTRU salah menandainya -> membuktikan AST lebih akurat
    assert len(checker.check_regex(code, "t.py")) >= 1


def test_ast_detects_real_call():
    checker = InjectionChecker()
    findings = checker.analyze('import os\nos.system("rm -rf /tmp/x")\n', "t.py")
    assert any(f.owasp_category.name == "A05" for f in findings)


def test_hybrid_fallback_on_syntax_error():
    # Kode tak lengkap -> ast.parse gagal -> fallback ke regex tetap mendeteksi
    checker = InjectionChecker()
    broken = 'os.system("ls")\ndef broken(\n'
    findings = checker.analyze(broken, "t.py")
    assert any(f.owasp_category.name == "A05" for f in findings)


def test_ast_ignores_secret_name_used_not_assigned():
    # 'password' sebagai pemakaian biasa, bukan assignment literal -> tidak ditandai
    checker = CryptoChecker()
    code = "def check(password):\n    return verify(password)\n"
    assert checker.analyze(code, "t.py") == []


def test_ast_detects_hardcoded_secret_assignment():
    checker = CryptoChecker()
    findings = checker.analyze('api_key = "supersecret12345"\n', "t.py")
    assert any(f.severity.value == "Critical" for f in findings)
