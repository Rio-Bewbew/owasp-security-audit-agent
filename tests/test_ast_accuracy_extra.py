"""Akurasi AST untuk 4 checker terbaru: Access Control (A01), Insecure Design
(A06), Logging (A09), Exception (A10)."""
from agent.tools.access_control_checker import AccessControlChecker
from agent.tools.exception_checker import ExceptionChecker
from agent.tools.logging_checker import LoggingChecker


def test_a10_detects_bare_except_pass():
    findings = ExceptionChecker().analyze("try:\n    x()\nexcept:\n    pass\n", "t.py")
    assert any(f.owasp_category.name == "A10" for f in findings)


def test_a10_ignores_except_pass_inside_string():
    # 'except: pass' hanya sebagai teks di dalam string -> bukan handler sungguhan
    code = 'doc = "contoh buruk: except: pass menelan error"\n'
    assert ExceptionChecker().analyze(code, "t.py") == []


def test_a10_division_in_try_not_flagged():
    safe = "def f(a, b):\n    try:\n        return a / b\n    except ZeroDivisionError:\n        return 0\n"
    findings = ExceptionChecker().analyze(safe, "t.py")
    assert not any("Division" in f.title for f in findings)


def test_a09_ignores_log_word_in_comment():
    # 'password' hanya di komentar, bukan argumen pemanggilan log sungguhan
    code = "logging.info(user_id)  # jangan log password di sini\n"
    findings = LoggingChecker().analyze(code, "t.py")
    assert findings == []


def test_a01_detects_path_traversal_but_not_plain_word():
    ac = AccessControlChecker()
    assert any(f.owasp_category.name == "A01"
               for f in ac.analyze('p = open("../../etc/passwd")\n', "t.py"))
    # kata 'delete' di komentar/variabel biasa bukan fungsi sensitif
    assert ac.analyze("deleted_count = 0  # delete something later\n", "t.py") == []
