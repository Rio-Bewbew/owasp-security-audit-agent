"""Setiap checker OWASP diuji: mendeteksi kategorinya sendiri, dan tidak
false-positive pada kode yang bersih."""
import pytest

from agent.registry import CheckerRegistry

# Satu snippet rentan yang spesifik untuk tiap kategori.
VULNERABLE = {
    "A01": 'data = open("../../etc/passwd").read()\n',           # path traversal
    "A02": 'DEBUG = True\n',                                       # debug mode aktif
    "A03": 'obj = pickle.loads(payload)\n',                        # unsafe deserialization
    "A04": 'api_key = "abcdef123456"\n',                           # hardcoded secret
    "A05": 'os.system("ls -la")\n',                                # command injection
    "A06": 'otp = random.randint(1000, 9999)\n',                   # random utk keamanan
    "A07": 'r = requests.get(url, verify=False)\n',                # SSL verify off
    "A08": 'subprocess.run("ls " + user_dir)\n',                   # subprocess string dinamis
    "A09": 'logging.info("user password: " + pw)\n',              # password di log
    "A10": "try:\n    risky()\nexcept:\n    pass\n",              # bare except: pass
}

CLEAN_CODE = 'def greet(name):\n    return "Hello " + name\n'


@pytest.fixture(scope="module")
def checkers():
    r = CheckerRegistry()
    r.discover_local("agent.tools")
    return {c.category.name: c for c in r.get_all()}


@pytest.mark.parametrize("code", sorted(VULNERABLE))
def test_checker_detects_its_own_category(checkers, code):
    checker = checkers[code]
    findings = checker.analyze(VULNERABLE[code], "vuln.py")
    assert any(f.owasp_category.name == code for f in findings), (
        f"{code} ({checker.name}) gagal mendeteksi snippet rentannya"
    )


@pytest.mark.parametrize("code", sorted(VULNERABLE))
def test_checker_no_false_positive_on_clean_code(checkers, code):
    findings = checkers[code].analyze(CLEAN_CODE, "clean.py")
    assert findings == [], f"{code} false-positive pada kode bersih: {findings}"


def test_all_ten_categories_covered(checkers):
    assert sorted(checkers) == [f"A{i:02d}" for i in range(1, 11)]
