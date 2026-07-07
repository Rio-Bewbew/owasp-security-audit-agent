import re
from typing import Tuple


class RuleBasedFixer:
    """
    Memperbaiki vulnerability secara deterministik menggunakan regex replacement.
    Tidak menggunakan LLM sehingga output konsisten dan tidak halusinasi.
    """

    def fix(self, code: str) -> Tuple[str, int]:
        """
        Jalankan semua rule fix pada kode.
        Returns: (fixed_code, jumlah_perbaikan)
        """
        fixed = code
        count = 0

        rules = [
            self._fix_md5,
            self._fix_sha1,
            self._fix_yaml_load,
            self._fix_pickle_loads,
            self._fix_debug_true,
            self._fix_os_system,
            self._fix_subprocess_shell,
            self._fix_bare_except,
            self._fix_verify_false,
            self._fix_random_for_secrets,
            self._fix_hardcoded_password,
            self._fix_hardcoded_secret_key,
            self._fix_hardcoded_api_key,
            self._fix_allowed_hosts_wildcard,
        ]

        for rule in rules:
            new_code, n = rule(fixed)
            fixed = new_code
            count += n

        return fixed, count

    def _fix_md5(self, code: str) -> Tuple[str, int]:
        pattern = r'hashlib\.md5\s*\('
        replacement = 'hashlib.sha256('
        new_code, n = re.subn(pattern, replacement, code)
        if n:
            new_code = self._add_comment(new_code, 'hashlib.sha256(', '# FIXED A04: Ganti MD5 dengan SHA-256')
        return new_code, n

    def _fix_sha1(self, code: str) -> Tuple[str, int]:
        pattern = r'hashlib\.sha1\s*\('
        replacement = 'hashlib.sha256('
        new_code, n = re.subn(pattern, replacement, code)
        if n:
            new_code = self._add_comment(new_code, 'hashlib.sha256(', '# FIXED A04: Ganti SHA1 dengan SHA-256')
        return new_code, n

    def _fix_yaml_load(self, code: str) -> Tuple[str, int]:
        pattern = r'yaml\.load\s*\(\s*(\w+)\s*\)'
        replacement = r'yaml.safe_load(\1)  # FIXED A03: Gunakan safe_load'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _fix_pickle_loads(self, code: str) -> Tuple[str, int]:
        pattern = r'pickle\.loads?\s*\('
        replacement = '# FIXED A03: pickle tidak aman, gunakan json.loads()\njson.loads('
        new_code, n = re.subn(pattern, replacement, code)
        if n and 'import json' not in new_code:
            new_code = 'import json  # FIXED A03: Tambah import json\n' + new_code
        return new_code, n

    def _fix_debug_true(self, code: str) -> Tuple[str, int]:
        pattern = r'\bDEBUG\s*=\s*True\b'
        replacement = 'DEBUG = os.getenv("DEBUG", "False") == "True"  # FIXED A02: Ambil dari env var'
        new_code, n = re.subn(pattern, replacement, code)
        if n and 'import os' not in new_code:
            new_code = 'import os\n' + new_code
        return new_code, n

    def _fix_os_system(self, code: str) -> Tuple[str, int]:
        pattern = r'os\.system\s*\(([^)]+)\)'
        replacement = r'subprocess.run(\1, shell=False)  # FIXED A05: Hindari os.system'
        new_code, n = re.subn(pattern, replacement, code)
        if n and 'import subprocess' not in new_code:
            new_code = 'import subprocess  # FIXED A05: Tambah import subprocess\n' + new_code
        return new_code, n

    def _fix_subprocess_shell(self, code: str) -> Tuple[str, int]:
        pattern = r'(subprocess\.\w+\([^)]*)\bshell\s*=\s*True([^)]*\))'
        replacement = r'\1shell=False\2  # FIXED A05: shell=False lebih aman'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _fix_bare_except(self, code: str) -> Tuple[str, int]:
        pattern = r'except\s*:\s*\n(\s*)pass'
        replacement = r'except Exception as e:\n\1import logging; logging.error(e)  # FIXED A10: Log exception'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _fix_verify_false(self, code: str) -> Tuple[str, int]:
        pattern = r'\bverify\s*=\s*False\b'
        replacement = 'verify=True  # FIXED A07: Aktifkan SSL verification'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _fix_random_for_secrets(self, code: str) -> Tuple[str, int]:
        pattern = r'\brandom\.randint\s*\('
        replacement = 'secrets.randbelow(  # FIXED A06: Gunakan secrets module'
        new_code, n = re.subn(pattern, replacement, code)
        if n and 'import secrets' not in new_code:
            new_code = 'import secrets  # FIXED A06: Tambah import secrets\n' + new_code
        return new_code, n

    def _fix_hardcoded_password(self, code: str) -> Tuple[str, int]:
        pattern = r'(password\s*=\s*)["\'][^"\']+["\']'
        replacement = r'\1os.getenv("PASSWORD")  # FIXED A04: Ambil dari environment variable'
        new_code, n = re.subn(pattern, replacement, code, flags=re.IGNORECASE)
        return new_code, n

    def _fix_hardcoded_secret_key(self, code: str) -> Tuple[str, int]:
        pattern = r'(SECRET_KEY\s*=\s*)["\'][^"\']+["\']'
        replacement = r'\1os.getenv("SECRET_KEY")  # FIXED A04: Ambil dari environment variable'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _fix_hardcoded_api_key(self, code: str) -> Tuple[str, int]:
        pattern = r'(api_key\s*=\s*)["\'][^"\']+["\']'
        replacement = r'\1os.getenv("API_KEY")  # FIXED A04: Ambil dari environment variable'
        new_code, n = re.subn(pattern, replacement, code, flags=re.IGNORECASE)
        return new_code, n

    def _fix_allowed_hosts_wildcard(self, code: str) -> Tuple[str, int]:
        pattern = r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]'
        replacement = 'ALLOWED_HOSTS = [os.getenv("ALLOWED_HOST", "localhost")]  # FIXED A02: Tentukan host spesifik'
        new_code, n = re.subn(pattern, replacement, code)
        return new_code, n

    def _add_comment(self, code: str, near: str, comment: str) -> str:
        """Tambahkan komentar di akhir baris yang mengandung pattern tertentu."""
        lines = code.split('\n')
        result = []
        for line in lines:
            if near in line and comment not in line:
                line = line.rstrip() + '  ' + comment
            result.append(line)
        return '\n'.join(result)
