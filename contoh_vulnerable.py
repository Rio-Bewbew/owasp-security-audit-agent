"""
Contoh kode VULNERABLE untuk testing OWASP Security Audit Agent.
JANGAN digunakan di production!
"""
import sqlite3
import hashlib
import logging
import subprocess
import yaml
import pickle
import os

# ──────────────────────────────────────────────
# A05 - Injection: SQL Injection
# ──────────────────────────────────────────────
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: string formatting langsung di query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(keyword):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # VULNERABLE: f-string di query
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")
    return cursor.fetchall()


# ──────────────────────────────────────────────
# A04 - Cryptographic Failures: MD5 + hardcoded secret
# ──────────────────────────────────────────────
SECRET_KEY = "mysecretpassword123"
DB_PASSWORD = "admin1234"
API_KEY = "sk-abc123hardcodedtoken"

def hash_password(password):
    # VULNERABLE: MD5 sudah deprecated untuk password hashing
    return hashlib.md5(password.encode()).hexdigest()


def check_password(input_pw, stored_hash):
    # VULNERABLE: MD5 + timing attack (== comparison)
    return hashlib.md5(input_pw.encode()).hexdigest() == stored_hash


# ──────────────────────────────────────────────
# A01 - Broken Access Control
# ──────────────────────────────────────────────
def get_user_data(user_id, requested_id):
    # VULNERABLE: tidak ada pengecekan apakah user_id == requested_id
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (requested_id,))
    return cursor.fetchone()


def delete_file(filepath):
    # VULNERABLE: tidak ada sanitasi path, bisa path traversal
    os.remove(filepath)


# ──────────────────────────────────────────────
# A05 - Injection: Command Injection + eval
# ──────────────────────────────────────────────
def ping_host(host):
    # VULNERABLE: command injection via shell=True
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


def calculate(expression):
    # VULNERABLE: eval() dengan input dari user
    return eval(expression)


def load_template(template_str):
    # VULNERABLE: eval untuk render template
    return eval(f'f"{template_str}"')


# ──────────────────────────────────────────────
# A09 - Logging Failures: log data sensitif
# ──────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG)

def login(username, password):
    # VULNERABLE: password ikut di-log
    logging.info(f"Login attempt: username={username}, password={password}")
    user = get_user(username)
    if user and check_password(password, user[2]):
        logging.info(f"Login success for {username}")
        return True
    logging.warning(f"Failed login for {username} with password {password}")
    return False


def process_payment(card_number, cvv, amount):
    # VULNERABLE: data kartu kredit di-log
    logging.debug(f"Processing payment: card={card_number}, cvv={cvv}, amount={amount}")
    return {"status": "ok"}


# ──────────────────────────────────────────────
# A08 - Data Integrity Failures: deserialisasi tidak aman
# ──────────────────────────────────────────────
def load_session(session_data: bytes):
    # VULNERABLE: pickle.loads dari input tidak terpercaya
    return pickle.loads(session_data)


def load_config(yaml_string: str):
    # VULNERABLE: yaml.load tanpa Loader (arbitrary code execution)
    return yaml.load(yaml_string)


# ──────────────────────────────────────────────
# A02 - Security Misconfiguration: debug mode + no TLS
# ──────────────────────────────────────────────
DEBUG = True
ALLOW_ALL_ORIGINS = True
VERIFY_SSL = False

def make_request(url, data):
    import urllib.request
    # VULNERABLE: SSL verification dimatikan
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.urlopen(url, context=ctx)


# ──────────────────────────────────────────────
# A10 - Exception Handling: bare except + info bocor
# ──────────────────────────────────────────────
def read_config(filepath):
    try:
        with open(filepath) as f:
            return f.read()
    except:
        # VULNERABLE: bare except, semua error ditelan
        pass


def api_endpoint(user_input):
    try:
        result = calculate(user_input)
        return {"result": result}
    except Exception as e:
        # VULNERABLE: stack trace bocor ke user
        return {"error": str(e), "trace": repr(e)}


if __name__ == "__main__":
    # Test semua fungsi rentan
    print(get_user("admin' OR '1'='1"))
    print(hash_password("password123"))
    print(ping_host("google.com; cat /etc/passwd"))
    print(calculate("__import__('os').system('id')"))
