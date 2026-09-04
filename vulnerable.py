import hashlib
import sqlite3
import subprocess

# 1. SQL Injection vulnerability (direct string interpolation in execute)
def get_user(username: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# 2. Command Injection vulnerability (shell=True with unescaped input)
def ping_server(host: str):
    cmd = f"ping -c 1 {host}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# 3. Weak Cryptographic Hash (MD5 is insecure for password hashing)
def hash_password(password: str):
    return hashlib.md5(password.encode()).hexdigest()
