from flask import Flask, request, jsonify, make_response, redirect, send_file
import sqlite3
import os
import pickle
import subprocess
import secrets
import hashlib

app = Flask(__name__)

# ==================== НАВМИСНО ЖАХЛИВІ СЕКРЕТИ ====================
API_KEY = "sk-1234567890abcdef1234567890abcdef"          # detect-secrets
JWT_SECRET = "super_secret_jwt_key_2025"                 # Bandit + detect-secrets
DB_PASSWORD = "P@ssw0rd123!@#"                           # detect-secrets
ENCRYPTION_KEY = "my-super-secret-aes-key-32bytes!!!"    # 32 байти, але в коді!

app.config['SECRET_KEY'] = "hardcoded_secret_key_change_in_production_please"

# ==================== ІНІЦІАЛІЗАЦІЯ БД (SQLi ready) ====================
def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            bio TEXT
        )
    ''')
    # Тестові дані зі слабкими паролями
    conn.execute("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    conn.commit()
    conn.close()

init_db()

# ==================== SQL INJECTION (класика) ====================
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    # НАВМИСНО небезпечна конкатенація!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Login successful", "user": user[1]})
    else:
        return jsonify({"error": "Invalid credentials"}), 401


# ==================== XSS (Reflected + Stored) ====================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        bio = request.form['bio']  # без жодної екранізації!
        user_id = request.form.get('id', '1')
        conn = sqlite3.connect('users.db')
        conn.execute(f"UPDATE users SET bio = '{bio}' WHERE id = {user_id}")
        conn.commit()
        conn.close()
        return jsonify({"message": "Profile updated"})

    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('users.db')
    user = conn.execute(f"SELECT bio FROM users WHERE id = {user_id}").fetchone()
    conn.close()

    # Reflected XSS в URL + Stored XSS з БД
    return f"<h1>Profile</h1><p>{request.args.get('message', '')}</p><p>Bio: {user[0] if user else ''}</p>"


# ==================== Command Injection ====================
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    # Пряме виконання системної команди
    result = subprocess.getoutput(f"ping -c 4 {ip}")
    return f"<pre>{result}</pre>"


# ==================== Path Traversal ====================
@app.route('/file')
def read_file():
    filename = request.args.get('file', '')
    # Без жодної валідації шляху!
    try:
        return send_file(filename)
    except Exception as e:
        return str(e)


# ==================== Insecure Deserialization (pickle) ====================
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data
    try:
        obj = pickle.loads(data)   # критична вразливість!
        return jsonify({"result": str(obj)})
    except:
        return jsonify({"error": "Invalid data"}), 400


# ==================== Open Redirect ====================
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url', '/')
    return redirect(url)


# ==================== Unvalidated File Upload ====================
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file", 400
    file = request.files['file']
    # Зберігаємо будь-який файл, навіть .php!
    file.save(os.path.join('/tmp', file.filename))
    return f"Uploaded {file.filename}"


# ==================== Hardcoded Credentials + Debug Info Leak ====================
@app.route('/debug')
def debug():
    return jsonify({
        "API_KEY": API_KEY,
        "JWT_SECRET": JWT_SECRET,
        "DB_PASSWORD": DB_PASSWORD,
        "ENCRYPTION_KEY": ENCRYPTION_KEY,
        "ENV": os.environ,
        "PYTHON_PATH": os.sys.path
    })


# ==================== Insecure Random (для сесій, токенів) ====================
@app.route('/generate-token')
def weak_token():
    token = hashlib.md5(str(secrets.randbelow(10000)).encode()).hexdigest()  # MD5 + слабка ентропія
    return jsonify({"token": token})


# ==================== Головна сторінка ====================
@app.route('/')
def index():
    return '''
    <h1>DevSecOps Lab 8 — Vulnerable Flask App</h1>
    <ul>
        <li><a href="/login?username=admin'&password=admin123">-- SQL Injection</a></li>
        <li><a href="/profile?message=<script>alert('XSS')</script>">Reflected XSS</a></li>
        <li><a href="/ping?ip=127.0.0.1;whoami">Command Injection</a></li>
        <li><a href="/file?file=../../../../../etc/passwd">Path Traversal</a></li>
        <li><a href="/redirect?url=https://evil.com">Open Redirect</a></li>
    </ul>
    '''


if __name__ == '__main__':
    # НАВМИСНО увімкнений debug режим і доступ ззовні!
    app.run(host='0.0.0.0', port=5000, debug=True)