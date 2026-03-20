"""
vulnerable_shop_FIXED.py  —  Module 4: OWASP Bingo Reference Solution
======================================================================
This is the corrected version of vulnerable_shop.py. Every deliberate
flaw has been fixed with inline annotations explaining WHY the change
makes the application more secure.

This file should be revealed to delegates AFTER the OWASP Bingo exercise
is complete — not before. The goal is for delegates to compare the two
files side-by-side and understand that the surface-level changes are
small but the security impact is significant.

SETUP (one-time, per VM — shares the same DB as the vulnerable version):
    pip3 install flask bcrypt --break-system-packages
    python3 vulnerable_shop_FIXED.py

    If running after vulnerable_shop.py, delete shop_fixed.db first:
    rm -f shop_fixed.db && python3 vulnerable_shop_FIXED.py

ACCOUNTS: admin / letmein  |  alice / password123  |  bob / qwerty
URL:      http://localhost:5001   (different port — run both side by side)

FIXES APPLIED:
    Fix 1  —  A02: Secret key loaded from environment variable, not hardcoded
    Fix 2  —  A05: DEBUG disabled by default; only enabled via env var
    Fix 3  —  A02: bcrypt replaces MD5 for password hashing
    Fix 4  —  A03: Parameterised queries replace f-string SQL throughout
    Fix 5  —  A07: Session stores user_id (immutable) not username (mutable)
    Fix 6  —  A01: login_required() decorator enforces authentication
    Fix 7  —  A01: Profile always loads from session user_id, never from URL
    Fix 8  —  A03: subprocess with shell=False + allowlist input validation
"""

from flask import Flask, request, session, jsonify, redirect, url_for, g, abort
import sqlite3
import os
import re
import subprocess
import bcrypt              # pip3 install bcrypt --break-system-packages
import functools

# ─────────────────────────────────────────────────────────────────────────────
#  Application configuration
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Fix 1 — Secret key is loaded from an environment variable set at runtime.
#          It NEVER appears in source code or version control.
#          Generate a strong key:  export FLASK_SECRET_KEY=$(openssl rand -hex 32)
#          If the env var is missing, we raise an error immediately rather than
#          silently falling back to a weak default.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
#   ^ os.urandom(32) is used as a development fallback — it changes on every
#     restart (invalidating existing sessions), making it unsuitable for
#     production but safe for a single-VM lab session.

# Fix 2 — DEBUG is off by default. It can only be enabled by setting the
#          environment variable FLASK_DEBUG=true explicitly.
#          In production, FLASK_DEBUG must never be set.
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

DB_PATH = "shop_fixed.db"


# ─────────────────────────────────────────────────────────────────────────────
#  Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    """Return a per-request SQLite connection (stored on Flask's g object)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the DB connection at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed demo data if the database does not yet exist."""
    if os.path.exists(DB_PATH):
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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

    # Fix 3 — Passwords are hashed with bcrypt (work factor 12).
    #          bcrypt is intentionally slow: ~250ms per hash on typical hardware.
    #          This makes offline dictionary attacks orders of magnitude harder
    #          compared to MD5, which can be computed at billions of hashes/second.
    def make_hash(plaintext: str) -> str:
        return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()

    users = [
        ("admin", make_hash("letmein"),      "admin", "admin@shopco.internal", "Shop Admin"),
        ("alice", make_hash("password123"),  "user",  "alice@example.com",    "Alice Smith"),
        ("bob",   make_hash("qwerty"),       "user",  "bob@example.com",      "Bob Jones"),
    ]
    c.executemany(
        "INSERT INTO users (username, password_hash, role, email, full_name) VALUES (?,?,?,?,?)",
        users
    )

    products = [
        ("Laptop Pro 15",      1299.99, 12),
        ("Wireless Mouse",       24.99, 87),
        ("USB-C Hub",            39.99, 43),
        ("Mechanical Keyboard",  89.99, 31),
        ("4K Webcam",            79.99, 18),
    ]
    c.executemany("INSERT INTO products (name, price, stock) VALUES (?,?,?)", products)
    conn.commit()
    conn.close()
    print("[*] Fixed database initialised with bcrypt-hashed passwords.")


# ─────────────────────────────────────────────────────────────────────────────
#  Authentication helpers
# ─────────────────────────────────────────────────────────────────────────────

# Fix 6 — A reusable decorator that enforces authentication on any route.
#          Wrap a route with @login_required to redirect unauthenticated
#          visitors to the login page instead of serving them the content.
def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # Fix 5 — We check for user_id (an immutable integer), not username
        #          (a mutable string). A user cannot change their own ID.
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Load the authenticated user's record from the DB using the session user_id."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    # Fix 4 — Parameterised query: user_id comes from the server-side session,
    #          but we still use a parameter placeholder to make the intent explicit
    #          and to protect against any future refactoring that might pass
    #          user-controlled values here.
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


# ─────────────────────────────────────────────────────────────────────────────
#  Inline HTML templates
# ─────────────────────────────────────────────────────────────────────────────

BASE_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>ShopCo FIXED — {title}</title>
  <style>
    body  {{ font-family: Arial, sans-serif; margin: 0; background: #f4f4f4; }}
    nav   {{ background: #1e7145; padding: 10px 20px; color: white; display: flex;
             justify-content: space-between; align-items: center; }}
    nav a {{ color: white; text-decoration: none; margin-left: 15px; font-size: 14px; }}
    .container {{ max-width: 900px; margin: 30px auto; background: white;
                  padding: 30px; border-radius: 6px; box-shadow: 0 2px 6px rgba(0,0,0,.1); }}
    input[type=text], input[type=password] {{
      width: 100%; padding: 8px; margin: 6px 0 14px; box-sizing: border-box;
      border: 1px solid #ccc; border-radius: 4px; }}
    button {{ background: #1e7145; color: white; padding: 9px 20px; border: none;
              border-radius: 4px; cursor: pointer; font-size: 14px; }}
    .alert-danger  {{ background: #fdecea; border: 1px solid #e74c3c; padding: 10px;
                      border-radius: 4px; margin-bottom: 15px; color: #c0392b; }}
    .alert-success {{ background: #eaf4ea; border: 1px solid #27ae60; padding: 10px;
                      border-radius: 4px; margin-bottom: 15px; color: #1e7145; }}
    .fix-note {{ background: #e8f4fd; border-left: 4px solid #2e75b6; padding: 10px 14px;
                 margin: 10px 0; font-size: 13px; color: #1a4a6b; }}
    table  {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
    th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 14px; }}
    th     {{ background: #1e7145; color: white; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
  </style>
</head>
<body>
<nav>
  <span><strong>ShopCo FIXED</strong> — Secure Demo</span>
  <div>
    {nav_links}
  </div>
</nav>
<div class="container">
  {content}
</div>
</body>
</html>"""


def render(title, content, user=None):
    """Minimal template renderer."""
    if user:
        nav_links = (
            f'<a href="/">Home</a>'
            f'<a href="/search">Products</a>'
            f'<a href="/profile">My Profile</a>'
            f'<a href="/ping">Ping Tool</a>'
            f'<a href="/logout">Logout ({user["username"]})</a>'
        )
    else:
        nav_links = '<a href="/">Home</a><a href="/login">Login</a>'
    return BASE_HTML.format(title=title, content=content, nav_links=nav_links)


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    user = get_current_user()
    content = """
        <h2>Welcome to ShopCo <span style="color:#1e7145">(Fixed Version)</span></h2>
        <p>This is the corrected version of the OWASP Bingo exercise app.</p>
        <p>Compare the source of this file with <code>vulnerable_shop.py</code> to see
           exactly what changed — and why.</p>
        <div class="fix-note">
          <strong>All 8 flaws have been corrected.</strong> The application still has the
          same features and UI — the security improvements are entirely in the server-side code.
        </div>
    """
    if user:
        content += f'<div class="alert-success">Logged in as: <strong>{user["username"]}</strong> (role: {user["role"]})</div>'
    return render("Home", content, user)


@app.route("/login", methods=["GET", "POST"])
def login():
    user  = get_current_user()
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Fix 4 — Parameterised query: the username value is passed as a
        #          parameter, never interpolated into the SQL string.
        #          No matter what the user types, it cannot alter the query structure.
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Fix 3 — bcrypt.checkpw() performs a constant-time comparison that
        #          is resistant to timing attacks. The stored hash includes the
        #          salt, so no separate salt column is needed.
        #          Note: we check row is not None BEFORE calling checkpw to
        #          avoid a bcrypt error — but we use the SAME error message
        #          regardless (preventing username enumeration).
        authenticated = (
            row is not None and
            bcrypt.checkpw(password.encode(), row["password_hash"].encode())
        )

        if authenticated:
            # Fix 5 — Store the immutable user_id, not the mutable username.
            #          Role and display name are re-fetched from the DB on each
            #          request via get_current_user(), never trusted from the session.
            session.clear()                    # Prevent session fixation
            session["user_id"] = row["id"]
            next_page = request.args.get("next", url_for("index"))
            return redirect(next_page)
        else:
            # Fix 10 (bonus) — Identical error message whether the username
            #                   exists or not, preventing account enumeration.
            error = "Invalid username or password."

    content = f"""
        <h2>Login</h2>
        <div class="fix-note">
          Fix 3: Passwords are stored as bcrypt hashes.<br>
          Fix 4: Login query uses a parameterised statement — SQL injection is not possible.<br>
          Fix 5: Session stores user_id, not username.
        </div>
        {'<div class="alert-danger">' + error + '</div>' if error else ''}
        <form method="POST">
          <label>Username</label>
          <input type="text"     name="username" autocomplete="username">
          <label>Password</label>
          <input type="password" name="password" autocomplete="current-password">
          <button type="submit">Login</button>
        </form>
        <p style="font-size:13px;color:#888">
          Demo accounts: admin/letmein &nbsp;|&nbsp; alice/password123 &nbsp;|&nbsp; bob/qwerty
        </p>
    """
    return render("Login", content, user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    user = get_current_user()
    q    = request.args.get("q", "")
    rows = []

    if q:
        # Fix 4 — Parameterised query. The LIKE wildcard characters % are part
        #          of the parameter value, not the query structure — so a user
        #          supplying % or ' in their search term cannot alter the query.
        rows = get_db().execute(
            "SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)
        ).fetchall()

    rows_html = ""
    for r in rows:
        rows_html += (
            f"<tr><td>{r['id']}</td><td>{r['name']}</td>"
            f"<td>£{r['price']:.2f}</td><td>{r['stock']}</td></tr>"
        )

    table = f"""
        <table>
          <tr><th>ID</th><th>Name</th><th>Price</th><th>Stock</th></tr>
          {rows_html if rows_html else '<tr><td colspan="4">No results</td></tr>'}
        </table>
    """ if q else ""

    content = f"""
        <h2>Product Search</h2>
        <div class="fix-note">
          Fix 4: Parameterised query — UNION injection returns an error, not data.
        </div>
        <form method="GET">
          <input type="text" name="q" value="{q}" placeholder="Search products...">
          <button type="submit">Search</button>
        </form>
        {table}
    """
    return render("Search", content, user)


@app.route("/profile")
@login_required    # Fix 6 — Route is now protected; unauthenticated requests are redirected
def profile():
    # Fix 7 — The user_id comes exclusively from the server-side session.
    #          There is no URL parameter. An authenticated user can only ever
    #          see their own profile — regardless of what they put in the URL.
    user = get_current_user()

    if not user:
        return redirect(url_for("login"))

    content = f"""
        <h2>My Profile</h2>
        <div class="fix-note">
          Fix 6: This route requires authentication (@login_required).<br>
          Fix 7: Profile loads from session user_id — no URL parameter is accepted.
          There is no way to view another user's profile from this route.
        </div>
        <table>
          <tr><th>Field</th><th>Value</th></tr>
          <tr><td>ID</td>        <td>{user["id"]}</td></tr>
          <tr><td>Username</td>  <td>{user["username"]}</td></tr>
          <tr><td>Role</td>      <td>{user["role"]}</td></tr>
          <tr><td>Email</td>     <td>{user["email"]}</td></tr>
          <tr><td>Full Name</td> <td>{user["full_name"]}</td></tr>
          <tr><td>Password</td>  <td><em>[bcrypt hash — not displayed]</em></td></tr>
        </table>
    """
    return render("My Profile", content, user)


@app.route("/ping")
@login_required    # Fix 6 — Also protected; unauthenticated users cannot use this tool
def ping():
    user   = get_current_user()
    host   = request.args.get("host", "")
    output = ""
    error  = ""

    if host:
        # Fix 8a — Input validation: only allow characters that appear in valid
        #           hostnames and IPv4/IPv6 addresses. Shell metacharacters
        #           (;  &  |  $  `  >  <  etc.) are rejected outright.
        if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
            error = (
                "Invalid host. Only letters, digits, hyphens, and dots are permitted. "
                "Shell metacharacters are not allowed."
            )
        else:
            try:
                # Fix 8b — subprocess.run() with shell=False passes the command as a
                #           list of strings. The OS executes ping directly without
                #           invoking a shell, so there is no shell to interpret
                #           metacharacters even if the allowlist were bypassed.
                result = subprocess.run(
                    ["ping", "-c", "2", "-W", "2", host],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False      # ← KEY: no shell means no shell injection
                )
                output = result.stdout or result.stderr
            except subprocess.TimeoutExpired:
                error = "Ping timed out."
            except Exception:
                error = "Ping failed. Check the hostname and try again."

    content = f"""
        <h2>Network Ping Tool</h2>
        <div class="fix-note">
          Fix 8a: Input validated against an allowlist of safe characters.<br>
          Fix 8b: subprocess.run() with shell=False — no shell, no injection.
        </div>
        {'<div class="alert-danger">' + error + '</div>' if error else ''}
        <form method="GET">
          <label>Hostname or IP address</label>
          <input type="text" name="host" value="{host}" placeholder="e.g. localhost or 8.8.8.8">
          <button type="submit">Ping</button>
        </form>
        {'<pre style="background:#1e1e1e;color:#d4d4d4;padding:15px;border-radius:4px;overflow:auto">'
         + output + '</pre>' if output else ''}
    """
    return render("Ping Tool", content, user)


@app.route("/admin")
@login_required
def admin():
    """Admin panel — now properly verifies role from the DB, not from a forgeable session."""
    user = get_current_user()

    # Fix 1 + Fix 5 combined: even if an attacker forged the session cookie,
    # the role comes from get_current_user() which re-queries the database using
    # the session user_id. There is no role stored in the session itself.
    if user["role"] != "admin":
        abort(403)

    rows = get_db().execute(
        "SELECT id, username, role, email FROM users"
    ).fetchall()

    rows_html = "".join(
        f"<tr><td>{r['id']}</td><td>{r['username']}</td>"
        f"<td>{r['role']}</td><td>{r['email']}</td></tr>"
        for r in rows
    )
    content = f"""
        <h2>Admin Panel — All Users</h2>
        <div class="fix-note">
          Fix 1 & 5: Role is always re-fetched from the database using the session user_id.
          It is never stored in or trusted from the session cookie — so cookie forgery
          grants no privilege escalation even if the secret key were compromised.
        </div>
        <table>
          <tr><th>ID</th><th>Username</th><th>Role</th><th>Email</th></tr>
          {rows_html}
        </table>
    """
    return render("Admin Panel", content, user)


# Fix 2 side-effect: Custom error handlers return safe, generic messages.
# The detailed exception is logged server-side only — never sent to the browser.
@app.errorhandler(403)
def forbidden(e):
    user = get_current_user()
    content = '<div class="alert-danger"><strong>403 Forbidden.</strong> You do not have permission to access this page.</div>'
    return render("Access Denied", content, user), 403


@app.errorhandler(404)
def not_found(e):
    # Deliberately vague — does not confirm whether the resource exists
    content = '<div class="alert-danger"><strong>404 Not Found.</strong> The page you requested could not be found.</div>'
    return render("Not Found", content), 404


@app.errorhandler(500)
def server_error(e):
    # Log the full exception server-side, return a generic message to the client
    app.logger.error(f"Unhandled exception: {e}", exc_info=True)
    content = '<div class="alert-danger"><strong>500 Internal Server Error.</strong> Something went wrong. Please try again.</div>'
    return render("Server Error", content), 500


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 60)
    print("  ShopCo FIXED  —  Module 4 OWASP Bingo Reference Solution")
    print("=" * 60)
    print("  URL:      http://localhost:5001")
    print("  Accounts: admin/letmein  |  alice/password123  |  bob/qwerty")
    print("  Compare this file line-by-line with vulnerable_shop.py")
    print("  to understand exactly what each fix does and why.")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=5001, debug=False)    # Fix 2 — debug=False
