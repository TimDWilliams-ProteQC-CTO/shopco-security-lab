"""
vulnerable_shop_CLEAN.py  —  Module 4: OWASP Bingo — Delegate Worksheet Version
=================================================================================
This is the CLEAN PRINT VERSION of the OWASP Bingo exercise.

The flaw-indicator comments have been removed so that delegates must identify
the security issues themselves. Print this file or display it on screen during
the exercise.

Instructions for delegates:
  1. Read through this source code carefully.
  2. Annotate each security flaw you find with the OWASP Top 10:2025 category.
  3. Describe in one sentence what an attacker could do with each flaw.
  4. There are EIGHT deliberate flaws. Can you find them all?

Hint: Focus on these areas —
  - Application configuration (top of the file)
  - The login() function
  - The profile() function
  - The ping() function
  - The search() function
"""

from flask import Flask, request, session, jsonify, redirect, url_for, make_response
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "password"
app.config["DEBUG"] = True

DB_PATH = "shop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_hash  = hashlib.md5(password.encode()).hexdigest()
        db       = get_db()
        query    = (
            f"SELECT * FROM users "
            f"WHERE username='{username}' AND password_hash='{pw_hash}'"
        )
        row = db.execute(query).fetchone()
        db.close()
        if row:
            session["user"] = row["username"]
            session["role"] = row["role"]
            return redirect("/")
        return "Invalid credentials", 401
    return """
        <form method="POST">
          <input name="username" placeholder="Username"><br>
          <input name="password" placeholder="Password" type="password"><br>
          <button>Login</button>
        </form>
    """


@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "1")
    db  = get_db()
    row = db.execute(f"SELECT * FROM users WHERE id={user_id}").fetchone()
    db.close()
    if not row:
        return "User not found", 404
    return jsonify({
        "id":            row["id"],
        "username":      row["username"],
        "role":          row["role"],
        "email":         row["email"],
        "full_name":     row["full_name"],
        "password_hash": row["password_hash"],
    })


@app.route("/search")
def search():
    q  = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/ping")
def ping():
    host   = request.args.get("host", "localhost")
    output = os.popen(f"ping -c 2 {host}").read()
    return f"<pre>{output}</pre>"


@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return "Forbidden", 403
    db   = get_db()
    rows = db.execute("SELECT id, username, role, email FROM users").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
