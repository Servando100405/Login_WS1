from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for login sessions
app.secret_key = "richelle_dashboard_secret"


# ==========================
# DATABASE CONNECTION
# ==========================

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


# ==========================
# CREATE DATABASE
# ==========================

def create_database():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ==========================
# LOGIN PAGE
# ==========================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            # Save user information in session
            session["user_id"] = user["id"]
            session["first_name"] = user["first_name"]
            session["last_name"] = user["last_name"]
            session["username"] = user["username"]

            return redirect("/dashboard")

        return "Invalid username or password."

    return render_template("Login.html")


# ==========================
# SIGN UP PAGE
# ==========================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check password
        if password != confirm_password:
            return "Passwords do not match."

        # Hash password
        hashed_password = generate_password_hash(password)

        conn = get_db()

        try:

            conn.execute("""
                INSERT INTO users
                (first_name, last_name, username, password)
                VALUES (?, ?, ?, ?)
            """, (
                first_name,
                last_name,
                username,
                hashed_password
            ))

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return "Username already exists."

        conn.close()

        # Go to login page
        return redirect("/")

    return render_template("SignUp.html")


# ==========================
# DASHBOARD
# ==========================

@app.route("/dashboard")
def dashboard():

    # Prevent access without login
    if "user_id" not in session:
        return redirect("/")

    return render_template(
        "Dashboard.html",
        first_name=session["first_name"],
        last_name=session["last_name"],
        username=session["username"]
    )


# ==========================
# LOGOUT
# ==========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ==========================
# RUN APPLICATION
# ==========================

if __name__ == "__main__":

    create_database()

    app.run(debug=True)
