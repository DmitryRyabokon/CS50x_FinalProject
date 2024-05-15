from cs50 import SQL

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from flask_socketio import SocketIO, emit, send
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
import datetime

# Configure application
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "secret!"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///messenger.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    history = db.execute("SELECT * FROM messages")
    try:
        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"]
        )[0]["username"]
        return render_template("index.html", name=username, history=history)
    except IndexError:
        return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return "No user name"

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "Incorrect password"

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return "invalid username and/or password"

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return "must provide username"

        # If username is already taken
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) > 0:
            return "username is already taken"

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "must provide password"

        # Ensure passwords match
        elif request.form.get("confirmation") != request.form.get("password"):
            return "password do not match"

        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))

        # Add user to database
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", username, password
        )
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        user_id = rows[0]["id"]
        session["user_id"] = user_id

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/settings", methods=["GET"])
def settings():
    return render_template("settings.html")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        if not request.form.get("old_password"):
            return "must provide old password"

        old_password = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"]
        )

        if not check_password_hash(
            old_password[0]["hash"], request.form.get("old_password")
        ):
            return "old password doesn't match"

        elif not request.form.get("new_password"):
            return "must provide new password"

        elif request.form.get("new_password") != request.form.get("confirmation"):
            return "new password doesn't match"

        new_password = generate_password_hash(request.form.get("new_password"))
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", new_password, session["user_id"]
        )

        return redirect("/")

    else:
        return render_template("change_password.html")


@socketio.on("message")
def handle_message(data):
    username = db.execute(
        "SELECT username FROM users WHERE id = ?", session["user_id"]
    )[0]["username"]
    if data["message"] != "has connected!":
        db.execute(
            "INSERT INTO messages (sender_username, message, timestamp) VALUES (?, ?, ?)",
            username,
            data["message"],
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        )
    send(data, broadcast=True)


def history():
    history = ["message1", "message2", "message3"]
    return render_template("index.html", history=history)

if __name__ == "__main__":
    socketio.run(app)
