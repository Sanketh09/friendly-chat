import eventlet
eventlet.monkey_patch()

from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
import sqlite3
import bcrypt
import os
import uuid
import base64
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecret'
app.config['SESSION_PERMANENT'] = False
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    manage_session=False,
    max_http_buffer_size=100 * 1024 * 1024  # 100MB
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ---------------- DATABASE ---------------- #

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Create table with banned column (if fresh DB)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            approved INTEGER DEFAULT 0,
            banned INTEGER DEFAULT 0
        )
    """)
    c.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender TEXT,
    role TEXT,
    text TEXT,
    time TEXT
)
""")
    

    # If banned column doesn't exist (old DB), add it safely
    try:
        c.execute("ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0")
    except:
        pass

    # Create default admin if not exists
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        c.execute("""
            INSERT INTO users (username,password,role,approved,banned)
            VALUES (?,?,?,?,?)
        """, ("admin", hashed, "admin", 1, 0))

    conn.commit()
    conn.close()

init_db()


def broadcast_pending_updates():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE approved=0")
    pending = c.fetchall()
    conn.close()

    socketio.emit("pending_update", pending)


# ---------------- USER CLASS ---------------- #

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()

    if user:
        return User(user[0], user[1], user[3])
    return None




# ---------------- ROUTES ---------------- #

@app.route("/", methods=["GET", "POST"])
def home():

    # ================= IF USER IS LOGGED IN =================
    if current_user.is_authenticated:

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT approved, banned, role FROM users WHERE id=?", (current_user.id,))
        user = c.fetchone()
        conn.close()

        if not user:
            logout_user()
            return redirect(url_for("home"))

        approved, banned, role = user

        # 🚫 If banned
        if banned == 1:
            logout_user()
            return render_template("request.html", error="You are banned by admin.")

        # ⏳ If pending
        if approved == 0:
            return render_template("request.html", error="Account pending admin approval.")

        # 👑 Admin
        if role == "admin":
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("SELECT id, username FROM users WHERE approved=0")
            pending_users = c.fetchall()
            conn.close()

            files = os.listdir(UPLOAD_FOLDER)

            return render_template(
                "admin_panel.html",
                username=current_user.username,
                pending=pending_users,
                files=files
            )

        # 👤 Normal approved user
        return render_template(
            "chat.html",
            username=current_user.username,
            role=current_user.role
        )

    # ================= NOT LOGGED IN =================
    error = None
    success = None

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()

        if user:
            if user[5] == 1:
                error = "You are banned by admin."
            elif not bcrypt.checkpw(password.encode(), user[2].encode()):
                error = "Wrong password"
            elif user[4] == 0:
                error = "Account pending admin approval"
            else:
                login_user(User(user[0], user[1], user[3]))
                conn.close()
                return redirect(url_for("home"))
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            c.execute(
                "INSERT INTO users (username,password,role,approved,banned) VALUES (?,?,?,?,?)",
                (username, hashed.decode(), "user", 0, 0)
            )
            conn.commit()
            success = "Request sent to admin. Wait for approval."

        conn.close()

    return render_template("request.html", error=error, success=success)





@app.route("/approve/<int:user_id>")
@login_required
def approve_user(user_id):
    if current_user.role != "admin":
        return "Access Denied"

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    broadcast_pending_updates()   # 👈 ADD THIS LINE

    return redirect(url_for("home"))

@app.route("/deny/<int:user_id>")
@login_required
def deny_user(user_id):
    if current_user.role != "admin":
        return "Access Denied"

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    broadcast_pending_updates()   # 👈 ADD HERE

    return redirect(url_for("home"))


@app.route("/ban/<int:user_id>")
@login_required
def ban_user(user_id):
    if current_user.role != "admin":
        return "Access Denied"

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET banned=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    broadcast_pending_updates()
    return redirect(url_for("home"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

from flask import send_from_directory



@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)



# ---------------- SOCKET EVENTS ---------------- #

online_users = {}


@socketio.on("typing")
def handle_typing(data):
    emit("show_typing", data, broadcast=True)

@socketio.on("pin_message")
def handle_pin(data):
    emit("show_pinned", data, broadcast=True)


@socketio.on("join")
def join():
    if not current_user.is_authenticated:
        return

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT approved, banned FROM users WHERE id=?", (current_user.id,))
    result = c.fetchone()
    conn.close()

    if not result or result[0] == 0 or result[1] == 1:
        return  # Do nothing if not approved

    online_users[request.sid] = current_user.username

    unique_users = list(set(online_users.values()))
    emit("update_users", unique_users, broadcast=True)


@socketio.on("disconnect")
def disconnect():

    if not current_user.is_authenticated:
        return

    # Remove from online users
    if request.sid in online_users:
        del online_users[request.sid]

    # 🔥 Reset approval for normal users only
    if current_user.role != "admin":

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET approved=0 WHERE id=?", (current_user.id,))
        conn.commit()
        conn.close()

    emit("update_users", list(online_users.values()), broadcast=True)

@socketio.on("send_message")
def send_message(data):
    if not current_user or not current_user.is_authenticated:
        return

    # Check banned
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT banned FROM users WHERE id=?", (current_user.id,))
    banned = c.fetchone()[0]
    if banned == 1:
        conn.close()
        logout_user()
        return
    conn.close()

    data["id"] = str(uuid.uuid4())
    data["sender"] = current_user.username
    data["role"] = current_user.role

    # Save to DB
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO messages (id,sender,role,text,time) VALUES (?,?,?,?,?)",
        (data["id"], data["sender"], data["role"], data["text"], data["time"])
    )
    conn.commit()
    conn.close()

    emit("receive_message", data, broadcast=True)

@socketio.on("delete_message")
def delete_message(data):
    if current_user.role != "admin":
        return

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE id=?", (data["id"],))
    conn.commit()
    conn.close()

    emit("remove_message", {"id": data["id"]}, broadcast=True)

@socketio.on("send_file")
def send_file(data):

    print("FILE EVENT TRIGGERED")

    if not current_user.is_authenticated:
        print("User not authenticated")
        return

    try:
        file_name = secure_filename(data["fileName"])

        header, encoded = data["fileData"].split(",", 1)
        file_bytes = base64.b64decode(encoded)

        file_path = os.path.join(UPLOAD_FOLDER, file_name)

        with open(file_path, "wb") as f:
            f.write(file_bytes)

        data["sender"] = current_user.username
        data["role"] = current_user.role

        emit("receive_file", data, broadcast=True)

        print("File sent successfully")

    except Exception as e:
        print("FILE ERROR:", e)



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host="0.0.0.0", port=port)
