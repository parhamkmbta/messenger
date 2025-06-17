from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import sqlite3
import string
import random
import logging
import jwt
from datetime import datetime, timezone, timedelta
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'your-secret-key'  # در تولید تغییر کند
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # محدودیت 5MB
socketio = SocketIO(app, cors_allowed_origins="*")
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")

# ایجاد دایرکتوری آپلود
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# تولید کد دعوت 5 کاراکتری
def generate_invite_code():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(5))

# دیتابیس
def init_db():
    try:
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, invite_code TEXT UNIQUE)''')
        c.execute('''CREATE TABLE IF NOT EXISTS connections (user1_code TEXT, user2_code TEXT, UNIQUE(user1_code, user2_code))''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_code TEXT,
            recipient_code TEXT,
            message TEXT,
            timestamp TEXT,
            is_image INTEGER DEFAULT 0
        )''')
        c.execute("PRAGMA table_info(messages)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_image' not in columns:
            c.execute("ALTER TABLE messages ADD COLUMN is_image INTEGER DEFAULT 0")
            logging.info("Added is_image column to messages table")
        conn.commit()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
    finally:
        conn.close()

init_db()

# توکن JWT
def create_token(username):
    try:
        payload = {"sub": username, "exp": datetime.now(timezone.utc) + timedelta(hours=24)}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        logging.info(f"Token created for {username}")
        return token
    except Exception as e:
        logging.error(f"Token creation failed: {str(e)}")
        raise

def verify_token(token):
    if not token:
        logging.error("No token provided")
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logging.info(f"Token verified for {payload['sub']}")
        return payload['sub']
    except jwt.InvalidTokenError as e:
        logging.error(f"Token verification failed: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error in token verification: {str(e)}")
        return None

# مسیرها
@app.route("/")
def index():
    logging.info("Serving index.html")
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        username, password = data.get("username"), data.get("password")
        if not username or not password:
            logging.warning("Missing username or password")
            return jsonify({"error": "نام کاربری و رمزعبور الزامی است"}), 400
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        invite_code = generate_invite_code()
        while True:
            try:
                c.execute("INSERT INTO users (username, password, invite_code) VALUES (?, ?, ?)", 
                          (username, password, invite_code))
                break
            except sqlite3.IntegrityError as e:
                if 'UNIQUE constraint failed: users.invite_code' in str(e):
                    invite_code = generate_invite_code()
                else:
                    raise
        conn.commit()
        token = create_token(username)
        logging.info(f"User {username} registered with invite code {invite_code}")
        return jsonify({"invite_code": invite_code, "token": token})
    except sqlite3.IntegrityError:
        logging.warning(f"Registration failed: Username {username} already exists")
        return jsonify({"error": "نام کاربری قبلاً ثبت شده است"}), 400
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({"error": "خطای سرور"}), 500
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        username, password, invite_code = data.get("username"), data.get("password"), data.get("invite_code")
        if not username or not password or not invite_code:
            logging.warning("Missing login credentials")
            return jsonify({"error": "نام کاربری، رمزعبور و کد دعوت الزامی است"}), 400
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT username, password, invite_code FROM users WHERE username = ? AND password = ? AND invite_code = ?", 
                  (username, password, invite_code))
        user = c.fetchone()
        conn.close()
        if user:
            token = create_token(username)
            logging.info(f"User {username} logged in successfully")
            return jsonify({"token": token, "invite_code": invite_code})
        else:
            logging.warning(f"Login failed for {username}")
            return jsonify({"error": "اطلاعات ورود نامعتبر است"}), 401
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/connect", methods=["POST"])
def connect():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        invite_code = request.json.get("invite_code")
        username = verify_token(token)
        if not username:
            logging.warning("Invalid token in connect request")
            return jsonify({"error": "توکن نامعتبر است"}), 401
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT invite_code FROM users WHERE username = ?", (username,))
        user_code = c.fetchone()
        if not user_code:
            conn.close()
            logging.warning(f"User {username} not found")
            return jsonify({"error": "کاربر یافت نشد"}), 404
        user_code = user_code[0]
        c.execute("SELECT invite_code FROM users WHERE invite_code = ?", (invite_code,))
        if not c.fetchone():
            conn.close()
            logging.warning(f"Invalid invite code: {invite_code}")
            return jsonify({"error": "کد دعوت نامعتبر است"}), 404
        try:
            c.execute("INSERT INTO connections (user1_code, user2_code) VALUES (?, ?)", (user_code, invite_code))
            conn.commit()
            logging.info(f"Connection established: {user_code} -> {invite_code}")
        except sqlite3.IntegrityError:
            logging.info(f"Connection already exists: {user_code} -> {invite_code}")
        conn.close()
        return jsonify({"message": "اتصال برقرار شد"})
    except Exception as e:
        logging.error(f"Connect error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/admin/users", methods=["GET"])
def admin_users():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        username = verify_token(token)
        if username != "admin":
            logging.warning(f"Unauthorized access to admin panel by {username}")
            return jsonify({"error": "دسترسی غیرمجاز"}), 403
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT username, invite_code FROM users")
        users = [{"username": row[0], "invite_code": row[1]} for row in c.fetchall()]
        conn.close()
        logging.info("Admin fetched user list")
        return jsonify(users)
    except Exception as e:
        logging.error(f"Admin users error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/admin/users/<username>", methods=["DELETE"])
def delete_user(username):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        admin_username = verify_token(token)
        if admin_username != "admin":
            logging.warning(f"Unauthorized delete attempt by {admin_username}")
            return jsonify({"error": "دسترسی غیرمجاز"}), 403
        if username == "admin":
            logging.warning("Attempt to delete admin user")
            return jsonify({"error": "نمی‌توان کاربر ادمین را حذف کرد"}), 400
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            conn.close()
            logging.warning(f"User {username} not found for deletion")
            return jsonify({"error": "کاربر یافت نشد"}), 404
        c.execute("DELETE FROM users WHERE username = ?", (username,))
        c.execute("DELETE FROM connections WHERE user1_code IN (SELECT invite_code FROM users WHERE username = ?) OR user2_code IN (SELECT invite_code FROM users WHERE username = ?)", (username, username))
        c.execute("DELETE FROM messages WHERE sender_code IN (SELECT invite_code FROM users WHERE username = ?) OR recipient_code IN (SELECT invite_code FROM users WHERE username = ?)", (username, username))
        conn.commit()
        conn.close()
        logging.info(f"User {username} deleted by admin")
        return jsonify({"message": "کاربر با موفقیت حذف شد"})
    except Exception as e:
        logging.error(f"Delete user error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/admin/users/<username>/invite_code", methods=["PUT"])
def update_invite_code(username):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        admin_username = verify_token(token)
        if admin_username != "admin":
            logging.warning(f"Unauthorized invite code update attempt by {admin_username}")
            return jsonify({"error": "دسترسی غیرمجاز"}), 403
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            conn.close()
            logging.warning(f"User {username} not found for invite code update")
            return jsonify({"error": "کاربر یافت نشد"}), 404
        new_invite_code = generate_invite_code()
        while True:
            try:
                c.execute("UPDATE users SET invite_code = ? WHERE username = ?", (new_invite_code, username))
                break
            except sqlite3.IntegrityError as e:
                if 'UNIQUE constraint failed: users.invite_code' in str(e):
                    new_invite_code = generate_invite_code()
                else:
                    raise
        conn.commit()
        conn.close()
        logging.info(f"Invite code updated for {username} to {new_invite_code}")
        return jsonify({"message": "کد دعوت با موفقیت تغییر کرد", "new_invite_code": new_invite_code})
    except Exception as e:
        logging.error(f"Update invite code error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/contacts")
def get_contacts():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        username = verify_token(token)
        if not username:
            logging.warning("Invalid token in contacts request")
            return jsonify({"error": "توکن نامعتبر است"}), 401
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT invite_code FROM users WHERE username = ?", (username,))
        user_code = c.fetchone()
        if not user_code:
            conn.close()
            logging.warning(f"User {username} not found")
            return jsonify({"error": "کاربر یافت نشد"}), 404
        user_code = user_code[0]
        c.execute("""
            SELECT u.username, u.invite_code 
            FROM users u 
            JOIN connections c ON u.invite_code = c.user2_code 
            WHERE c.user1_code = ?
            UNION
            SELECT u.username, u.invite_code 
            FROM users u 
            JOIN connections c ON u.invite_code = c.user1_code 
            WHERE c.user2_code = ?
        """, (user_code, user_code))
        contacts = [{"username": row[0], "invite_code": row[1]} for row in c.fetchall()]
        conn.close()
        logging.info(f"Contacts fetched for {username}")
        return jsonify(contacts)
    except Exception as e:
        logging.error(f"Contacts error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

@app.route("/chat_history/<recipient_code>")
def chat_history(recipient_code):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        username = verify_token(token)
        if not username:
            logging.warning("Invalid token in chat history request")
            return jsonify({"error": "توکن نامعتبر است"}), 401
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT invite_code FROM users WHERE username = ?", (username,))
        user_code = c.fetchone()
        if not user_code:
            conn.close()
            logging.warning(f"User {username} not found")
            return jsonify({"error": "کاربر یافت نشد"}), 404
        user_code = user_code[0]
        logging.debug(f"Fetching chat history for {username} with {recipient_code}")
        c.execute("""
            SELECT sender_code, recipient_code, message, timestamp, is_image
            FROM messages
            WHERE (sender_code = ? AND recipient_code = ?) OR (sender_code = ? AND recipient_code = ?)
            ORDER BY timestamp ASC
        """, (user_code, recipient_code, recipient_code, user_code))
        messages = [
            {
                "sender_code": row[0],
                "recipient_code": row[1],
                "message": row[2],
                "timestamp": row[3],
                "is_image": row[4]
            } for row in c.fetchall()
        ]
        conn.close()
        logging.info(f"Chat history fetched for {username} with {recipient_code}")
        return jsonify(messages)
    except Exception as e:
        logging.error(f"Chat history error: {str(e)}")
        return jsonify({"error": f"خطای سرور: {str(e)}"}), 500

@app.route("/upload_image", methods=["POST"])
def upload_image():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        username = verify_token(token)
        if not username:
            logging.warning("Invalid token in upload image request")
            return jsonify({"error": "توکن نامعتبر است"}), 401
        if 'image' not in request.files:
            logging.warning("No image file in request")
            return jsonify({"error": "فایلی انتخاب نشده است"}), 400
        file = request.files['image']
        if file.filename == '':
            logging.warning("Empty filename in upload request")
            return jsonify({"error": "فایلی انتخاب نشده است"}), 400
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{random.randint(1000, 9999)}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"
            logging.info(f"Image uploaded: {image_url}")
            return jsonify({"image_url": image_url})
        else:
            logging.warning("Invalid file type")
            return jsonify({"error": "فرمت فایل مجاز نیست"}), 400
    except Exception as e:
        logging.error(f"Upload image error: {e}")
        return jsonify({"error": "خطای سرور"}), 500

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# WebSocket
@socketio.on("message")
def handle_message(data):
    try:
        token = data.get("token")
        recipient_code = data.get("recipient_code")
        message = data.get("message")
        is_image = data.get("is_image", 0)
        username = verify_token(token)
        if not username:
            logging.warning("Invalid token in WebSocket message")
            emit("error", {"error": "توکن نامعتبر است"})
            return
        conn = sqlite3.connect("messenger.db")
        c = conn.cursor()
        c.execute("SELECT invite_code FROM users WHERE username = ?", (username,))
        user_code = c.fetchone()
        if not user_code:
            conn.close()
            logging.warning(f"User {username} not found")
            emit("error", {"error": "کاربر یافت نشد"})
            return
        user_code = user_code[0]
        logging.debug(f"Checking connection: {user_code} -> {recipient_code}")
        c.execute("SELECT * FROM connections WHERE (user1_code = ? AND user2_code = ?) OR (user1_code = ? AND user2_code = ?)", 
                  (user_code, recipient_code, recipient_code, user_code))
        if not c.fetchone():
            conn.close()
            logging.warning(f"Not connected: {user_code} -> {recipient_code}")
            emit("error", {"error": "اتصال برقرار نشده است"})
            return
        timestamp = datetime.now(timezone.utc).isoformat()
        c.execute("INSERT INTO messages (sender_code, recipient_code, message, timestamp, is_image) VALUES (?, ?, ?, ?, ?)",
                  (user_code, recipient_code, message, timestamp, is_image))
        conn.commit()
        conn.close()
        logging.info(f"Message sent from {user_code} to {recipient_code}")
        emit("message", {"message": message, "sender": user_code, "recipient": recipient_code, "timestamp": timestamp, "is_image": is_image}, broadcast=True)
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")
        emit("error", {"error": f"خطای سرور: {str(e)}"})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8000)