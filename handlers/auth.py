import sqlite3
import hashlib
import datetime
import os

DB_FILE = "utuvox_db.db"
ADMIN_KEY_FILE = "./admin_key.txt"

# Initialize admin key file with a default value if it doesn't exist
if not os.path.exists(ADMIN_KEY_FILE):
    with open(ADMIN_KEY_FILE, "w") as f:
        f.write("default_admin_key_123")  # Default admin key


def get_admin_key():
    """Read the current admin key from the file."""
    with open(ADMIN_KEY_FILE, "r") as f:
        return f.read().strip()


def set_admin_key(new_key):
    """Update the admin key in the file."""
    with open(ADMIN_KEY_FILE, "w") as f:
        f.write(new_key)
    return True


def init_db():
    """Initialize the SQLite database with a users table including is_banned."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0  -- 0 = not banned, 1 = banned
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def register_user(username, password, admin_key=None):
    """Register a new user, optionally as admin if admin_key matches."""
    if not username or not password:
        return False, "Username and password cannot be empty."

    is_admin = 0
    if admin_key:
        if admin_key == get_admin_key():
            is_admin = 1
        else:
            return False, "Invalid admin key."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password_hash, is_admin, is_banned) VALUES (?, ?, ?, 0)",
                       (username, hash_password(password), is_admin))
        conn.commit()
        role = "admin" if is_admin else "user"
        return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Registration successful as {role}."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()


def login_user(username, password):
    """Verify user login credentials and check ban status."""
    if not username or not password:
        return False, "Username and password cannot be empty.", False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, is_admin, is_banned FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        if result[2]:  # is_banned
            return False, "You are banned from this server.", False
        if result[0] == hash_password(password):
            is_admin = bool(result[1])
            return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Login successful.", is_admin
    return False, "Invalid username or password.", False


def change_password(username, old_password, new_password):
    if not new_password:
        return False, "New password cannot be empty."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result and result[0] == hash_password(old_password):
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                       (hash_password(new_password), username))
        conn.commit()
        conn.close()
        return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Password changed successfully."
    else:
        conn.close()
        return False, "Incorrect old password."


def is_admin_user(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result and bool(result[0])


def add_user(admin_username, new_username, new_password, is_admin=0):
    if not is_admin_user(admin_username):
        return False, "Only admins can add users."
    return register_user(new_username, new_password, None if is_admin == 0 else get_admin_key())


def edit_user(admin_username, target_username, new_password=None, new_is_admin=None):
    if not is_admin_user(admin_username):
        return False, "Only admins can edit users."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (target_username,))
    if not cursor.fetchone():
        conn.close()
        return False, f"User '{target_username}' does not exist."

    updates = []
    params = []
    if new_password:
        updates.append("password_hash = ?")
        params.append(hash_password(new_password))
    if new_is_admin is not None:
        updates.append("is_admin = ?")
        params.append(1 if new_is_admin else 0)

    if updates:
        params.append(target_username)
        query = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] User '{target_username}' updated."
    conn.close()
    return False, "No changes specified."


def view_users(admin_username):
    if not is_admin_user(admin_username):
        return False, "Only admins can view users."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_admin, is_banned FROM users")
    users = cursor.fetchall()
    conn.close()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_list = "\n".join(
        [f"Username: {u[0]}, Admin: {'Yes' if u[1] else 'No'}, Banned: {'Yes' if u[2] else 'No'}" for u in users])
    return True, f"[{current_time}] Users:\n{user_list}"


def ban_user(admin_username, target_username):
    """Ban a user by setting is_banned to 1."""
    if not is_admin_user(admin_username):
        return False, "Only admins can ban users."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (target_username,))
    if cursor.fetchone():
        cursor.execute("UPDATE users SET is_banned = 1 WHERE username = ?", (target_username,))
        conn.commit()
        conn.close()
        return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] User '{target_username}' banned."
    conn.close()
    return False, f"User '{target_username}' does not exist."


def unban_user(admin_username, target_username):
    """Unban a user by setting is_banned to 0."""
    if not is_admin_user(admin_username):
        return False, "Only admins can unban users."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_banned FROM users WHERE username = ?", (target_username,))
    result = cursor.fetchone()

    if result:
        if not result[0]:  # Not banned
            conn.close()
            return False, f"User '{target_username}' is not banned."
        cursor.execute("UPDATE users SET is_banned = 0 WHERE username = ?", (target_username,))
        conn.commit()
        conn.close()
        return True, f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] User '{target_username}' unbanned."
    conn.close()
    return False, f"User '{target_username}' does not exist."