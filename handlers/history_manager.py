import sqlite3
import datetime

DB_FILE = "utuvox_db.db"

def init_history_db():
    """Initialize the SQLite database with history and admin_logs tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Room history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS room_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            FOREIGN KEY (room_name) REFERENCES rooms(room_name)
        )
    """)
    # Admin logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_event(room_name, event):
    """Log an event (message, join, leave, etc.) to the room's history."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO room_history (room_name, timestamp, event) VALUES (?, ?, ?)",
                   (room_name, timestamp, event))
    conn.commit()
    conn.close()
    return f"[{timestamp}] {event}"

def get_room_history(room_name):
    """Retrieve the full chat history for a room."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, event FROM room_history WHERE room_name = ? ORDER BY id ASC",
                   (room_name,))
    history = [f"[{timestamp}] {event}" for timestamp, event in cursor.fetchall()]
    conn.close()
    return history

def delete_room_history(room_name):
    """Delete all history entries for a room."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM room_history WHERE room_name = ?", (room_name,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if affected > 0:
        return True, f"[{current_time}] History for room '{room_name}' deleted."
    return False, f"[{current_time}] No history found for room '{room_name}'."

def log_admin_action(admin_username, action):
    """Log an admin action globally."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO admin_logs (admin_username, timestamp, action) VALUES (?, ?, ?)",
                   (admin_username, timestamp, action))
    conn.commit()
    conn.close()
    return f"[{timestamp}] {action}"

def get_admin_logs():
    """Retrieve all admin actions."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT admin_username, timestamp, action FROM admin_logs ORDER BY id ASC")
    logs = [f"[{timestamp}] {admin_username}: {action}" for admin_username, timestamp, action in cursor.fetchall()]
    conn.close()
    return logs