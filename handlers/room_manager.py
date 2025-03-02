import sqlite3
import datetime

DB_FILE = "utuvox_db.db"


def init_room_db():
    """Initialize the SQLite database with a rooms table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            room_name TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()


def create_room(room_name):
    """Create a new room in the database if it doesn't exist."""
    if not room_name:
        return False, "Room name cannot be empty."

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO rooms (room_name) VALUES (?)", (room_name,))
        conn.commit()
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return True, f"[{current_time}] Room '{room_name}' created successfully."
    except sqlite3.IntegrityError:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return False, f"[{current_time}] Room '{room_name}' already exists."
    finally:
        conn.close()


def room_exists(room_name):
    """Check if a room exists in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT room_name FROM rooms WHERE room_name = ?", (room_name,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def get_all_rooms():
    """Retrieve all room names from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT room_name FROM rooms")
    rooms = [row[0] for row in cursor.fetchall()]
    conn.close()
    return rooms


def delete_room(room_name):
    """Delete a room from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rooms WHERE room_name = ?", (room_name,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if affected > 0:
        return True, f"[{current_time}] Room '{room_name}' deleted."
    return False, f"[{current_time}] Room '{room_name}' does not exist."