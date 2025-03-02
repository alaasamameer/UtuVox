import sqlite3
import os
import datetime
import hashlib
from .history_manager import log_event  # New import

DB_FILE = "utuvox_db.db"
UPLOADS_DIR = "./uploads"

# Ensure uploads directory exists
if not os.path.exists(UPLOADS_DIR):
    os.makedirs(UPLOADS_DIR)


def init_file_db():
    """Initialize the SQLite database with a files table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            unique_name TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            room_name TEXT NOT NULL,
            upload_timestamp TEXT NOT NULL,
            FOREIGN KEY (room_name) REFERENCES rooms(room_name)
        )
    """)
    conn.commit()
    conn.close()


def generate_unique_name(room_name, original_filename):
    """Generate a unique, informative name for the file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = os.path.splitext(original_filename)[0]
    extension = os.path.splitext(original_filename)[1]
    unique_name = f"{room_name}_{timestamp}_{filename_base}{extension}"
    # Ensure uniqueness by appending a hash if needed
    hash_suffix = hashlib.md5(unique_name.encode()).hexdigest()[:8]
    final_name = f"{unique_name}_{hash_suffix}"
    return final_name


def save_file(room_name, filepath, username):
    """Save a file to the uploads directory with a unique name and log it in the database and history."""
    if not os.path.exists(filepath):
        return False, "File not found."

    original_filename = os.path.basename(filepath)
    unique_name = generate_unique_name(room_name, original_filename)
    save_path = os.path.join(UPLOADS_DIR, unique_name)

    try:
        with open(filepath, 'rb') as source, open(save_path, 'wb') as dest:
            dest.write(source.read())

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (unique_name, original_name, room_name, upload_timestamp) VALUES (?, ?, ?, ?)",
            (unique_name, original_filename, room_name, timestamp))
        conn.commit()
        conn.close()

        # Log the upload event to room history
        upload_event = f"User {username} uploaded file '{unique_name}' (Original: {original_filename})"
        log_event(room_name, upload_event)
        return True, f"[{timestamp}] File '{unique_name}' uploaded to room '{room_name}'."
    except Exception as e:
        return False, f"Error uploading file: {str(e)}"


def get_file_info(unique_name):
    """Retrieve file information from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT original_name, room_name, upload_timestamp FROM files WHERE unique_name = ?", (unique_name,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result
    return None


def get_room_files(room_name):
    """Retrieve all files for a room."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT unique_name, original_name, upload_timestamp FROM files WHERE room_name = ? ORDER BY upload_timestamp DESC",
        (room_name,))
    files = [(row[0], row[1], row[2]) for row in cursor.fetchall()]
    conn.close()
    return files


def serve_file(unique_name, client_socket, username):
    """Send a file to the client and log the download in the room history."""
    file_path = os.path.join(UPLOADS_DIR, unique_name)
    if not os.path.exists(file_path):
        client_socket.send(
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] File '{unique_name}' not found.".encode(
                "utf-8"))
        return

    try:
        file_info = get_file_info(unique_name)
        if file_info:
            room_name = file_info[1]
            file_size = os.path.getsize(file_path)
            client_socket.send(f"/file {unique_name} {file_size}".encode("utf-8"))
            with open(file_path, 'rb') as file:
                while (chunk := file.read(4096)):
                    client_socket.send(chunk)

            # Log the download event to room history
            download_event = f"User {username} downloaded file '{unique_name}' (Original: {file_info[0]})"
            log_event(room_name, download_event)
    except Exception as e:
        client_socket.send(
            f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error sending file: {str(e)}".encode("utf-8"))