import datetime
import socket
import threading
import signal
import sys

from handlers.auth import init_db, register_user, login_user, get_admin_key
from handlers.command_handler import process_command
from handlers.file_manager import init_file_db
from handlers.history_manager import init_history_db
from handlers.room_manager import init_room_db

rooms = {}
clients = {}
usernames = {}
rooms_lock = threading.Lock()
usernames_lock = threading.Lock()

# Global flag for shutdown
shutdown_flag = False

def handle_client(client_socket, client_address):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}] New connection from {client_address}")

    client_socket.send(
        f"[{current_time}] Welcome! Please use /register <username> <password> [admin_key] or /login <username> <password>".encode("utf-8")
    )

    authenticated = False
    username = None
    is_admin = False

    try:
        while not authenticated and not shutdown_flag:
            message = client_socket.recv(1024).decode("utf-8", errors='ignore')
            print(f"[{current_time}] [RECV from {client_address}] {message}")
            if message.startswith("/register "):
                parts = message.split(" ", 4)
                if len(parts) < 3 or len(parts) > 4:
                    client_socket.send(f"[{current_time}] Usage: /register <username> <password> [admin_key]".encode("utf-8"))
                    continue
                username, password = parts[1], parts[2]
                admin_key = parts[3] if len(parts) == 4 else None
                success, response = register_user(username, password, admin_key)
                client_socket.send(response.encode("utf-8"))
                if success:
                    authenticated = True
                    is_admin = response.endswith("as admin.")
            elif message.startswith("/login "):
                parts = message.split(" ", 3)
                if len(parts) != 3:
                    client_socket.send(f"[{current_time}] Usage: /login <username> <password>".encode("utf-8"))
                    continue
                success, response, is_admin = login_user(parts[1], parts[2])
                client_socket.send(response.encode("utf-8"))
                if success:
                    username = parts[1]
                    authenticated = True
            else:
                client_socket.send(f"[{current_time}] Please register or login first.".encode("utf-8"))

        with usernames_lock:
            usernames[client_socket] = username
            clients[client_socket] = (client_address, is_admin)
        print(f"[{current_time}] Authenticated: {username} from {client_address} (Admin: {is_admin})")

        while not shutdown_flag:
            message = client_socket.recv(1024).decode("utf-8", errors='ignore')
            print(f"[{current_time}] [RECV from {username}] {message}")
            if not process_command(client_socket, message, rooms, usernames, clients):
                break

    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[{current_time}] [ERROR] Connection error: {e}")
        pass
    finally:
        client_socket.close()
        with usernames_lock:
            if client_socket in usernames:
                del usernames[client_socket]
            if client_socket in clients:
                del clients[client_socket]
        print(f"[{current_time}] [INFO] {username or 'Unauthenticated user'} disconnected from server.")

def signal_handler(sig, frame):
    global shutdown_flag
    print("\nShutting down server gracefully...")
    shutdown_flag = True

def start_server(host, port):
    global shutdown_flag
    init_db()
    init_room_db()
    init_history_db()
    init_file_db()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signal

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow immediate restart
    server_socket.bind((host, port))
    server_socket.listen(128)  # Increased backlog to 128
    print(f"Server started on {host}:{port}")
    print(f"Admin key: {get_admin_key()} (use this to register as admin)")

    try:
        while not shutdown_flag:
            server_socket.settimeout(0.5)  # 0.5-second timeout for faster polling
            try:
                client_socket, client_address = server_socket.accept()
                threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
            except socket.timeout:
                continue
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        print("Closing server socket...")
        server_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    start_server('127.0.0.1', 9090)