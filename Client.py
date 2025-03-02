import socket
import threading
import os
import datetime
import time
import signal
import sys


class ClientState:
    """Stores shared state like credentials and current room."""
    def __init__(self):
        self.username = None
        self.password = None
        self.current_room = None  # Tracks the current room, None if outside


# Global shutdown flag
shutdown_flag = False


def connect_to_server(host, port):
    """Create and connect a socket to the server, returning the socket."""
    global shutdown_flag
    while not shutdown_flag:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Connected to the server.")
            return client_socket
        except (ConnectionRefusedError, OSError) as e:
            print(
                f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Connection failed: {e}. Retrying in 2 seconds...")
            time.sleep(2)
    return None  # Return None if shutdown is triggered


def receive_messages(client_socket, host, port, state):
    """Receive messages from the server, update room status, and handle reconnection."""
    global shutdown_flag
    while not shutdown_flag:
        try:
            message = client_socket.recv(4096).decode("utf-8", errors='ignore')
            if not message:
                raise ConnectionResetError("Server closed the connection")
            print(f"[RECV] {message}")

            # Update room status based on server messages
            if "You joined room '" in message:
                # Extract room name between single quotes
                start = message.find("You joined room '") + len("You joined room '")
                end = message.find("'", start)
                room_name = message[start:end] if start != -1 and end != -1 else None
                if room_name:
                    print(f"Debug: Updating current_room to {room_name}")  # Debug print
                    state.current_room = room_name
            elif "Room '" in message and "' created successfully" in message:
                # Optionally auto-join after creation
                start = message.find("Room '") + len("Room '")
                end = message.find("'", start)
                room_name = message[start:end] if start != -1 and end != -1 else None
                if room_name:
                    print(f"Debug: Auto-joining room {room_name} after creation")  # Debug print
                    state.current_room = room_name
            elif "You left room" in message or "has been deleted by an admin" in message:
                print(f"Debug: Setting current_room to None (left or deleted)")  # Debug print
                state.current_room = None  # User is no longer in a room
            elif "User " in message and "joined room '" in message:
                # Handle notifications of other users joining (optional, for logging)
                pass  # No need to update state.current_room for others joining
            elif message.startswith("/file "):
                parts = message.split(" ", 3)
                if len(parts) >= 3:
                    filename, file_size = parts[1], int(parts[2])
                    receive_file(client_socket, filename, file_size)

        except (ConnectionResetError, OSError) as e:
            print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Connection lost: {e}")
            client_socket.close()
            if not shutdown_flag:
                print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Attempting to reconnect...")
                client_socket = connect_to_server(host, port)
                if client_socket and state.username and state.password:
                    client_socket.send(f"/login {state.username} {state.password}".encode("utf-8"))
                    print(
                        f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [SENT] /login {state.username} {state.password}")
            else:
                break


def send_file(client_socket, room_name, filepath):
    """Send a file to the server."""
    if not os.path.exists(filepath):
        print(f"[ERROR] File '{filepath}' not found.")
        return
    file_size = os.path.getsize(filepath)
    client_socket.send(f"/upload {room_name} {filepath} {file_size}".encode("utf-8"))
    with open(filepath, 'rb') as file:
        while (chunk := file.read(4096)):
            client_socket.send(chunk)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}] [INFO] File sent to server for room '{room_name}'.")


def receive_file(client_socket, filename, file_size):
    """Receive a file from the server."""
    file_data = b''
    while len(file_data) < file_size:
        chunk = client_socket.recv(min(4096, file_size - len(file_data)))
        if not chunk:
            break
        file_data += chunk
    save_path = os.path.join("downloads", filename)
    os.makedirs("downloads", exist_ok=True)
    with open(save_path, 'wb') as file:
        file.write(file_data)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}] [INFO] File '{filename}' downloaded successfully to 'downloads/'.")


def signal_handler(sig, frame):
    """Handle system signals like SIGTERM or SIGINT."""
    global shutdown_flag
    print(
        f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Received signal {sig}. Shutting down client...")
    shutdown_flag = True


def main():
    global shutdown_flag
    host = '127.0.0.1'  # Update to server IP if on different node
    port = 9090

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal (e.g., kill command on Unix)

    # Shared state for credentials and room
    state = ClientState()
    client_socket = connect_to_server(host, port)
    if not client_socket:  # Exit if initial connection fails due to shutdown
        return

    # Start receive thread with shared state
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, host, port, state), daemon=True)
    receive_thread.start()

    print("Waiting for instructions...")

    try:
        while not shutdown_flag:
            # Wait briefly for any pending state updates from receive_messages
            time.sleep(0.1)  # Small delay to allow state updates to propagate
            # Dynamic prompt showing username and current room status
            prompt = f"({state.username if state.username else 'unknown'}@{state.current_room if state.current_room else 'outside'})> "
            sys.stdout.flush()  # Ensure prompt updates immediately
            command = input(prompt)
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            valid_commands = [
                "/register ", "/login ", "/create ", "/join ", "/message ", "/quit", "/help",
                "/list_all_users", "/list_users_in_room", "/leave", "/list_all_rooms",
                "/changepassword ", "/delete_room ", "/add_user ", "/edit_user ", "/view_users",
                "/view_room_history ", "/ban_user ", "/unban_user ", "/change_admin_key ",
                "/upload ", "/download ", "/list_files", "/whoami", "/whereami"
            ]

            if any(command.startswith(cmd) for cmd in valid_commands) or command == "/view_users":
                try:
                    client_socket.send(command.encode("utf-8"))
                    print(f"[{current_time}] [SENT] {command}")

                    # Update room status for local commands
                    if command.startswith("/join "):
                        # Room updates will be handled by server response in receive_messages
                        pass
                    elif command.startswith("/leave"):
                        state.current_room = None  # Immediately update locally
                    elif command.startswith("/quit"):
                        print(f"[{current_time}] [INFO] Disconnecting...")
                        shutdown_flag = True
                        client_socket.close()
                        break

                    # Update credentials after login or registration
                    elif command.startswith("/login "):
                        parts = command.split(" ", 3)
                        if len(parts) == 3:
                            state.username, state.password = parts[1], parts[2]
                    elif command.startswith("/register "):
                        parts = command.split(" ", 4)
                        if len(parts) >= 3:
                            state.username, state.password = parts[1], parts[2]  # Set username after registration

                    # Handle file upload
                    elif command.startswith("/upload "):
                        parts = command.split(" ", 3)
                        if len(parts) < 3:
                            print(f"[{current_time}] [ERROR] Usage: /upload <room> <filepath>")
                            continue
                        room_name, filepath = parts[1], parts[2]
                        send_file(client_socket, room_name, filepath)

                except (ConnectionResetError, OSError) as e:
                    print(f"[{current_time}] [ERROR] Failed to send command: {e}. Waiting for reconnection...")
                    time.sleep(1)
            else:
                print(f"[{current_time}] [ERROR] Unknown command. Use /help after login.")

    finally:
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [INFO] Cleaning up...")
        client_socket.close()
        sys.exit(0)  # Ensure clean exit


if __name__ == "__main__":
    main()