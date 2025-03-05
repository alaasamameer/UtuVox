import datetime
import threading
import socket
from typing import Optional, Dict, Set, Callable
from functools import wraps
from .room_manager import create_room, room_exists, get_all_rooms, delete_room
from .history_manager import log_event, get_room_history, delete_room_history, log_admin_action
from .auth import change_password, add_user, edit_user, view_users, ban_user, unban_user, set_admin_key
from .file_manager import get_room_files, save_file, get_file_info, serve_file

from config import usernames_lock, rooms_lock

def get_timestamp() -> str:
    """Return the current timestamp formatted as 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def broadcast(message: str, clients: Set[socket.socket], sender_socket: Optional[socket.socket] = None) -> None:
    """Broadcast a message to all clients in a set, excluding the sender."""
    timestamp = get_timestamp()
    message_with_time = f"[{timestamp}] {message}"
    sent_to = set()
    for client_socket in clients:
        if client_socket is not sender_socket and client_socket not in sent_to:
            try:
                print(f"[{timestamp}] [SEND to {client_socket}] {message_with_time}")
                client_socket.send(message_with_time.encode("utf-8"))
                sent_to.add(client_socket)
            except socket.error as error:
                print(f"[{timestamp}] [ERROR] Failed to send to client: {error}")
                client_socket.close()

def notify_joined(room_name: str, username: str, room_clients: Set[socket.socket], sender_socket: Optional[socket.socket]) -> None:
    """Notify room clients when a user joins."""
    message = f"User {username} joined room '{room_name}'"
    log_event(room_name, message)
    broadcast(message, room_clients, sender_socket)

def notify_left(room_name: str, username: str, room_clients: Set[socket.socket], sender_socket: Optional[socket.socket]) -> None:
    """Notify room clients when a user leaves."""
    message = f"User {username} left room '{room_name}'"
    log_event(room_name, message)
    broadcast(message, room_clients, sender_socket)

def get_current_room(client_socket: socket.socket, rooms: Dict[str, Set[socket.socket]]) -> Optional[str]:
    """Get the current room of a client, if any."""
    with rooms_lock:
        for room_name, clients_list in rooms.items():
            if client_socket in clients_list:
                return room_name
    return None

# Command Handlers
def handle_quit(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /quit command."""
    username = usernames.get(client_socket, "Unknown")
    timestamp = get_timestamp()
    print(f"[{timestamp}] [INFO] {username} disconnecting from server.")
    current_room = get_current_room(client_socket, rooms)
    if current_room:
        notify_left(current_room, username, rooms[current_room], client_socket)
        with rooms_lock:
            rooms[current_room].remove(client_socket)
            if not rooms[current_room]:
                del rooms[current_room]
    return False

def handle_leave(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /leave command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    current_room = get_current_room(client_socket, rooms)
    if current_room:
        notify_left(current_room, username, rooms[current_room], client_socket)
        with rooms_lock:
            rooms[current_room].remove(client_socket)
            if not rooms[current_room]:
                del rooms[current_room]
        client_socket.send(f"[{timestamp}] You left room '{current_room}'.".encode("utf-8"))
        print(f"[{timestamp}] [INFO] {username} left room {current_room}.")
    else:
        client_socket.send(f"[{timestamp}] [ERROR] You are not in a room.".encode("utf-8"))
    return True

def handle_message(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /message command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    message_text = message.split(" ", 1)[1]
    current_room = get_current_room(client_socket, rooms)
    if current_room and client_socket in rooms[current_room]:
        full_message = f"{username}: {message_text}"
        log_event(current_room, full_message)
        broadcast(full_message, rooms[current_room], client_socket)
    else:
        client_socket.send(f"[{timestamp}] [ERROR] You are not in a room.".encode("utf-8"))
    return True

def handle_upload(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /upload command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 4)
    if len(parts) != 4:
        client_socket.send(f"[{timestamp}] Usage: /upload <room> <filepath>".encode("utf-8"))
        return True
    room_name, filepath, file_size = parts[1], parts[2], int(parts[3])
    file_data = b""
    while len(file_data) < file_size:
        try:
            chunk = client_socket.recv(min(4096, file_size - len(file_data)))
            if not chunk:
                break
            file_data += chunk
        except OSError as error:
            print(f"[{timestamp}] [ERROR] Failed to receive file chunk: {error}")
            client_socket.send(f"[{timestamp}] Error receiving file: {error}".encode("utf-8"))
            return True
    try:
        with open(filepath, "wb") as f:
            f.write(file_data)
        success, response = save_file(room_name, filepath, username)
        if success:
            for room_client in rooms.get(room_name, set()):
                if room_client != client_socket:
                    room_client.send(response.encode("utf-8"))
        client_socket.send(response.encode("utf-8"))
    except Exception as file_error:
        client_socket.send(f"[{timestamp}] Error uploading file: {file_error}".encode("utf-8"))
    return True

def handle_download(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /download command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    filename = message.split(" ", 2)[1]
    try:
        file_info = get_file_info(filename)
        if file_info:
            serve_file(filename, client_socket, username)
        else:
            client_socket.send(f"[{timestamp}] File '{filename}' not found.".encode("utf-8"))
    except Exception as file_error:
        client_socket.send(f"[{timestamp}] Error downloading file: {file_error}".encode("utf-8"))
    return True

def handle_list_all_users(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /list_all_users command."""
    timestamp = get_timestamp()
    all_users = ", ".join(usernames.values())
    client_socket.send(f"[{timestamp}] All online users: {all_users}".encode("utf-8"))
    return True

def handle_list_users_in_room(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /list_users_in_room command."""
    timestamp = get_timestamp()
    current_room = get_current_room(client_socket, rooms)
    if current_room:
        with rooms_lock:
            unique_clients = list(dict.fromkeys(rooms[current_room]))
            users_in_room = ", ".join([usernames.get(client, "Unknown") for client in unique_clients])
            client_socket.send(f"[{timestamp}] Users in room '{current_room}': {users_in_room}".encode("utf-8"))
    else:
        client_socket.send(f"[{timestamp}] [ERROR] You are not in a room.".encode("utf-8"))
    return True

def handle_list_all_rooms(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /list_all_rooms command."""
    timestamp = get_timestamp()
    room_list = ", ".join(get_all_rooms()) if get_all_rooms() else "No active rooms"
    client_socket.send(f"[{timestamp}] Available rooms: {room_list}".encode("utf-8"))
    return True

def handle_list_files(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /list_files command."""
    timestamp = get_timestamp()
    current_room = get_current_room(client_socket, rooms)
    if current_room:
        files = get_room_files(current_room)
        if files:
            file_list = "\n".join([f"Unique Name: {f[0]}, Original Name: {f[1]}, Uploaded: {f[2]}" for f in files])
            client_socket.send(f"[{timestamp}] Files in room '{current_room}':\n{file_list}".encode("utf-8"))
        else:
            client_socket.send(f"[{timestamp}] No files found in room '{current_room}'.".encode("utf-8"))
    else:
        client_socket.send(f"[{timestamp}] [ERROR] You are not in a room.".encode("utf-8"))
    return True

def handle_whoami(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /whoami command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unauthenticated")
    client_socket.send(f"[{timestamp}] You are logged in as '{username}'.".encode("utf-8"))
    print(f"[{timestamp}] [INFO] {username} queried their identity.")
    return True

def handle_whereami(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /whereami command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    current_room = get_current_room(client_socket, rooms)
    if current_room:
        client_socket.send(f"[{timestamp}] You are currently in room '{current_room}'.".encode("utf-8"))
    else:
        client_socket.send(f"[{timestamp}] You are not in any room.".encode("utf-8"))
    print(f"[{timestamp}] [INFO] {username} queried their room status.")
    return True

def handle_help(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /help command."""
    timestamp = get_timestamp()
    is_admin = clients.get(client_socket, (None, False))[1]
    help_message = (
        f"[{timestamp}] Available commands:\n"
        "/register <username> <password> [admin_key] - register a new user, optionally as admin\n"
        "/login <username> <password> - login with existing credentials\n"
        "/changepassword <old_password> <new_password> - change your password\n"
        "/help - show this list\n"
        "/create <room> - create a room\n"
        "/join <room> - join a room\n"
        "/leave - leave the current room\n"
        "/message <text> - send a message to the room\n"
        "/upload <room> <filepath> - upload a file to the room\n"
        "/download <filename> - download a file by its unique name\n"
        "/list_files - list all files uploaded to the current room\n"
        "/list_all_users - list all online users\n"
        "/list_users_in_room - list users in the current room\n"
        "/list_all_rooms - list all available rooms\n"
        "/whoami - check which username you are currently logged in as\n"
        "/whereami - check which room you are currently in\n"
        "/quit - exit the chat\n"
    )
    if is_admin:
        help_message += (
            "Admin commands:\n"
            "/delete_room <room> - delete a room and its history (even with active users)\n"
            "/add_user <username> <password> [is_admin] - add a new user (is_admin: 0 or 1, default 0)\n"
            "/edit_user <username> <new_password> [is_admin] - edit user’s password and/or admin status\n"
            "/view_users - view all users’ info\n"
            "/view_room_history <room> - view history of a room\n"
            "/ban_user <username> - disconnect and ban a user\n"
            "/unban_user <username> - unban a user\n"
            "/change_admin_key <new_key> - change the admin registration key\n"
        )
    client_socket.send(help_message.encode("utf-8"))
    return True

def handle_create(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /create command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    room_name = message.split(" ")[1]
    with rooms_lock:
        success, response = create_room(room_name)
        client_socket.send(response.encode("utf-8"))
        if success:
            rooms[room_name] = {client_socket}
            history = get_room_history(room_name)
            if history:
                history_message = f"[{timestamp}] Chat history for '{room_name}':\n" + "\n".join(history)
                client_socket.send(history_message.encode("utf-8"))
            notify_joined(room_name, username, rooms[room_name], client_socket)
            client_socket.send(f"[{timestamp}] You joined room '{room_name}'.".encode("utf-8"))
    return True

def handle_join(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /join command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    room_name = message.split(" ", 1)[1]
    current_room = get_current_room(client_socket, rooms)
    with rooms_lock:
        if room_exists(room_name):
            if client_socket in rooms.get(room_name, set()):
                client_socket.send(f"[{timestamp}] You are already in room '{room_name}'.".encode("utf-8"))
                return True
            if current_room and client_socket in rooms[current_room]:
                notify_left(current_room, username, rooms[current_room], client_socket)
                rooms[current_room].remove(client_socket)
                if not rooms[current_room]:
                    del rooms[current_room]
            if room_name not in rooms:
                rooms[room_name] = set()
            rooms[room_name].add(client_socket)
            history = get_room_history(room_name)
            if history:
                history_message = f"[{timestamp}] Chat history for '{room_name}':\n" + "\n".join(history)
                client_socket.send(history_message.encode("utf-8"))
            notify_joined(room_name, username, rooms[room_name], client_socket)
            client_socket.send(f"[{timestamp}] You joined room '{room_name}'.".encode("utf-8"))
        else:
            client_socket.send(f"[{timestamp}] Room '{room_name}' does not exist.".encode("utf-8"))
    return True

def handle_changepassword(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /changepassword command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 3)
    if len(parts) != 3:
        client_socket.send(f"[{timestamp}] Usage: /changepassword <old_password> <new_password>".encode("utf-8"))
    else:
        old_password, new_password = parts[1], parts[2]
        success, response = change_password(username, old_password, new_password)
        client_socket.send(response.encode("utf-8"))
    return True

# Admin Commands Decorator
def require_admin(func: Callable) -> Callable:
    """Decorator to restrict commands to admins."""
    @wraps(func)
    def wrapper(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
        timestamp = get_timestamp()
        is_admin = clients.get(client_socket, (None, False))[1]
        if not is_admin:
            client_socket.send(f"[{timestamp}] [ERROR] Admin privileges required.".encode("utf-8"))
            return True
        return func(client_socket, message, rooms, usernames, clients)
    return wrapper

@require_admin
def handle_delete_room(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /delete_room command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    room_name = message.split(" ", 2)[1]
    with rooms_lock:
        if room_exists(room_name):
            if room_name in rooms:
                for client in rooms[room_name]:
                    try:
                        client.send(f"[{timestamp}] Room '{room_name}' has been deleted by an admin.".encode("utf-8"))
                        client.close()
                    except OSError as error:
                        print(f"[{timestamp}] [ERROR] Failed to notify client: {error}")
                del rooms[room_name]
            success, response = delete_room(room_name)
            if success:
                delete_room_history(room_name)
                log_admin_action(username, f"Deleted room '{room_name}' and its history (with active users)")
            client_socket.send(response.encode("utf-8"))
        else:
            client_socket.send(f"[{timestamp}] Room '{room_name}' does not exist.".encode("utf-8"))
    return True

@require_admin
def handle_add_user(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /add_user command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 4)
    if len(parts) < 3 or len(parts) > 4:
        client_socket.send(f"[{timestamp}] Usage: /add_user <username> <password> [is_admin]".encode("utf-8"))
    else:
        new_username, new_password = parts[1], parts[2]
        new_is_admin = int(parts[3]) if len(parts) == 4 else 0
        success, response = add_user(username, new_username, new_password, new_is_admin)
        if success:
            log_admin_action(username, f"Added user '{new_username}' (is_admin: {new_is_admin})")
        client_socket.send(response.encode("utf-8"))
    return True

@require_admin
def handle_edit_user(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /edit_user command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 4)
    if len(parts) < 3 or len(parts) > 4:
        client_socket.send(f"[{timestamp}] Usage: /edit_user <username> <new_password> [is_admin]".encode("utf-8"))
    else:
        target_username, new_password = parts[1], parts[2]
        new_is_admin = int(parts[3]) if len(parts) == 4 else None
        success, response = edit_user(username, target_username, new_password, new_is_admin)
        if success:
            for client_sock, (addr, is_admin_status) in list(clients.items()):
                if usernames.get(client_sock) == target_username:
                    with usernames_lock:
                        old_is_admin = is_admin_status
                        clients[client_sock] = (addr, bool(new_is_admin) if new_is_admin is not None else is_admin_status)
                    if new_is_admin is not None:
                        new_status = "an admin" if new_is_admin else "a regular user"
                        old_status = "an admin" if old_is_admin else "a regular user"
                        try:
                            client_sock.send(f"[{timestamp}] Your status has changed from {old_status} to {new_status} by admin '{username}'.".encode("utf-8"))
                        except OSError as error:
                            print(f"[{timestamp}] [ERROR] Failed to notify user: {error}")
            log_admin_action(username, f"Edited user '{target_username}' (new_password: {new_password}, is_admin: {new_is_admin})")
        client_socket.send(response.encode("utf-8"))
    return True

@require_admin
def handle_view_users(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /view_users command."""
    username = usernames.get(client_socket, "Unknown")
    success, response = view_users(username)
    client_socket.send(response.encode("utf-8"))
    return True

@require_admin
def handle_view_room_history(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /view_room_history command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    room_name = message.split(" ", 2)[1]
    if room_exists(room_name):
        history = get_room_history(room_name)
        if history:
            history_message = f"[{timestamp}] History for '{room_name}':\n" + "\n".join(history)
            client_socket.send(history_message.encode("utf-8"))
        else:
            client_socket.send(f"[{timestamp}] No history found for room '{room_name}'.".encode("utf-8"))
        log_admin_action(username, f"Viewed history of room '{room_name}'")
    else:
        client_socket.send(f"[{timestamp}] Room '{room_name}' does not exist.".encode("utf-8"))
    return True

@require_admin
def handle_ban_user(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /ban_user command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    target_username = message.split(" ", 2)[1]
    success, response = ban_user(username, target_username)
    if success:
        for client_sock, uname in list(usernames.items()):
            if uname == target_username:
                try:
                    client_sock.send(f"[{timestamp}] You have been banned by an admin.".encode("utf-8"))
                    client_sock.close()
                except OSError as error:
                    print(f"[{timestamp}] [ERROR] Failed to ban user: {error}")
                with usernames_lock:
                    del usernames[client_sock]
                    del clients[client_sock]
        log_admin_action(username, f"Banned user '{target_username}'")
    client_socket.send(response.encode("utf-8"))
    return True

@require_admin
def handle_unban_user(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /unban_user command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 2)
    if len(parts) != 2:
        client_socket.send(f"[{timestamp}] Usage: /unban_user <username>".encode("utf-8"))
    else:
        target_username = parts[1]
        success, response = unban_user(username, target_username)
        if success:
            for client_sock, (addr, _) in list(clients.items()):
                if usernames.get(client_sock) == target_username:
                    try:
                        client_sock.send(f"[{timestamp}] You have been unbanned by admin '{username}'.".encode("utf-8"))
                    except OSError as error:
                        print(f"[{timestamp}] [ERROR] Failed to unban user: {error}")
            log_admin_action(username, f"Unbanned user '{target_username}'")
        client_socket.send(response.encode("utf-8"))
    return True

@require_admin
def handle_change_admin_key(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """Handle the /change_admin_key command."""
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    parts = message.split(" ", 2)
    if len(parts) != 2:
        client_socket.send(f"[{timestamp}] Usage: /change_admin_key <new_key>".encode("utf-8"))
    else:
        new_key = parts[1]
        set_admin_key(new_key)
        log_admin_action(username, f"Changed admin key to '{new_key}'")
        client_socket.send(f"[{timestamp}] Admin key changed successfully.".encode("utf-8"))
    return True

# Command Registry
COMMAND_HANDLERS: Dict[str, Callable] = {
    "/quit": handle_quit,
    "/leave": handle_leave,
    "/message": handle_message,
    "/upload": handle_upload,
    "/download": handle_download,
    "/list_all_users": handle_list_all_users,
    "/list_users_in_room": handle_list_users_in_room,
    "/list_all_rooms": handle_list_all_rooms,
    "/list_files": handle_list_files,
    "/whoami": handle_whoami,
    "/whereami": handle_whereami,
    "/help": handle_help,
    "/create": handle_create,
    "/join": handle_join,
    "/changepassword": handle_changepassword,
    "/delete_room": handle_delete_room,
    "/add_user": handle_add_user,
    "/edit_user": handle_edit_user,
    "/view_users": handle_view_users,
    "/view_room_history": handle_view_room_history,
    "/ban_user": handle_ban_user,
    "/unban_user": handle_unban_user,
    "/change_admin_key": handle_change_admin_key,
}

def process_command(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    """
    Process a command from a client and dispatch it to the appropriate handler.

    Args:
        client_socket: The client's socket connection.
        message: The raw command string from the client.
        rooms: Dictionary of room names to sets of client sockets.
        usernames: Dictionary mapping client sockets to usernames.
        clients: Dictionary mapping client sockets to (address, is_admin) tuples.

    Returns:
        bool: True to continue processing, False to disconnect the client.
    """
    timestamp = get_timestamp()
    username = usernames.get(client_socket, "Unknown")
    if not message.startswith('/message'):
        print(f"[{timestamp}] [COMMAND] {username} executed: {message}")

    command_parts = message.split(" ", 1)
    command = command_parts[0]
    args = command_parts[1] if len(command_parts) > 1 else ""

    handler = COMMAND_HANDLERS.get(command)
    if handler:
        return handler(client_socket, message if args else command, rooms, usernames, clients)
    else:
        client_socket.send(f"[{timestamp}] [ERROR] Unknown command: {command}. Use /help for a list of commands.".encode("utf-8"))
        return True