import datetime
import threading
import socket  # Import socket for socket operations
from typing import Optional, Dict, Set  # Updated for set type hints
from .room_manager import create_room, room_exists, get_all_rooms, delete_room
from .history_manager import log_event, get_room_history, delete_room_history, log_admin_action
from .auth import change_password, add_user, edit_user, view_users, ban_user, unban_user, set_admin_key
from .file_manager import get_room_files, save_file, get_file_info, serve_file

rooms_lock = threading.Lock()
usernames_lock = threading.Lock()

def broadcast(message: str, clients: Set[socket.socket], sender_socket: Optional[socket.socket] = None) -> None:
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message_with_time = f"[{current_time}] {message}"
    sent_to = set()
    for client_socket in clients:
        if client_socket is not sender_socket and client_socket not in sent_to:
            try:
                print(f"[{current_time}] [SEND to {client_socket}] {message_with_time}")
                client_socket.send(message_with_time.encode("utf-8"))
                sent_to.add(client_socket)
            except socket.error as error:  # Use 'error' instead of 'e' to avoid potential shadowing issues
                print(f"[{current_time}] [ERROR] Failed to send to client: {error}")
                client_socket.close()

def notify_joined(room_name: str, joined_username: str, room_clients: Set[socket.socket], sender_socket: Optional[socket.socket]) -> None:
    message = f"User {joined_username} joined room '{room_name}'"
    log_event(room_name, message)  # Removed unused logged_message
    broadcast(message, room_clients, sender_socket)

def notify_left(room_name: str, exited_username: str, room_clients: Set[socket.socket], sender_socket: Optional[socket.socket]) -> None:
    message = f"User {exited_username} left room '{room_name}'"
    log_event(room_name, message)  # Removed unused logged_message
    broadcast(message, room_clients, sender_socket)

def get_current_room(client_socket: socket.socket, rooms: Dict[str, Set[socket.socket]]) -> Optional[str]:
    """Helper function to get the user's current room based on their client_socket."""
    with rooms_lock:
        for room_name, clients_list in rooms.items():
            if client_socket in clients_list:
                return room_name
    return None

def process_command(client_socket: socket.socket, message: str, rooms: Dict[str, Set[socket.socket]], usernames: Dict[socket.socket, str], clients: Dict[socket.socket, tuple]) -> bool:
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = usernames.get(client_socket, "Unknown")
    is_admin = clients.get(client_socket, (None, False))[1]

    if not message.startswith('/message'):
        print(f"[{current_time}] [COMMAND] {username} executed: {message}")

    if message == '/quit':
        print(f"[{current_time}] [INFO] {username} disconnecting from server.")
        current_room = get_current_room(client_socket, rooms)
        if current_room:
            notify_left(current_room, username, rooms[current_room], client_socket)
            with rooms_lock:
                rooms[current_room].remove(client_socket)
                if not rooms[current_room]:
                    del rooms[current_room]
        return False

    elif message == '/leave':
        current_room = get_current_room(client_socket, rooms)
        if current_room:
            notify_left(current_room, username, rooms[current_room], client_socket)
            with rooms_lock:
                rooms[current_room].remove(client_socket)
                if not rooms[current_room]:
                    del rooms[current_room]
            client_socket.send(f"[{current_time}] You left room '{current_room}'.".encode("utf-8"))
            print(f"[{current_time}] [INFO] {username} left room {current_room}.")
            return True
        client_socket.send(f"[{current_time}] [ERROR] You are not in a room.".encode("utf-8"))
        return True

    elif message.startswith('/message '):
        message_text = message.split(' ', 1)[1]
        current_room = get_current_room(client_socket, rooms)
        if current_room and client_socket in rooms[current_room]:
            full_message = f"{username}: {message_text}"
            log_event(current_room, full_message)  # Removed unused logged_message
            broadcast(full_message, rooms[current_room], client_socket)
            return True
        client_socket.send(f"[{current_time}] [ERROR] You are not in a room.".encode("utf-8"))
        return True

    # Handle /upload command
    elif message.startswith('/upload '):
        parts = message.split(" ", 4)
        if len(parts) != 4:
            client_socket.send(f"[{current_time}] Usage: /upload <room> <filepath>".encode("utf-8"))
            return True
        room_name, filepath, file_size = parts[1], parts[2], int(parts[3])
        file_data = b''
        while len(file_data) < file_size:
            try:
                chunk = client_socket.recv(min(4096, file_size - len(file_data)))
                if not chunk:
                    break
                file_data += chunk
            except OSError as error:  # Use 'error' instead of 'e' to avoid potential shadowing
                print(f"[{current_time}] [ERROR] Failed to receive file chunk: {error}")
                client_socket.send(f"[{current_time}] Error receiving file: {error}".encode("utf-8"))
                return True
        try:
            success, response = save_file(room_name, filepath, username)
            if success:
                for room_client in rooms.get(room_name, set()):
                    if room_client != client_socket:
                        room_client.send(response.encode("utf-8"))
            client_socket.send(response.encode("utf-8"))
        except Exception as file_error:  # Specific exception for file operations
            client_socket.send(f"[{current_time}] Error uploading file: {file_error}".encode("utf-8"))
        return True

    # Handle /download command
    elif message.startswith('/download '):
        filename = message.split(" ", 2)[1]
        try:
            file_info = get_file_info(filename)
            if file_info:
                serve_file(filename, client_socket, username)
            else:
                client_socket.send(f"[{current_time}] File '{filename}' not found.".encode("utf-8"))
        except Exception as file_error:  # Specific exception for file operations
            client_socket.send(f"[{current_time}] Error downloading file: {file_error}".encode("utf-8"))
        return True

    elif message == '/list_all_users':
        all_users = ", ".join(usernames.values())
        client_socket.send(f"[{current_time}] All online users: {all_users}".encode("utf-8"))

    elif message == '/list_users_in_room':
        current_room = get_current_room(client_socket, rooms)
        if current_room:
            with rooms_lock:
                # Remove duplicates and get unique usernames
                unique_clients = list(dict.fromkeys(rooms[current_room]))  # Remove duplicates while preserving order
                users_in_room = ", ".join([usernames.get(client, "Unknown") for client in unique_clients])
                client_socket.send(f"[{current_time}] Users in room '{current_room}': {users_in_room}".encode("utf-8"))
            return True
        client_socket.send(f"[{current_time}] [ERROR] You are not in a room.".encode("utf-8"))
        return True

    elif message == '/list_all_rooms':
        room_list = ", ".join(get_all_rooms()) if get_all_rooms() else "No active rooms"
        client_socket.send(f"[{current_time}] Available rooms: {room_list}".encode("utf-8"))

    elif message == '/list_files':
        current_room = get_current_room(client_socket, rooms)
        if current_room:
            files = get_room_files(current_room)
            if files:
                file_list = "\n".join(
                    [f"Unique Name: {f[0]}, Original Name: {f[1]}, Uploaded: {f[2]}" for f in files]
                )
                client_socket.send(
                    f"[{current_time}] Files in room '{current_room}':\n{file_list}".encode("utf-8")
                )
            else:
                client_socket.send(
                    f"[{current_time}] No files found in room '{current_room}'.".encode("utf-8")
                )
            return True
        client_socket.send(f"[{current_time}] [ERROR] You are not in a room.".encode("utf-8"))
        return True

    elif message == '/whoami':
        username = usernames.get(client_socket, "Unauthenticated")
        client_socket.send(
            f"[{current_time}] You are logged in as '{username}'.".encode("utf-8")
        )
        print(f"[{current_time}] [INFO] {username} queried their identity.")
        return True

    elif message == '/whereami':
        current_room = get_current_room(client_socket, rooms)
        if current_room:
            client_socket.send(
                f"[{current_time}] You are currently in room '{current_room}'.".encode("utf-8")
            )
        else:
            client_socket.send(
                f"[{current_time}] You are not in any room.".encode("utf-8")
            )
        print(f"[{current_time}] [INFO] {username} queried their room status.")
        return True

    elif message == '/help':
        help_message = (
            f"[{current_time}] Available commands:\n"
            "/register <username> <password> [admin_key] - register a new user, optionally as admin\n"
            "/login <username> <password> - login with existing credentials\n"
            "/changepassword <old_password> <new_password> - change your password\n"  # Fixed typo
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

    elif message.startswith('/create '):
        room_name = message.split(" ")[1]
        with rooms_lock:
            success, response = create_room(room_name)
            client_socket.send(response.encode("utf-8"))
            if success:
                rooms[room_name] = {client_socket}  # Use set literal for clarity and uniqueness
                # Auto-join the room after creation
                rooms[room_name].add(client_socket)  # Ensure client is added (set preserves uniqueness)
                history = get_room_history(room_name)
                if history:
                    history_message = f"[{current_time}] Chat history for '{room_name}':\n" + "\n".join(history)
                    client_socket.send(history_message.encode("utf-8"))
                notify_joined(room_name, username, rooms[room_name], client_socket)
                client_socket.send(f"[{current_time}] You joined room '{room_name}'.".encode("utf-8"))

    elif message.startswith('/join '):
        room_name = message.split(" ", 1)[1]
        current_room = get_current_room(client_socket, rooms)
        with rooms_lock:
            if room_exists(room_name):
                if client_socket in rooms.get(room_name, set()):
                    client_socket.send(f"[{current_time}] You are already in room '{room_name}'.".encode("utf-8"))
                    return True
                # Leave the current room if joining a new one
                if current_room and client_socket in rooms[current_room]:
                    notify_left(current_room, username, rooms[current_room], client_socket)
                    rooms[current_room].remove(client_socket)
                    if not rooms[current_room]:
                        del rooms[current_room]
                # Join the new room
                if room_name not in rooms:
                    rooms[room_name] = set()
                rooms[room_name].add(client_socket)  # Add client to set, ensuring uniqueness
                history = get_room_history(room_name)
                if history:
                    history_message = f"[{current_time}] Chat history for '{room_name}':\n" + "\n".join(history)
                    client_socket.send(history_message.encode("utf-8"))
                notify_joined(room_name, username, rooms[room_name], client_socket)
                client_socket.send(f"[{current_time}] You joined room '{room_name}'.".encode("utf-8"))
            else:
                client_socket.send(f"[{current_time}] Room '{room_name}' does not exist.".encode("utf-8"))

    elif message.startswith('/changepassword '):
        parts = message.split(" ", 3)
        if len(parts) != 3:
            client_socket.send(f"[{current_time}] Usage: /changepassword <old_password> <new_password>".encode("utf-8"))
        else:
            old_password, new_password = parts[1], parts[2]
            success, response = change_password(username, old_password, new_password)
            client_socket.send(response.encode("utf-8"))

    # Admin Commands
    elif message.startswith('/delete_room ') and is_admin:
        room_name = message.split(" ", 2)[1]
        with rooms_lock:
            if room_exists(room_name):
                if room_name in rooms:
                    # Notify and disconnect all active users in the room
                    for client in rooms[room_name]:
                        try:
                            client.send(f"[{current_time}] Room '{room_name}' has been deleted by an admin.".encode("utf-8"))
                            client.close()
                        except OSError as error:  # Use 'error' instead of 'e' to avoid potential shadowing
                            print(f"[{current_time}] [ERROR] Failed to notify client: {error}")
                    del rooms[room_name]  # Remove from in-memory rooms
                success, response = delete_room(room_name)
                if success:
                    delete_room_history(room_name)
                    log_admin_action(username, f"Deleted room '{room_name}' and its history (with active users)")
                client_socket.send(response.encode("utf-8"))
            else:
                client_socket.send(f"[{current_time}] Room '{room_name}' does not exist.".encode("utf-8"))

    elif message.startswith('/add_user ') and is_admin:
        parts = message.split(" ", 4)
        if len(parts) < 3 or len(parts) > 4:
            client_socket.send(f"[{current_time}] Usage: /add_user <username> <password> [is_admin]".encode("utf-8"))
        else:
            new_username, new_password = parts[1], parts[2]
            new_is_admin = int(parts[3]) if len(parts) == 4 else 0
            success, response = add_user(username, new_username, new_password, new_is_admin)
            if success:
                log_admin_action(username, f"Added user '{new_username}' (is_admin: {new_is_admin})")
            client_socket.send(response.encode("utf-8"))

    elif message.startswith('/edit_user ') and is_admin:
        parts = message.split(" ", 4)
        if len(parts) < 3 or len(parts) > 4:
            client_socket.send(f"[{current_time}] Usage: /edit_user <username> <new_password> [is_admin]".encode("utf-8"))
        else:
            target_username, new_password = parts[1], parts[2]
            new_is_admin = int(parts[3]) if len(parts) == 4 else None
            success, response = edit_user(username, target_username, new_password, new_is_admin)
            if success:
                # If the user is online, update their client status and notify them
                for client_socket, (addr, is_admin_status) in list(clients.items()):
                    if usernames.get(client_socket) == target_username:
                        with usernames_lock:
                            old_is_admin = is_admin_status
                            clients[client_socket] = (addr, bool(new_is_admin) if new_is_admin is not None else is_admin_status)
                        # Notify the user of the change
                        if new_is_admin is not None:
                            new_status = "an admin" if new_is_admin else "a regular user"
                            old_status = "an admin" if old_is_admin else "a regular user"
                            try:
                                client_socket.send(f"[{current_time}] Your status has changed from {old_status} to {new_status} by admin '{username}'.".encode("utf-8"))
                            except OSError as error:  # Use 'error' instead of 'e' to avoid potential shadowing
                                print(f"[{current_time}] [ERROR] Failed to notify user: {error}")
                log_admin_action(username, f"Edited user '{target_username}' (new_password: {new_password}, is_admin: {new_is_admin})")
            client_socket.send(response.encode("utf-8"))

    elif message == '/view_users' and is_admin:
        success, response = view_users(username)
        client_socket.send(response.encode("utf-8"))

    elif message.startswith('/view_room_history ') and is_admin:
        room_name = message.split(" ", 2)[1]
        if room_exists(room_name):
            history = get_room_history(room_name)
            if history:
                history_message = f"[{current_time}] History for '{room_name}':\n" + "\n".join(history)
                client_socket.send(history_message.encode("utf-8"))
            else:
                client_socket.send(f"[{current_time}] No history found for room '{room_name}'.".encode("utf-8"))
            log_admin_action(username, f"Viewed history of room '{room_name}'")
        else:
            client_socket.send(f"[{current_time}] Room '{room_name}' does not exist.".encode("utf-8"))

    elif message.startswith('/ban_user ') and is_admin:
        target_username = message.split(" ", 2)[1]
        success, response = ban_user(username, target_username)
        if success:
            for client_socket, uname in list(usernames.items()):
                if uname == target_username:
                    try:
                        client_socket.send(f"[{current_time}] You have been banned by an admin.".encode("utf-8"))
                        client_socket.close()
                    except OSError as error:  # Use 'error' instead of 'e' to avoid potential shadowing
                        print(f"[{current_time}] [ERROR] Failed to ban user: {error}")
                    with usernames_lock:
                        del usernames[client_socket]
                        del clients[client_socket]
            log_admin_action(username, f"Banned user '{target_username}'")
        client_socket.send(response.encode("utf-8"))

    elif message.startswith('/unban_user ') and is_admin:
        parts = message.split(" ", 2)
        if len(parts) != 2:
            client_socket.send(f"[{current_time}] Usage: /unban_user <username>".encode("utf-8"))
        else:
            target_username = parts[1]
            success, response = unban_user(username, target_username)
            if success:
                # Notify the user if online (though they’ll need to reconnect)
                for client_socket, (addr, _) in list(clients.items()):
                    if usernames.get(client_socket) == target_username:
                        try:
                            client_socket.send(f"[{current_time}] You have been unbanned by admin '{username}'.".encode("utf-8"))
                        except OSError as error:  # Use 'error' instead of 'e' to avoid potential shadowing
                            print(f"[{current_time}] [ERROR] Failed to unban user: {error}")
                log_admin_action(username, f"Unbanned user '{target_username}'")
            client_socket.send(response.encode("utf-8"))

    elif message.startswith('/change_admin_key ') and is_admin:
        parts = message.split(" ", 2)
        if len(parts) != 2:
            client_socket.send(f"[{current_time}] Usage: /change_admin_key <new_key>".encode("utf-8"))
        else:
            new_key = parts[1]
            set_admin_key(new_key)
            log_admin_action(username, f"Changed admin key to '{new_key}'")
            client_socket.send(f"[{current_time}] Admin key changed successfully.".encode("utf-8"))

    elif (message.startswith('/delete_room ') or message.startswith('/add_user ') or
          message.startswith('/edit_user ') or message == '/view_users' or
          message.startswith('/view_room_history ') or message.startswith('/ban_user ') or
          message.startswith('/unban_user ') or message.startswith('/change_admin_key ')):
        client_socket.send(f"[{current_time}] [ERROR] Admin privileges required.".encode("utf-8"))

    return True