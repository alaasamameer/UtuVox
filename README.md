# UtuVox

## Overview
Chat Messenger with File Sharing **for educational purposes** is a multi-user, multi-room chat application developed in Python using socket programming and SQLite. This application enables real-time communication, allowing users to create and join chat rooms, exchange messages, and share files securely.

The project features server-client architecture with user authentication, admin controls, persistent chat history, and file storage capabilities. It serves as an educational tool, showcasing key programming concepts such as networking, multithreading, database management, and file handling.

---

## Features
- **User Authentication**: Register and log in with a username and password. Admin registration requires a secret key stored in `admin_key.txt`.
- **Chat Rooms**: Create, join, and leave rooms. View chat history, active users, and available rooms.
- **Real-Time Messaging**: Send and receive timestamped messages in real-time within chat rooms.
- **File Sharing**: Upload and download files within rooms. Files are stored server-side in the `uploads/` directory with unique identifiers and can be retrieved by clients in the `downloads/` directory.
- **Admin Controls**: Manage users (add, edit, ban, unban). Delete rooms, view room histories, and update the admin key.
- **Persistent Storage**: SQLite database (`utuvox_db.db`) stores user credentials, room data, chat history, file metadata, and admin logs.
- **Multithreading**: Handles multiple client connections concurrently for seamless interaction using Python’s `threading` module.
- **Error Handling**: Comprehensive logging with timestamps for connection issues, invalid commands, and file operations. Updated to use `OSError` for socket and file-related errors, improving robustness.

---

## Development Status
The core functionality—authentication, messaging, file sharing, and admin management—is implemented and functional. The project is under development, with ongoing enhancements may include:

- Refinement of core functions for better performance and reliability.
- Potential future features:
  - Video and voice call support.
  - Desktop sharing capabilities.
  - Enhanced user interface and experience (e.g., GUI or web-based interface).
  - Advanced security features (e.g., encryption, rate limiting).
  - ...etc.

---

## Requirements
- Python 3.6 or later (recommended: 3.9+ for full type hint support)
- No external libraries required (built using Python’s standard library):
  - `socket`
  - `threading`
  - `sqlite3`
  - `os`
  - `datetime`
  - `hashlib`

Note: Type hints for `socket` (e.g., `types-python-socket` or manual stubs) may be required for IDE support, but they are not necessary for runtime functionality.

---

### Directory Structure:
- The project automatically creates:
  - `uploads/` (server-side) for file storage.
  - `downloads/` (client-side) for file retrieval.
  - `utuvox_db.db` (SQLite database) on the first run.
  - `admin_key.txt` (stores the admin key, initialized with `default_admin_key_123`).

### Run the Server:
```bash
python server.py
```
- The server starts on `127.0.0.1:9090` (default).
- Note the admin key displayed on startup (e.g., `default_admin_key_123`).

### Run the Client (in a separate terminal):
```bash
python client.py
```

---

## User Registration
Users can register as either a normal user or an admin.

### Register as a Normal User:
```
/register <username> <password>
```
**Example:**
```
/register johndoe mypassword
```
Response: `[2025-03-01 21:00:00] Registration successful as user.`

### Register as an Admin:
```
/register <username> <password> <admin_key>
```
**Example:**
```
/register adminuser mypass default_admin_key_123
```
Response: `[2025-03-01 21:00:00] Registration successful as admin.`

Note: The admin key is stored in `admin_key.txt` and can be changed with `/change_admin_key <new_key>`.

### Log in:
```
/login <username> <password>
```

## Usage

### Server
- Starts on `127.0.0.1:9090` (configurable in `server.py`).
- Manages client connections, authentication, and command processing.
- Logs all activities with timestamps, including errors handled by `OSError`.

### Client
- Connects to the server via a command-line interface with a dynamic prompt (`(username@room)>` or `(username@outside)>`).

### Basic Commands:
| Command | Description |
|---------|-------------|
| `/register <username> <password> [admin_key]` | Register a new user (admin key required for admin status). |
| `/login <username> <password>` | Log in with existing credentials. |
| `/changepassword <old_password> <new_password>` | Change your password. |
| `/help` | Show the list of available commands. |
| `/create <room>` | Create a new chat room and auto-join it. |
| `/join <room>` | Join an existing chat room and view its history. |
| `/leave` | Leave the current room. |
| `/message <text>` | Send a message to the current room. |
| `/upload <room> <filepath>` | Upload a file to the specified room (stored with a unique name). |
| `/download <filename>` | Download a file by its unique name to the `downloads/` directory. |
| `/list_all_users` | List all online users. |
| `/list_users_in_room` | List users currently in the joined room (duplicate-free). |
| `/list_all_rooms` | List all available chat rooms. |
| `/quit` | Disconnect from the server and exit the chat. |
| `/whoami` | Check the currently logged-in username. |
| `/whereami` | Check the current room or status (outside). |

### Admin Commands (in addition to basic commands):
| Command | Description |
|---------|-------------|
| `/delete_room <room>` | Delete a room and its history, even with active users. |
| `/add_user <username> <password> [is_admin]` | Add a new user (`is_admin`: 0 or 1, default 0). |
| `/edit_user <username> <new_password> [is_admin]` | Edit a user’s password and/or admin status. |
| `/view_users` | List all registered users with their admin and ban status. |
| `/view_room_history <room>` | View a room’s chat history, including messages, joins, leaves, and file operations. |
| `/ban_user <username>` | Ban a user from the server, disconnecting them immediately. |
| `/unban_user <username>` | Unban a previously banned user. |
| `/change_admin_key <new_key>` | Update the admin registration key in `admin_key.txt`. |

---

## Example Usage
### Start the Server:
```
Server started on 127.0.0.1:9090
Admin key: default_admin_key_123
```

### Register as an Admin:
```
(unknown@outside)> /register adminuser mypass default_admin_key_123
[2025-03-01 21:00:00] Registration successful as admin.
(adminuser@outside)> 
```

### Log in and Create a Room:
```
(unknown@outside)> /login adminuser mypass
[2025-03-01 21:00:05] Login successful.
(adminuser@outside)> /create general
[2025-03-01 21:00:10] Room 'general' created successfully.
Debug: Auto-joining room general after creation
[2025-03-01 21:00:10] You joined room 'general'.
Debug: Updating current_room to general
(adminuser@general)> 
```

### Upload a File:
```
(adminuser@general)> /upload general ./example.txt
[2025-03-01 21:00:15] File 'general_20250301_210015_example.txt_<hash>' uploaded to room 'general'.
[2025-03-01 21:00:15] [INFO] File sent to server for room 'general'.
```

### Join Another User and List Room Users:
```
(unknown@outside)> /login johndoe mypassword
[2025-03-01 21:00:20] Login successful.
(johndoe@outside)> /join general
[2025-03-01 21:00:25] Chat history for 'general':
[2025-03-01 21:00:10] User adminuser joined room 'general'
[2025-03-01 21:00:15] User adminuser uploaded file 'general_20250301_210015_example.txt_<hash>' (Original: example.txt)
[2025-03-01 21:00:25] You joined room 'general'.
Debug: Updating current_room to general
(johndoe@general)> /list_users_in_room
[2025-03-01 21:00:30] Users in room 'general': adminuser, johndoe
```

---

## File Structure
```
UtuVox/
├── .venv/               # Virtual environment (auto-generated)
├── client.py            # Client-side script for command-line interaction
├── server.py            # Server-side script for managing connections
├── handlers/            # Directory for handler modules
│   ├── __init__.py      # Initialization file for handlers
│   ├── auth.py          # User authentication and management
│   ├── command_handler.py # Processes client commands
│   ├── file_manager.py  # File upload/download management
│   ├── history_manager.py # Chat history and admin log management
│   ├── room_manager.py  # Room creation and management
├── uploads/             # Auto-generated: Stores uploaded files (server-side)
├── downloads/           # Auto-generated: Stores downloaded files (client-side)
├── utuvox_db.db         # Auto-generated: SQLite database for users, rooms, history, and files
├── admin_key.txt        # Auto-generated: Stores the admin key (default: default_admin_key_123)
└── README.md            # Project documentation
```

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Developer
**Ameer B. A. Alaasam**  
Doctor of Philosophy in Computer Science  
Кандидат физико-математических наук  
📧 Email: alaasam.ameer.b@gmail.com  
```