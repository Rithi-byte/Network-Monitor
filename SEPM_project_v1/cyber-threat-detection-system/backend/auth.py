"""User authentication backed by users.csv."""
import csv
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

VALID_ROLES = frozenset({"admin", "user"})
FORBIDDEN_USERNAMES = frozenset({"admin"})
# Username must start with a letter and be 3-20 alphanumeric characters or dots/underscores
USERNAME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9._]{2,19}$")


def _users_path(root_dir):
    return os.path.join(root_dir, "database", "users.csv")


def ensure_users_file(root_dir):
    path = _users_path(root_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["username", "password", "role"])
            w.writeheader()
            w.writerow(
                {
                    "username": "admin",
                    "password": generate_password_hash("admin123"),
                    "role": "admin",
                }
            )
    return path


def load_users(root_dir):
    path = ensure_users_file(root_dir)
    users = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            users[row["username"]] = {
                "password": row["password"],
                "role": row["role"],
            }
    return users


def register_user(root_dir, username, password, role="user", is_admin_action=False):
    # Public registration always defaults to 'user'
    if not is_admin_action:
        role = "user"
    else:
        if role not in VALID_ROLES:
            role = "user"
    username = (username or "").strip()
    if not username or not password:
        return False, "Username and password are required."
    
    if len(password) < 5:
        return False, "Password must be at least 5 characters long."
    
    if username.lower() in FORBIDDEN_USERNAMES:
        return False, f"Username '{username}' is not allowed."
        
    if not USERNAME_REGEX.match(username):
        return (
            False,
            "Invalid username format. Use 3-20 alphanumeric characters starting with a letter.",
        )

    path = ensure_users_file(root_dir)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["username"].lower() == username.lower():
                return False, "Username already exists."
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=["username", "password", "role"]).writerow(
            {
                "username": username,
                "password": generate_password_hash(password),
                "role": role,
            }
        )
    return True, "Registered successfully."


def verify_user(root_dir, username, password):
    users = load_users(root_dir)
    u = users.get((username or "").strip())
    if not u:
        return None
    if check_password_hash(u["password"], password):
        return {"username": username.strip(), "role": u["role"]}
    return None


def _write_all_users(root_dir, rows):
    path = ensure_users_file(root_dir)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["username", "password", "role"])
        w.writeheader()
        for row in rows:
            w.writerow(row)


def list_users_public(root_dir):
    """Username and role only (no password hashes)."""
    users = load_users(root_dir)
    return [
        {"username": u, "role": d["role"]}
        for u, d in sorted(users.items(), key=lambda x: x[0].lower())
    ]


def delete_user(root_dir, target_username, actor_username):
    target_username = (target_username or "").strip()
    actor_username = (actor_username or "").strip()
    if not target_username:
        return False, "Username required."
    users = load_users(root_dir)
    if target_username not in users:
        return False, "User not found."
    if target_username == actor_username:
        return False, "You cannot delete your own account."
    admin_names = [u for u, d in users.items() if d["role"] == "admin"]
    if users[target_username]["role"] == "admin" and len(admin_names) <= 1:
        return False, "Cannot remove the last administrator."
    del users[target_username]
    rows = [
        {"username": u, "password": d["password"], "role": d["role"]}
        for u, d in users.items()
    ]
    _write_all_users(root_dir, rows)
    return True, "User deleted."


def set_user_role(root_dir, target_username, new_role):
    target_username = (target_username or "").strip()
    if new_role not in VALID_ROLES:
        return False, "Invalid role."
    users = load_users(root_dir)
    if target_username not in users:
        return False, "User not found."
    old = users[target_username]["role"]
    admin_count = sum(1 for d in users.values() if d["role"] == "admin")
    if old == "admin" and new_role != "admin" and admin_count <= 1:
        return False, "Cannot demote the last administrator."
    users[target_username]["role"] = new_role
    rows = [
        {"username": u, "password": d["password"], "role": d["role"]}
        for u, d in users.items()
    ]
    _write_all_users(root_dir, rows)
    return True, "Role updated."


def admin_create_user(root_dir, username, password, role="user"):
    """Same rules as register_user; used from admin API, but allows role setting."""
    return register_user(root_dir, username, password, role, is_admin_action=True)
