import sqlite3
import time
from getpass import getpass

import bcrypt

DB_PATH = "users.db"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def verify_password(password: str, password_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash)


def user_exists(username: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = cur.fetchone() is not None
    conn.close()
    return result


def register_user(username: str, password: str) -> bool:
    if user_exists(username):
        return False

    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    conn.close()
    return True


def get_user_record(username: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT username, password_hash, failed_attempts, lock_until FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def update_failed_attempt(username: str, failed_attempts: int, lock_until: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
        (failed_attempts, lock_until, username),
    )
    conn.commit()
    conn.close()


def reset_attempts(username: str) -> None:
    update_failed_attempt(username, 0, 0)


def login_user(username: str, password: str) -> bool:
    user = get_user_record(username)
    if not user:
        return False

    _, password_hash, failed_attempts, lock_until = user
    now = int(time.time())

    if lock_until > now:
        remaining = lock_until - now
        print(f"Account is temporarily locked. Try again in {remaining} seconds.")
        return False

    if verify_password(password, password_hash):
        reset_attempts(username)
        return True

    failed_attempts += 1
    if failed_attempts >= MAX_LOGIN_ATTEMPTS:
        new_lock_until = now + LOCKOUT_SECONDS
        update_failed_attempt(username, failed_attempts, new_lock_until)
        print("Too many failed attempts. Account locked for 60 seconds.")
    else:
        update_failed_attempt(username, failed_attempts, 0)
        print(f"Invalid credentials. Remaining attempts: {MAX_LOGIN_ATTEMPTS - failed_attempts}")

    return False


def prompt_username() -> str:
    while True:
        username = input("Username: ").strip()
        if len(username) >= 3:
            return username
        print("Username must be at least 3 characters.")


def prompt_password() -> str:
    while True:
        password = getpass("Password: ").strip()
        if len(password) >= 8:
            return password
        print("Password must be at least 8 characters.")


def register_flow() -> None:
    print("\n=== Register ===")
    username = prompt_username()
    password = prompt_password()

    if register_user(username, password):
        print("Registration successful.")
    else:
        print("Username already exists.")


def login_flow() -> None:
    print("\n=== Login ===")
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()

    if login_user(username, password):
        print("Login successful.")
    else:
        print("Login failed.")


def main() -> None:
    init_db()

    while True:
        print("\n1) Register")
        print("2) Login")
        print("3) Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            register_flow()
        elif choice == "2":
            login_flow()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
