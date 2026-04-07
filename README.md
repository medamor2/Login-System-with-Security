# Python Secure Login System

A simple login system using Python and SQLite with secure password hashing.

## Features

- Username/password login
- Secure password storage with `bcrypt`
- No plain-text password storage
- Login attempt limiting
- Temporary account lockout to slow brute-force attacks

## How It Works

### 1) Password Hashing

This project uses `bcrypt`, which is designed for password storage:

- A unique salt is generated for each password.
- The password is hashed with a configurable work factor (`rounds=12`).
- Only the hash is stored in the database, never the original password.

Why this matters:

- If the database is leaked, attackers do not get plain-text passwords.
- The computational cost of `bcrypt` makes large-scale password cracking slower.

### 2) Authentication Flow

- On registration, the password is hashed and saved as `password_hash`.
- On login, the entered password is verified against the stored hash.
- After a successful login, failed-attempt counters are reset.

### 3) Brute-Force Protection

- Each account tracks failed login attempts.
- After `5` failed attempts, the account is locked for `60` seconds.
- During lockout, login is denied until the timer expires.

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the program:

```bash
python secure_login.py
```

## Security Best Practices

- Use `bcrypt` (or Argon2) for password hashing in production systems.
- Enforce stronger password rules (length, complexity, breached-password checks).
- Use HTTPS for all authentication traffic in web apps.
- Add MFA for sensitive systems.
- Log authentication events and monitor suspicious activity.
- Rate-limit login attempts per IP and per account.
- Store secrets and configuration in environment variables, not source code.
- Keep dependencies and Python patched.

## Project Notes

- Database file: `users.db` (created automatically)
- User table stores:
  - `username`
  - `password_hash`
  - `failed_attempts`
  - `lock_until`

## 👤 Author

Developed by **Mohamed Moncef Amor**

## 📜 License

All rights reserved © Mohamed Moncef Amor
