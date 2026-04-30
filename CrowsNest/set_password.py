#!/usr/bin/env python3
"""
Windrose Game Server Controller — Password Setup CLI

Sets or updates the hashed password for a user in the .env file.
The password is hashed with PBKDF2-SHA256 (260,000 iterations, random salt).

Usage:
    python set_password.py <username>

    python set_password.py scott
    python set_password.py jeff
"""

import sys
import hashlib
import getpass
import re
import secrets
from pathlib import Path

ENV_FILE = Path(__file__).parent / ".env"
PBKDF2_ITERATIONS = 260_000

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{1,64}$')


def hash_password(plain_password: str) -> str:
    """Return a PBKDF2-SHA256 hash string with an embedded random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def update_env_file(username: str, hashed_password: str) -> None:
    """Insert or replace the password hash line for *username* in the .env file."""
    key = f"{username.upper()}_PASSWORD_HASH"
    new_line = f"{key}={hashed_password}"

    if ENV_FILE.exists():
        content = ENV_FILE.read_text()
        pattern = rf"^{re.escape(key)}=.*$"
        if re.search(pattern, content, re.MULTILINE):
            # Key already exists — replace it in-place
            updated = re.sub(pattern, new_line, content, flags=re.MULTILINE)
            ENV_FILE.write_text(updated)
        else:
            # Append a new line
            with ENV_FILE.open("a") as f:
                if content and not content.endswith("\n"):
                    f.write("\n")
                f.write(f"{new_line}\n")
    else:
        ENV_FILE.write_text(f"{new_line}\n")

    print(f"Password for '{username}' has been updated in {ENV_FILE}")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] in {"-h", "--help"}:
        print(__doc__.strip())
        sys.exit(0 if sys.argv[1:] and sys.argv[1] in {"-h", "--help"} else 1)

    username = sys.argv[1].lower().strip()

    if not _USERNAME_RE.match(username):
        print(f"Error: '{username}' is not a valid username.")
        print("Usernames must be alphanumeric (letters, numbers, underscores, max 64 chars).")
        sys.exit(1)

    try:
        password = getpass.getpass(f"New password for '{username}': ")
        if not password:
            print("Error: Password cannot be empty.")
            sys.exit(1)

        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match.")
            sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(1)

    hashed = hash_password(password)
    update_env_file(username, hashed)
    print("Done.")


if __name__ == "__main__":
    main()
