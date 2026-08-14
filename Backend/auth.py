"""
auth.py — Google OAuth token verification and local JWT issuance.

Bootstrap admin mechanism:
  Set BOOTSTRAP_ADMIN_EMAIL in the environment before first run.
  On the first sign-in attempt by that email the account is created and
  promoted to 'admin'. This cannot be triggered a second time because
  subsequent sign-ins find the existing user row and return it directly.

Session design:
  Stateless JWTs (12h TTL). Logout is handled client-side by deleting the token
  from localStorage. The backend has no session store to invalidate — a deliberate
  trade-off for operational simplicity on a hobby server. If a token is stolen
  the window of exposure is at most 12 hours.
"""

import os
import datetime
import jwt
from google.oauth2 import id_token
from google.auth.transport import requests
from database import DB_PATH, get_db

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID")
SESSION_SECRET       = os.environ.get("SESSION_SECRET", "fallback-dev-secret-change-me")
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("BOOTSTRAP_ADMIN_EMAIL")


def verify_google_token(token: str):
    """
    Validates a Google ID token and returns the verified email address,
    or None if the token is invalid or the client ID is not configured.
    """
    if not GOOGLE_CLIENT_ID:
        print("[Auth] Warning: GOOGLE_CLIENT_ID not set; token verification disabled.")
        return None
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        return idinfo.get("email")
    except ValueError:
        return None


def get_or_create_user(email: str):
    """
    Looks up the user in SQLite.
    If the user does not exist and their email matches BOOTSTRAP_ADMIN_EMAIL,
    creates the admin account. Otherwise returns None (access denied).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    # If user exists, return them
    if user:
        conn.close()
        return dict(user)

    # Check if there are ANY users in the database yet
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    # For testing: ANY user who logs in is automatically created.
    # The first user becomes admin, everyone else becomes a regular user.
    role = "admin" if user_count == 0 else "user"
    
    cursor.execute(
        "INSERT INTO users (email, role) VALUES (?, ?)",
        (email, role)
    )
    conn.commit()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = dict(cursor.fetchone())
    conn.close()
    return user


def generate_jwt(user_dict: dict) -> str:
    """Issues a stateless session token valid for 12 hours."""
    payload = {
        "sub":   user_dict["id"],
        "email": user_dict["email"],
        "role":  user_dict["role"],
        "exp":   datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12),
    }
    return jwt.encode(payload, SESSION_SECRET, algorithm="HS256")
