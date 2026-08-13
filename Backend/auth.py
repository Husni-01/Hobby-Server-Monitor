import os
import jwt
import datetime
from google.oauth2 import id_token
from google.auth.transport import requests
import sqlite3

# Load from environment variables
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "fallback-dev-secret-change-me")
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("BOOTSTRAP_ADMIN_EMAIL")
DB_PATH = "hobby_monitor.db"

def verify_google_token(token: str):
    """Verifies the Google OAuth ID token and extracts user info."""
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        return idinfo['email']
    except ValueError:
        return None

def get_or_create_user(email: str):
    """
    Handles the bootstrap logic: First user matching the env variable gets admin.
    Otherwise, checks if the user exists (invited by admin).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user:
        return dict(user)

    # If user doesn't exist, check if they are the bootstrap admin
    if email == BOOTSTRAP_ADMIN_EMAIL:
        cursor.execute(
            "INSERT INTO users (email, role) VALUES (?, ?)", 
            (email, 'admin')
        )
        conn.commit()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        return dict(cursor.fetchone())

    # User is not in the database and is not the bootstrap admin
    return None

def generate_jwt(user_dict: dict):
    """Issues a stateless session token valid for 12 hours."""
    payload = {
        'sub': user_dict['id'],
        'email': user_dict['email'],
        'role': user_dict['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    }
    return jwt.encode(payload, SESSION_SECRET, algorithm='HS256')
