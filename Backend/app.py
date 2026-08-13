import falcon
import jwt
import os
import json
import sqlite3
import shlex
from auth import verify_google_token, get_or_create_user, generate_jwt
from datetime import datetime, timedelta, timezone
from tinyflux import TimeQuery
from database import DB_PATH, get_tsdb
from lxd_client import get_all_containers_summary, create_container



SESSION_SECRET = os.environ.get("SESSION_SECRET", "fallback-dev-secret-change-me")

class AuthMiddleware:
    """
    Global middleware to enforce authentication.
    Denies access by default unless the route is explicitly exempt.
    """
    def __init__(self, exempt_routes=None):
        self.exempt_routes = exempt_routes or []

    def process_request(self, req, resp):
        # 1. Allow exempt routes (like the login endpoint)
        if req.path in self.exempt_routes:
            return

        # 2. Check for Authorization header
        auth_header = req.get_header('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            raise falcon.HTTPUnauthorized(description='Missing or invalid authorization token')

        token = auth_header.split(' ')[1]

        # 3. Validate the JWT
        try:
            decoded = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
            # Attach user context to the request so downstream endpoints can use it
            req.context.user = decoded
        except jwt.ExpiredSignatureError:
            raise falcon.HTTPUnauthorized(description='Session expired. Please log in again.')
        except jwt.InvalidTokenError:
            raise falcon.HTTPUnauthorized(description='Invalid token.')

class LoginResource:
    """Handles exchanging a Google ID token for our local JWT."""
    def on_post(self, req, resp):
        # Parse incoming JSON
        doc = req.media
        google_token = doc.get('google_token')

        if not google_token:
            raise falcon.HTTPBadRequest(description="Missing google_token")

        email = verify_google_token(google_token)
        if not email:
            raise falcon.HTTPUnauthorized(description="Invalid Google token")

        user = get_or_create_user(email)
        if not user:
            # The prompt requires: "Users who have never been invited by an Admin 
            # must not gain access by simply signing in"
            raise falcon.HTTPForbidden(description="User not registered or invited by an admin.")

        # Issue our session token
        session_token = generate_jwt(user)
        
        resp.status = falcon.HTTP_200
        resp.media = {
            'token': session_token,
            'user': {
                'email': user['email'],
                'role': user['role']
            }
        }

# Initialize the Falcon application
# Notice how we pass the AuthMiddleware to the app, making it global.
app = falcon.App(middleware=[
    AuthMiddleware(exempt_routes=['/api/auth/login'])
])

# Route wiring
app.add_route('/api/auth/login', LoginResource())

# --- RBAC Helper ---
def require_admin(req, resp, resource, params):
    """Falcon hook to reject non-admins before the route handler runs."""
    if req.context.user['role'] != 'admin':
        raise falcon.HTTPForbidden(description="Admin privileges required.")

def user_has_container_access(user_id: int, role: str, container_id: str) -> bool:
    """Admins see everything. Users only see assigned containers."""
    if role == 'admin':
        return True
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM user_container_access WHERE user_id = ? AND container_id = ?",
        (user_id, container_id)
    )
    return cursor.fetchone() is not None

# --- API Resources ---

class ContainerListResource:
    def on_get(self, req, resp):
        """Returns containers based on user role."""
        user = req.context.user
        all_containers = get_all_containers_summary()

        if user['role'] == 'admin':
            resp.media = all_containers
        else:
            # Filter the LXD list against the SQLite permissions table
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT container_id FROM user_container_access WHERE user_id = ?", (user['sub'],))
            allowed_ids = {row[0] for row in cursor.fetchall()}
            
            resp.media = [c for c in all_containers if c['name'] in allowed_ids]

    @falcon.before(require_admin)
    def on_post(self, req, resp):
        """Admin only: Create a new container."""
        payload = req.media
        name = payload.get('name')
        image = payload.get('image', 'ubuntu/22.04')
        limits = payload.get('limits', {})

        # Server-side validation (Security Constraint)
        if not name or type(name) is not str:
            raise falcon.HTTPBadRequest(description="Valid container name required.")
        
        # Enforce hard limits so a compromised admin account can't request 1000 cores
        ram = min(int(limits.get('ram_mb', 512)), 8192) # Max 8GB
        cpu = min(int(limits.get('cpu_cores', 1)), 4)   # Max 4 Cores

        safe_limits = {
            "ram_mb": ram,
            "cpu_cores": cpu,
            "ephemeral": bool(limits.get('ephemeral', False))
        }

        try:
            create_container(name, image, safe_limits)
            
            # Record ownership in SQLite
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO containers (id, created_by) VALUES (?, ?)", (name, req.context.user['sub']))
            conn.commit()
            
            resp.status = falcon.HTTP_201
            resp.media = {"status": "success", "message": f"Container {name} created."}
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except Exception as e:
            raise falcon.HTTPInternalServerError(description=str(e))

class ContainerMetricsResource:
    def on_get(self, req, resp, container_name):
        """Fetches TSDB historical data, downsampled for the browser."""
        user = req.context.user
        
        if not user_has_container_access(user['sub'], user['role'], container_name):
            raise falcon.HTTPForbidden(description="You do not have access to this container.")

        hours_back = int(req.get_param('hours') or 1)
        
        db = get_tsdb()
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        # Query TinyFlux
        time_query = TimeQuery() >= cutoff_time
        points = db.search(time_query)
        
        # Filter for the specific container and format for JSON
        raw_data = [
            {
                "time": p.time.isoformat(),
                "cpu": p.fields.get('cpu_usage', 0),
                "ram": p.fields.get('memory_usage', 0)
            }
            for p in points if p.tags.get('container_name') == container_name
        ]

        # Downsample: If we have > 100 points, take every Nth point to save bandwidth
        # This prevents the frontend charting library from locking up the browser
        if len(raw_data) > 100:
            step = len(raw_data) // 100
            sampled_data = raw_data[::step]
        else:
            sampled_data = raw_data

        resp.media = sampled_data

# --- Wiring the Routes ---
app.add_route('/api/containers', ContainerListResource())
app.add_route('/api/containers/{container_name}/metrics', ContainerMetricsResource())

class ContainerExecResource:
    def on_post(self, req, resp, container_name):
        """Executes a command securely inside the container namespace."""
        user = req.context.user
        
        if not user_has_container_access(user['sub'], user['role'], container_name):
            raise falcon.HTTPForbidden(description="You do not have access to this container.")

        payload = req.media
        raw_command = payload.get('command', '').strip()
        
        if not raw_command:
            raise falcon.HTTPBadRequest(description="Command cannot be empty.")

        # SECURITY: Safely split the string into an array.
        # This prevents shell injection. 'ls -l && rm -rf /' becomes ['ls', '-l', '&&', 'rm', '-rf', '/']
        # The container will just complain that the file '&&' does not exist.
        try:
            safe_command_array = shlex.split(raw_command)
        except ValueError:
            raise falcon.HTTPBadRequest(description="Malformed command string.")

        try:
            from lxd_client import execute_in_container
            
            result = execute_in_container(container_name, safe_command_array)
            
            resp.media = {
                "exit_code": result["exit_code"],
                "stdout": result["stdout"] if result["stdout"] else "",
                "stderr": result["stderr"] if result["stderr"] else ""
            }
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPInternalServerError(description=str(e))

# ... existing code ...
# Add to the bottom of app.py
app.add_route('/api/containers/{container_name}/exec', ContainerExecResource())


# Add this above your route wiring at the bottom of app.py

class UserListResource:
    @falcon.before(require_admin)
    def on_get(self, req, resp):
        """Returns all users and their assigned containers."""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, email, role, max_cpu_cores, max_ram_mb, max_disk_gb FROM users")
        users = [dict(row) for row in cursor.fetchall()]
        
        # Attach assigned containers to each user
        for u in users:
            cursor.execute("SELECT container_id FROM user_container_access WHERE user_id = ?", (u['id'],))
            u['containers'] = [row['container_id'] for row in cursor.fetchall()]
            
        resp.media = users

    @falcon.before(require_admin)
    def on_post(self, req, resp):
        """Invites a new user with resource quotas."""
        payload = req.media
        email = payload.get('email')
        role = payload.get('role', 'user')
        max_cpu = int(payload.get('max_cpu_cores', 2))
        max_ram = int(payload.get('max_ram_mb', 2048))
        
        if not email:
            raise falcon.HTTPBadRequest(description="Email is required.")
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, role, max_cpu_cores, max_ram_mb) VALUES (?, ?, ?, ?)",
                (email, role, max_cpu, max_ram)
            )
            conn.commit()
            resp.status = falcon.HTTP_201
            resp.media = {"status": "success", "message": f"User {email} invited."}
        except sqlite3.IntegrityError:
            raise falcon.HTTPConflict(description="User already exists.")

class UserContainerResource:
    @falcon.before(require_admin)
    def on_post(self, req, resp, user_id):
        """Assigns a container to a user."""
        payload = req.media
        container_id = payload.get('container_id')
        
        if not container_id:
            raise falcon.HTTPBadRequest(description="Container ID is required.")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO user_container_access (user_id, container_id) VALUES (?, ?)", 
                (user_id, container_id)
            )
            conn.commit()
            resp.status = falcon.HTTP_201
            resp.media = {"status": "success", "message": "Container assigned."}
        except sqlite3.IntegrityError:
            raise falcon.HTTPConflict(description="Container is already assigned to this user.")

    @falcon.before(require_admin)
    def on_delete(self, req, resp, user_id, container_id):
        """Revokes container access from a user."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM user_container_access WHERE user_id = ? AND container_id = ?", 
            (user_id, container_id)
        )
        conn.commit()
        resp.status = falcon.HTTP_200
        resp.media = {"status": "success"}

# --- Wiring the Routes ---
app.add_route('/api/users', UserListResource())
app.add_route('/api/users/{user_id}/containers', UserContainerResource())
app.add_route('/api/users/{user_id}/containers/{container_id}', UserContainerResource())
