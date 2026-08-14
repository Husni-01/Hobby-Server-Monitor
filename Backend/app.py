"""
app.py — Falcon WSGI application for the LXD Monitor backend.

Run with:
    gunicorn app:app --bind 0.0.0.0:8000 --workers 2

Authorization model:
  Every route passes through AuthMiddleware before the handler runs.
  The middleware attaches req.context.user on success.
  Admin-only endpoints use the @falcon.before(require_admin) hook.
  This makes it structurally impossible to add a new endpoint and forget
  to add auth — you have to explicitly opt out.

CORS:
  The CorsMiddleware allows the Astro dev server origin and the production
  origin. Set ALLOWED_ORIGIN in .env (defaults to http://localhost:4321).
"""

import falcon
from dotenv import load_dotenv
load_dotenv()
import jwt
import os
import json
import sqlite3
import shlex
from datetime import datetime, timedelta, timezone

from auth import verify_google_token, get_or_create_user, generate_jwt
from database import DB_PATH, get_tsdb, get_db, init_db, write_audit
from lxd_client import (
    get_all_containers_summary,
    get_container_detail,
    create_container,
    perform_lifecycle_action,
    delete_container,
    update_container_limits,
    execute_in_container,
    get_host_resources,
    get_storage_pools,
    get_network_profiles,
    get_available_images,
)
from tinyflux import TimeQuery

# ── Configuration ──────────────────────────────────────────────────────────────
SESSION_SECRET  = os.environ.get("SESSION_SECRET", "fallback-dev-secret-change-me")
ALLOWED_ORIGIN  = os.environ.get("ALLOWED_ORIGIN", "http://localhost:4321")

# Initialise the database on startup (no-op if tables already exist)
init_db()


# ── Middleware ─────────────────────────────────────────────────────────────────

class CorsMiddleware:
    """
    Adds CORS headers so the Astro frontend can reach this Falcon server.
    Only the configured origin is allowed — not a wildcard.
    """
    def process_request(self, req, resp):
        resp.set_header("Access-Control-Allow-Origin",  ALLOWED_ORIGIN)
        resp.set_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        resp.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        resp.set_header("Access-Control-Max-Age",       "3600")

        if req.method == "OPTIONS":
            raise falcon.HTTPStatus(falcon.HTTP_204)

    def process_response(self, req, resp, resource, req_succeeded):
        resp.set_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)


class AuthMiddleware:
    """
    Global middleware — every request is authenticated unless the route is
    explicitly listed in exempt_routes. Adding a new endpoint and forgetting
    to include auth is not possible: the middleware rejects it by default.
    """
    def __init__(self, exempt_routes=None):
        self.exempt_routes = set(exempt_routes or [])

    def process_request(self, req, resp):
        if req.method == "OPTIONS":
            return
        if req.path in self.exempt_routes:
            return

        auth_header = req.get_header("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise falcon.HTTPUnauthorized(description="Missing or invalid authorization token.")

        token = auth_header.split(" ", 1)[1]
        try:
            decoded = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
            req.context.user = decoded
        except jwt.ExpiredSignatureError:
            raise falcon.HTTPUnauthorized(description="Session expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise falcon.HTTPUnauthorized(description="Invalid token.")


# ── RBAC helpers ───────────────────────────────────────────────────────────────
def require_admin(req, resp, resource, params):
    """Falcon before-hook: rejects non-admins before the handler runs."""
    if req.context.user.get("role") != "admin":
        raise falcon.HTTPForbidden(description="Administrator privileges required.")


def user_has_container_access(user_id: int, role: str, container_id: str) -> bool:
    """Returns True if the user may access the named container."""
    if role == "admin":
        return True
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM user_container_access WHERE user_id = ? AND container_id = ?",
        (user_id, container_id)
    )
    result = cursor.fetchone() is not None
    conn.close()
    return result


# ── Quota helpers ──────────────────────────────────────────────────────────────
def get_user_quota(user_id: int) -> dict:
    """Returns the resource quota and current allocation for a user."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT max_cpu_cores, max_ram_mb, max_disk_gb FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {}
    quota = dict(row)

    # Current allocations: sum config values of all assigned containers in LXD
    cursor.execute(
        "SELECT container_id FROM user_container_access WHERE user_id = ?",
        (user_id,)
    )
    assigned = [r["container_id"] for r in cursor.fetchall()]
    conn.close()

    total_cpu = 0
    total_ram = 0
    total_disk = 0
    if assigned:
        try:
            from pylxd import Client
            lxd = Client()
            for cname in assigned:
                try:
                    c = lxd.containers.get(cname)
                    cfg = c.config
                    cpu_str = cfg.get("limits.cpu", "0")
                    try:
                        total_cpu += int(cpu_str.split(",")[0]) if cpu_str else 0
                    except ValueError:
                        pass
                    ram_str = cfg.get("limits.memory", "0MB")
                    if ram_str.endswith("MB"):
                        total_ram += int(ram_str[:-2])
                    elif ram_str.endswith("GB"):
                        total_ram += int(ram_str[:-2]) * 1024
                except Exception:
                    pass
        except Exception:
            pass

    quota["used_cpu_cores"] = total_cpu
    quota["used_ram_mb"]    = total_ram
    quota["used_disk_gb"]   = total_disk
    return quota


def check_quota(user_id: int, role: str, new_cpu: int, new_ram_mb: int, new_disk_gb: int = 0):
    """
    Raises HTTPForbidden if adding the requested resources would exceed the user's quota.
    Admins are exempt.
    """
    if role == "admin":
        return
    quota = get_user_quota(user_id)
    if not quota:
        return

    if new_cpu and (quota.get("used_cpu_cores", 0) + new_cpu) > quota.get("max_cpu_cores", 99):
        raise falcon.HTTPForbidden(
            description=f"CPU quota exceeded: you have {quota['max_cpu_cores'] - quota['used_cpu_cores']} cores remaining."
        )
    if new_ram_mb and (quota.get("used_ram_mb", 0) + new_ram_mb) > quota.get("max_ram_mb", 99999):
        remaining = quota["max_ram_mb"] - quota["used_ram_mb"]
        raise falcon.HTTPForbidden(
            description=f"RAM quota exceeded: you have {remaining} MB remaining."
        )
    if new_disk_gb and (quota.get("used_disk_gb", 0) + new_disk_gb) > quota.get("max_disk_gb", 9999):
        remaining = quota["max_disk_gb"] - quota["used_disk_gb"]
        raise falcon.HTTPForbidden(
            description=f"Disk quota exceeded: you have {remaining} GB remaining."
        )


# ── API Resources ──────────────────────────────────────────────────────────────

class LoginResource:
    """POST /api/auth/login — exchange a Google ID token for a local JWT."""
    def on_post(self, req, resp):
        doc = req.media
        google_token = doc.get("google_token")
        if not google_token:
            raise falcon.HTTPBadRequest(description="Missing google_token.")

        email = verify_google_token(google_token)
        if not email:
            raise falcon.HTTPUnauthorized(description="Invalid Google token.")

        user = get_or_create_user(email)
        if not user:
            raise falcon.HTTPForbidden(description="Access denied. You must be invited by an administrator.")

        session_token = generate_jwt(user)
        resp.media = {
            "token": session_token,
            "user": {"email": user["email"], "role": user["role"], "id": user["id"]},
        }


class ContainerListResource:
    def on_get(self, req, resp):
        """GET /api/containers — list containers (role-filtered)."""
        user = req.context.user
        all_containers = get_all_containers_summary()

        if user["role"] == "admin":
            resp.media = all_containers
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT container_id FROM user_container_access WHERE user_id = ?",
                (user["sub"],)
            )
            allowed_ids = {row["container_id"] for row in cursor.fetchall()}
            conn.close()
            resp.media = [c for c in all_containers if c.get("name") in allowed_ids]

    @falcon.before(require_admin)
    def on_post(self, req, resp):
        """POST /api/containers — create a new container (admin only)."""
        payload = req.media
        name  = (payload.get("name") or "").strip()
        image = payload.get("image", "ubuntu/22.04")

        if not name:
            raise falcon.HTTPBadRequest(description="Container name is required.")

        limits = payload.get("limits", {})
        cpu_cores  = int(limits.get("cpu_cores", 1))
        ram_mb     = int(limits.get("ram_mb", 512))
        disk_gb    = int(limits.get("disk_gb", 0))
        cpu_allowance = limits.get("cpu_allowance", "")

        # ── Server-side quota enforcement ──────────────────────────────────────
        check_quota(req.context.user["sub"], req.context.user["role"], cpu_cores, ram_mb, disk_gb)

        # ── Retrieve host caps and clamp values ────────────────────────────────
        host = get_host_resources()
        cpu_cores = min(cpu_cores, host.get("cpu_cores", 64))
        ram_mb    = min(ram_mb,    host.get("ram_mb",    131072))

        safe_limits = {
            "cpu_cores":    cpu_cores,
            "cpu_allowance": cpu_allowance,
            "ram_mb":       ram_mb,
            "disk_gb":      disk_gb if disk_gb > 0 else None,
            "ephemeral":    bool(limits.get("ephemeral", False)),
            "autostart":    bool(limits.get("autostart", True)),
            "pool":         limits.get("pool", "default"),
            "profiles":     limits.get("profiles", ["default"]),
            "description":  payload.get("description", ""),
        }

        try:
            create_container(name, image, safe_limits)

            conn = get_db()
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO containers (id, created_by, description) VALUES (?, ?, ?)",
                    (name, req.context.user["sub"], payload.get("description", ""))
                )
                conn.commit()
            finally:
                conn.close()

            write_audit(
                actor_email=req.context.user["email"],
                action="container.create",
                target=name,
                details={"image": image, "limits": safe_limits},
            )

            resp.status = falcon.HTTP_201
            resp.media  = {"status": "success", "message": f"Container '{name}' created."}
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPInternalServerError(description=str(e))


class ContainerDetailResource:
    def on_get(self, req, resp, container_name):
        """GET /api/containers/{name} — full detail for one container."""
        user = req.context.user
        if not user_has_container_access(user["sub"], user["role"], container_name):
            raise falcon.HTTPForbidden(description="You do not have access to this container.")
        try:
            resp.media = get_container_detail(container_name)
        except ValueError as e:
            raise falcon.HTTPNotFound(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPServiceUnavailable(description=str(e))


class ContainerActionResource:
    @falcon.before(require_admin)
    def on_post(self, req, resp, container_name):
        """POST /api/containers/{name}/action — lifecycle actions (admin only)."""
        action = (req.media.get("action") or "").strip().lower()
        if not action:
            raise falcon.HTTPBadRequest(description="'action' field is required.")

        if action == "delete":
            try:
                # Delete is handled separately to avoid name collision
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT container_id FROM user_container_access WHERE container_id = ?",
                    (container_name,)
                )
                has_users = cursor.fetchone() is not None
                conn.close()

                write_audit(
                    actor_email=req.context.user["email"],
                    action="container.delete",
                    target=container_name,
                    details={"had_users": has_users},
                )
                result = delete_container(container_name)

                # Remove from our DB (CASCADE will clean up user_container_access)
                conn = get_db()
                conn.execute("DELETE FROM containers WHERE id = ?", (container_name,))
                conn.commit()
                conn.close()

                resp.media = result
            except ValueError as e:
                raise falcon.HTTPNotFound(description=str(e))
            except RuntimeError as e:
                raise falcon.HTTPInternalServerError(description=str(e))
            return

        try:
            result = perform_lifecycle_action(container_name, action)
            write_audit(
                actor_email=req.context.user["email"],
                action=f"container.{action}",
                target=container_name,
            )
            resp.media = result
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPInternalServerError(description=str(e))


class ContainerLimitsResource:
    @falcon.before(require_admin)
    def on_patch(self, req, resp, container_name):
        """PATCH /api/containers/{name}/limits — update limits live (admin only)."""
        payload = req.media
        limits  = {}
        if "cpu_cores" in payload:
            limits["cpu_cores"] = int(payload["cpu_cores"])
        if "cpu_allowance" in payload:
            limits["cpu_allowance"] = str(payload["cpu_allowance"])
        if "ram_mb" in payload:
            limits["ram_mb"] = int(payload["ram_mb"])

        if not limits:
            raise falcon.HTTPBadRequest(description="No limits provided to update.")

        try:
            # Get current limits for audit trail
            from pylxd import Client
            lxd_c = Client()
            c = lxd_c.containers.get(container_name)
            before = {
                "cpu": c.config.get("limits.cpu", ""),
                "ram": c.config.get("limits.memory", ""),
            }
        except Exception:
            before = {}

        try:
            result = update_container_limits(container_name, limits)
            write_audit(
                actor_email=req.context.user["email"],
                action="container.limits.update",
                target=container_name,
                details={"before": before, "after": limits},
            )
            resp.media = result
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPInternalServerError(description=str(e))


class ContainerMetricsResource:
    def on_get(self, req, resp, container_name):
        """GET /api/containers/{name}/metrics — downsampled TSDB data."""
        user = req.context.user
        if not user_has_container_access(user["sub"], user["role"], container_name):
            raise falcon.HTTPForbidden(description="You do not have access to this container.")

        hours_back   = max(1, min(int(req.get_param("hours") or 1), 168))
        cutoff_time  = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        db     = get_tsdb()
        tq     = TimeQuery() >= cutoff_time
        points = db.search(tq)

        raw_data = [
            {
                "time":      p.time.isoformat(),
                "cpu_ns":    p.fields.get("cpu_ns", 0),
                "ram_bytes": p.fields.get("ram_bytes", 0),
                "disk_bytes":p.fields.get("disk_bytes", 0),
                "net_rx":    p.fields.get("net_rx_bytes", 0),
                "net_tx":    p.fields.get("net_tx_bytes", 0),
                "processes": p.fields.get("process_count", 0),
            }
            for p in points
            if p.tags.get("container_name") == container_name
               and p.measurement == "container_metrics"
        ]

        # Downsample to ≤200 points regardless of the time window
        if len(raw_data) > 200:
            step = len(raw_data) // 200
            raw_data = raw_data[::step]

        resp.media = raw_data


class ContainerExecResource:
    def on_post(self, req, resp, container_name):
        """POST /api/containers/{name}/exec — run a command inside the container."""
        user = req.context.user
        if not user_has_container_access(user["sub"], user["role"], container_name):
            raise falcon.HTTPForbidden(description="You do not have access to this container.")

        raw_command = (req.media.get("command") or "").strip()
        if not raw_command:
            raise falcon.HTTPBadRequest(description="Command cannot be empty.")

        try:
            safe_command = shlex.split(raw_command)
        except ValueError:
            raise falcon.HTTPBadRequest(description="Malformed command string.")

        try:
            result = execute_in_container(container_name, safe_command)
            resp.media = result
        except ValueError as e:
            raise falcon.HTTPBadRequest(description=str(e))
        except RuntimeError as e:
            raise falcon.HTTPInternalServerError(description=str(e))


# ── User management ────────────────────────────────────────────────────────────

class UserListResource:
    @falcon.before(require_admin)
    def on_get(self, req, resp):
        """GET /api/users — list all users with their assigned containers."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, role, max_cpu_cores, max_ram_mb, max_disk_gb, created_at FROM users"
        )
        users = [dict(row) for row in cursor.fetchall()]

        for u in users:
            cursor.execute(
                "SELECT container_id FROM user_container_access WHERE user_id = ?",
                (u["id"],)
            )
            u["containers"] = [row["container_id"] for row in cursor.fetchall()]

        conn.close()
        resp.media = users

    @falcon.before(require_admin)
    def on_post(self, req, resp):
        """POST /api/users — invite a new user with a resource quota."""
        payload     = req.media
        email       = (payload.get("email") or "").strip()
        role        = payload.get("role", "user")
        max_cpu     = int(payload.get("max_cpu_cores", 2))
        max_ram     = int(payload.get("max_ram_mb", 2048))
        max_disk    = int(payload.get("max_disk_gb", 20))

        if not email:
            raise falcon.HTTPBadRequest(description="Email is required.")
        if role not in ("admin", "user"):
            raise falcon.HTTPBadRequest(description="Role must be 'admin' or 'user'.")

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (email, role, max_cpu_cores, max_ram_mb, max_disk_gb) VALUES (?, ?, ?, ?, ?)",
                (email, role, max_cpu, max_ram, max_disk)
            )
            conn.commit()
            resp.status = falcon.HTTP_201
            resp.media  = {"status": "success", "message": f"User '{email}' invited."}
        except sqlite3.IntegrityError:
            raise falcon.HTTPConflict(description="A user with that email already exists.")
        finally:
            conn.close()


class UserDetailResource:
    @falcon.before(require_admin)
    def on_patch(self, req, resp, user_id):
        """PATCH /api/users/{id} — update role or quota."""
        payload = req.media
        updates = []
        values  = []

        if "role" in payload:
            role = payload["role"]
            if role not in ("admin", "user"):
                raise falcon.HTTPBadRequest(description="Role must be 'admin' or 'user'.")
            updates.append("role = ?")
            values.append(role)
        if "max_cpu_cores" in payload:
            updates.append("max_cpu_cores = ?")
            values.append(int(payload["max_cpu_cores"]))
        if "max_ram_mb" in payload:
            updates.append("max_ram_mb = ?")
            values.append(int(payload["max_ram_mb"]))
        if "max_disk_gb" in payload:
            updates.append("max_disk_gb = ?")
            values.append(int(payload["max_disk_gb"]))

        if not updates:
            raise falcon.HTTPBadRequest(description="No fields to update.")

        values.append(int(user_id))
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            values
        )
        if cursor.rowcount == 0:
            conn.close()
            raise falcon.HTTPNotFound(description="User not found.")
        conn.commit()
        conn.close()
        resp.media = {"status": "success"}

    @falcon.before(require_admin)
    def on_delete(self, req, resp, user_id):
        """DELETE /api/users/{id} — revoke a user entirely."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = ?", (int(user_id),))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise falcon.HTTPNotFound(description="User not found.")

        conn.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
        conn.commit()
        conn.close()

        write_audit(
            actor_email=req.context.user["email"],
            action="user.revoke",
            target=row["email"],
        )
        resp.media = {"status": "success", "message": f"User '{row['email']}' revoked."}


class UserContainerResource:
    @falcon.before(require_admin)
    def on_post(self, req, resp, user_id):
        """POST /api/users/{id}/containers — assign a container to a user."""
        container_id = (req.media.get("container_id") or "").strip()
        if not container_id:
            raise falcon.HTTPBadRequest(description="container_id is required.")

        conn = get_db()
        try:
            # Ensure the container row exists in our DB before assigning
            conn.execute(
                "INSERT OR IGNORE INTO containers (id, created_by) VALUES (?, NULL)",
                (container_id,)
            )
            conn.execute(
                "INSERT INTO user_container_access (user_id, container_id) VALUES (?, ?)",
                (int(user_id), container_id)
            )
            conn.commit()
            resp.status = falcon.HTTP_201
            resp.media  = {"status": "success", "message": "Container assigned."}
        except sqlite3.IntegrityError:
            raise falcon.HTTPConflict(description="Container already assigned to this user.")
        finally:
            conn.close()

    @falcon.before(require_admin)
    def on_delete(self, req, resp, user_id, container_id):
        """DELETE /api/users/{id}/containers/{cid} — revoke container access."""
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM user_container_access WHERE user_id = ? AND container_id = ?",
            (int(user_id), container_id)
        )
        if cursor.rowcount == 0:
            conn.close()
            raise falcon.HTTPNotFound(description="Assignment not found.")
        conn.commit()
        conn.close()
        resp.media = {"status": "success"}


class UserQuotaResource:
    def on_get(self, req, resp, user_id):
        """GET /api/users/{id}/quota — quota and current usage (own or admin)."""
        caller = req.context.user
        if caller["role"] != "admin" and caller["sub"] != int(user_id):
            raise falcon.HTTPForbidden(description="You may only view your own quota.")
        quota = get_user_quota(int(user_id))
        resp.media = quota


# ── Admin: Accounting and Host Info ───────────────────────────────────────────

class AccountingResource:
    @falcon.before(require_admin)
    def on_get(self, req, resp):
        """GET /api/admin/accounting — host totals and per-user allocation."""
        host = get_host_resources()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, max_cpu_cores, max_ram_mb, max_disk_gb FROM users"
        )
        users = [dict(row) for row in cursor.fetchall()]

        per_user = []
        for u in users:
            cursor.execute(
                "SELECT container_id FROM user_container_access WHERE user_id = ?",
                (u["id"],)
            )
            assigned_containers = [r["container_id"] for r in cursor.fetchall()]
            quota_info = get_user_quota(u["id"])
            per_user.append({
                "email":          u["email"],
                "max_cpu_cores":  u["max_cpu_cores"],
                "max_ram_mb":     u["max_ram_mb"],
                "max_disk_gb":    u["max_disk_gb"],
                "used_cpu_cores": quota_info.get("used_cpu_cores", 0),
                "used_ram_mb":    quota_info.get("used_ram_mb", 0),
                "used_disk_gb":   quota_info.get("used_disk_gb", 0),
                "container_count": len(assigned_containers),
            })

        conn.close()
        resp.media = {
            "host": host,
            "per_user": per_user,
        }


class HostInfoResource:
    @falcon.before(require_admin)
    def on_get(self, req, resp):
        """GET /api/admin/host-info — images, pools, and profiles for the create form."""
        resp.media = {
            "host":     get_host_resources(),
            "images":   get_available_images(),
            "pools":    get_storage_pools(),
            "profiles": get_network_profiles(),
        }


class AuditLogResource:
    @falcon.before(require_admin)
    def on_get(self, req, resp):
        """GET /api/admin/audit — recent audit log entries."""
        limit = min(int(req.get_param("limit") or 100), 500)
        conn  = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        resp.media = rows


# ── Application assembly ───────────────────────────────────────────────────────
app = falcon.App(middleware=[
    CorsMiddleware(),
    AuthMiddleware(exempt_routes=["/api/auth/login"]),
])

# Auth
app.add_route("/api/auth/login", LoginResource())

# Containers
app.add_route("/api/containers",                    ContainerListResource())
app.add_route("/api/containers/{container_name}",   ContainerDetailResource())
app.add_route("/api/containers/{container_name}/action",  ContainerActionResource())
app.add_route("/api/containers/{container_name}/limits",  ContainerLimitsResource())
app.add_route("/api/containers/{container_name}/metrics", ContainerMetricsResource())
app.add_route("/api/containers/{container_name}/exec",    ContainerExecResource())

# Users
app.add_route("/api/users",               UserListResource())
app.add_route("/api/users/{user_id}",     UserDetailResource())
app.add_route("/api/users/{user_id}/quota",              UserQuotaResource())
app.add_route("/api/users/{user_id}/containers",         UserContainerResource())
app.add_route("/api/users/{user_id}/containers/{container_id}", UserContainerResource())

# Admin
app.add_route("/api/admin/accounting", AccountingResource())
app.add_route("/api/admin/host-info",  HostInfoResource())
app.add_route("/api/admin/audit",      AuditLogResource())
