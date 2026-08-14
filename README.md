Here is the complete `README.md` file as a single text block. You can click the "Copy" button in the top right corner of the code box and paste it directly into your root `README.md` file, overwriting everything currently in it.

```markdown
# LXD Monitor

A lightweight, self-hosted web dashboard for provisioning, monitoring, and managing Linux containers (LXD) on an on-premises server.

---

## Table of Contents

1. [Setup from Scratch](#setup-from-scratch)
2. [Architecture](#architecture)
3. [Data Model](#data-model)
4. [API Reference](#api-reference)
5. [Security Notes](#security-notes)
6. [Running as a Service](#running-as-a-service)
7. [Frontend Development Guide](#frontend-development-guide)

---

## Setup from Scratch

These instructions start from a fresh Ubuntu 22.04 / 24.04 machine or WSL2 environment.

### 1. Install LXD

```bash
sudo snap install lxd
sudo lxd init --auto          # creates a default storage pool and network bridge
sudo usermod -aG lxd $USER    # allow the current user to access the LXD socket
newgrp lxd                    # activate the group without logging out

```

### 2. Clone the repository

```bash
git clone [https://github.com/](https://github.com/)<your-username>/Hobby-Server-Monitor.git
cd Hobby-Server-Monitor

```

### 3. Set up the Python backend

```bash
cd Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirement.txt

# Initialise the SQLite database (creates hobby_monitor.db)
python database.py

```

### 4. Configure environment variables

```bash
cp ../.env.example .env
# Edit .env and fill in:
#   GOOGLE_CLIENT_ID
#   SESSION_SECRET  (generate with: python -c "import secrets; print(secrets.token_hex(32))")
#   BOOTSTRAP_ADMIN_EMAIL
#   ALLOWED_ORIGIN  (http://localhost:4321 for development)

```

### 5. Set up Google OAuth 2.0

1. Go to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
2. Create a new **OAuth 2.0 Client ID** (Application type: *Web application*).
3. Add `http://localhost:4321` to **Authorised JavaScript origins**.
4. Copy the Client ID into `GOOGLE_CLIENT_ID` (and `PUBLIC_GOOGLE_CLIENT_ID`) in `.env`.

### 6. Set up the Astro frontend

```bash
cd ../Frontend/frontend
npm install
cp ../../.env.example .env         # or create a .env with only the PUBLIC_ vars
# Edit .env:
#   PUBLIC_GOOGLE_CLIENT_ID=<same as backend>
#   PUBLIC_API_BASE=http://localhost:8000/api

```

### 7. Run the backend (API server + collector)

Open two terminal windows in `Backend/` with the virtualenv active:

**Terminal A — Falcon API server:**

```bash
source venv/bin/activate
export $(cat .env | xargs)         # load env vars
gunicorn app:app --bind 0.0.0.0:8000 --workers 2 --reload

```

**Terminal B — Background metrics collector:**

```bash
source venv/bin/activate
export $(cat .env | xargs)
python collector.py

```

### 8. Run the frontend

```bash
cd Frontend/frontend
npm run dev

```

Open **http://localhost:4321** in your browser. Sign in with the Google account matching `BOOTSTRAP_ADMIN_EMAIL`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (Astro SSG — static pages, client-side JS)        │
│                                                             │
│  login → Google GSI → credential sent to Falcon API        │
│  Dashboard / Container / Users / Accounting pages          │
│  fetch() + JWT in Authorization header                      │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP (CORS)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Falcon API Server (gunicorn)  :8000                        │
│                                                             │
│  AuthMiddleware (global JWT check, deny by default)        │
│  CorsMiddleware                                             │
│                                                             │
│  /api/auth/login    ── Google token verify → issue JWT     │
│  /api/containers/*  ── RBAC-gated container endpoints      │
│  /api/users/*       ── Admin-only user management          │
│  /api/admin/*       ── Accounting, host-info, audit log    │
│                                                             │
│  Uses:  SQLite (via database.py)                           │
│         TinyFlux (read metrics for chart endpoints)        │
│         pylxd  (LXD socket /var/snap/lxd/…/unix.socket)   │
└───────┬─────────────────────────────────────┬───────────────┘
        │ pylxd                               │ SQLite r/w
        ▼                                     ▼
┌───────────────┐                   ┌─────────────────────────┐
│  LXD Daemon   │                   │  hobby_monitor.db        │
│  (snapd)      │                   │  users, containers,      │
│               │                   │  user_container_access,  │
│  containers,  │                   │  audit_log               │
│  state, exec  │                   └─────────────────────────┘
└───────────────┘
        ▲
        │ pylxd (separate process)
┌───────────────────────────────────────────────────────────────┐
│  Background Collector (collector.py)                          │
│                                                               │
│  Loop every 10s:  poll all Running containers → write Point  │
│  Loop every 1h :  purge TinyFlux rows older than 7 days      │
│                                                               │
│  Writes to: metrics.csv (TinyFlux CSV store)                 │
│  Independent of API server — no browser tabs required        │
└───────────────────────────────────────────────────────────────┘

```

### Component Summary

| Component | File(s) | Role |
| --- | --- | --- |
| Falcon API | `Backend/app.py` | HTTP API, auth, RBAC, all business logic |
| Auth | `Backend/auth.py` | Google token verify, bootstrap admin, JWT issuance |
| LXD wrapper | `Backend/lxd_client.py` | pylxd calls, validation, lifecycle, exec |
| DB layer | `Backend/database.py` | SQLite schema, TinyFlux accessor, audit helper |
| Collector | `Backend/collector.py` | Standalone metrics polling process |
| Astro frontend | `Frontend/frontend/src/` | Static pages, client-side fetch, Xterm.js, uPlot |

---

## Data Model

### SQLite (`hobby_monitor.db`)

```sql
-- Users and their resource quotas
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE,
    role            TEXT    NOT NULL DEFAULT 'user'   CHECK(role IN ('admin','user')),
    max_cpu_cores   INTEGER NOT NULL DEFAULT 2,
    max_ram_mb      INTEGER NOT NULL DEFAULT 2048,
    max_disk_gb     INTEGER NOT NULL DEFAULT 20,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Containers managed through this tool (LXD is the source of truth for live state)
CREATE TABLE containers (
    id              TEXT    PRIMARY KEY,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    description     TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Access control: which user may access which container
CREATE TABLE user_container_access (
    user_id         INTEGER NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
    container_id    TEXT    NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    granted_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (user_id, container_id)
);

-- Immutable audit trail for destructive and limit-changing actions
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_email     TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    details         TEXT,        -- JSON
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

```

**Schema durability decisions:**

* `containers.id` is the LXD container name (immutable once created by LXD convention).
* `user_container_access` uses `ON DELETE CASCADE` so revoking a user or deleting a container cleans up orphaned rows automatically.
* `containers.created_by` uses `ON DELETE SET NULL` so the container record survives the creator's account being revoked.
* `audit_log` is append-only by design — no UPDATE or DELETE paths exist in the codebase.

### TinyFlux (`metrics.csv`)

TinyFlux uses a CSV file as its storage backend.

**Measurement:** `container_metrics`

| Tag | Example | Description |
| --- | --- | --- |
| `container_name` | `web-server-01` | LXD container name |

| Field | Type | Description |
| --- | --- | --- |
| `cpu_ns` | float | Cumulative CPU time in nanoseconds (monotonic) |
| `ram_bytes` | float | Current RSS memory usage in bytes |
| `disk_bytes` | float | Root device disk usage in bytes |
| `net_rx_bytes` | float | Cumulative network bytes received on eth0 |
| `net_tx_bytes` | float | Cumulative network bytes sent on eth0 |
| `process_count` | float | Number of processes in the container |

**Retention:** 7 days. The `enforce_retention()` loop wakes once per hour and removes all points older than 168 hours. At 10-second intervals with 10 containers, maximum storage is approximately 72 MB.

**Downsampling:** The metrics endpoint returns at most 200 points regardless of the requested time window (`?hours=N`). For a 7-day request at 10-second intervals, step is approximately 302 — so only 1 in 302 samples reaches the browser.

---

## API Reference

All endpoints except `/api/auth/login` require `Authorization: Bearer <JWT>`.

### Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | None | Exchange Google ID token for local JWT |

**Request:** `{ "google_token": "<Google credential>" }`
**Response:** `{ "token": "<JWT>", "user": { "email", "role", "id" } }`

### Containers

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/containers` | Any | List containers (RBAC filtered) |
| POST | `/api/containers` | Admin | Create container |
| GET | `/api/containers/{name}` | Owner/Admin | Full container detail |
| POST | `/api/containers/{name}/action` | Admin | Lifecycle action |
| PATCH | `/api/containers/{name}/limits` | Admin | Update CPU/RAM live |
| GET | `/api/containers/{name}/metrics` | Owner/Admin | TSDB history (`?hours=N`) |
| POST | `/api/containers/{name}/exec` | Owner/Admin | Run command in container |

**Container action body:** `{ "action": "start"|"stop"|"restart"|"freeze"|"unfreeze"|"delete" }`

**Container limits body:** `{ "cpu_cores": 2, "ram_mb": 1024 }` (either field optional)

**Exec body:** `{ "command": "ls -la /etc" }`
**Exec response:** `{ "exit_code": 0, "stdout": "...", "stderr": "" }`

### Users

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/users` | Admin | List all users |
| POST | `/api/users` | Admin | Invite user |
| PATCH | `/api/users/{id}` | Admin | Update role/quota |
| DELETE | `/api/users/{id}` | Admin | Revoke user |
| GET | `/api/users/{id}/quota` | Self/Admin | Quota and current usage |
| POST | `/api/users/{id}/containers` | Admin | Assign container |
| DELETE | `/api/users/{id}/containers/{cid}` | Admin | Revoke container access |

### Admin

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/admin/accounting` | Admin | Host totals + per-user allocation |
| GET | `/api/admin/host-info` | Admin | Images, pools, profiles for create form |
| GET | `/api/admin/audit` | Admin | Recent audit log (`?limit=N`) |

---

## Security Notes

### LXD privilege model

pylxd connects to the local LXD Unix socket at `/var/snap/lxd/common/lxd/unix.socket`. Membership in the `lxd` group is required. **This is equivalent to root on the host**: a member can create privileged containers, mount host paths, or use the LXD API to escape into the host namespace.

**What we did about it:**

1. `create_container()` always sets `security.privileged: false` — containers run as unprivileged (UID-mapped). This is the primary defence.
2. `security.nesting: false` by default — prevents containers running Docker/LXD inside themselves.
3. The API server runs as a non-root user that is a member of `lxd` but not `sudo`.
4. No user-controlled data ever flows into LXD container configuration without validation. Container names pass `VALID_NAME_REGEX` before any pylxd call. Resource limits are clamped to host capacity server-side.

### Terminal execution security

The exec endpoint uses `shlex.split()` to tokenise the user's command string into a list and passes it directly to `container.execute(command_list)`. pylxd's `execute()` maps to `lxc exec --`, which passes the list to the container's `execve()` — **no shell is invoked on the host**. Shell metacharacters (`&&`, `|`, `;`) are passed as literal string arguments to the first command, not interpreted by any shell.

A user can still cause harm *inside* the container (e.g., `rm -rf /`). The container provides the isolation boundary. If a container is destroyed by a user command, the container is gone — the host is unaffected.

Known limitation: there is no allowlist of commands. An authenticated user with terminal access can run anything the container's init will accept. This is intentional for operational flexibility; production deployments should consider restricting via LXD profiles or seccomp.

### Authentication & session management

* Google ID tokens are verified via `google-auth`'s `verify_oauth2_token` against Google's public keys.
* Sessions are stateless JWTs (HS256, 12h TTL). Logout deletes the token from localStorage. The backend has no session store — a revoked JWT remains valid until expiry. This is a deliberate trade-off for simplicity; 12 hours is the maximum exposure window.
* The bootstrap admin mechanism: set `BOOTSTRAP_ADMIN_EMAIL` in the environment. On the first sign-in by that email, the row is created. Subsequent sign-ins return the existing row — no re-promotion is possible. An attacker who can set the env var already has shell access to the host and the attack surface is moot.

### Authorization architecture

Every request passes through `AuthMiddleware` before reaching any handler. Routes are **denied by default** — the middleware rejects everything except explicitly exempted paths. Adding a new endpoint cannot accidentally skip auth; it must be explicitly added to `exempt_routes` to opt out. Admin-only endpoints additionally use `@falcon.before(require_admin)` as a second check.

---

## Running as a Service

To ensure operational readiness, this repository includes pre-configured systemd service files. You do not need to write these manually.

**1. Copy the provided service files from the deployment folder:**

```bash
sudo cp deployment/lxd-monitor-api.service /etc/systemd/system/
sudo cp deployment/lxd-monitor-collector.service /etc/systemd/system/

```

**2. Reload systemd and enable the services to start on boot:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lxd-monitor-api lxd-monitor-collector
sudo systemctl status lxd-monitor-api lxd-monitor-collector

```

### Continuous Integration (CI/CD)

This project includes an automated GitHub Actions pipeline located in `.github/workflows/ci.yml`. On every push to the `main` branch, the pipeline boots an Ubuntu runner to:

1. Validate the Astro SSG build (Node 22).
2. Perform syntax checks across the Python Falcon backend.

### Production Deployment

For a full production environment, build the Astro frontend (`npm run build`) and serve the resulting `dist/` directory using a reverse proxy like Nginx or Caddy. Configure the proxy to route `/api/*` requests to the Falcon API running on `localhost:8000`.

---

## Frontend Development Guide

### Project Structure

Inside of the Astro project (`Frontend/frontend/`), you'll see the following folders and files:

```text
/
├── public/
├── src/
│   └── pages/    
│       ├── index.astro
│       ├── login.astro
│       ├── users.astro
│       ├── accounting.astro
│       ├── create.astro
│       └── container/
│            └── [name].astro
│
└── package.json

```

Astro looks for `.astro` or `.md` files in the `src/pages/` directory. Each page is exposed as a route based on its file name. Any static assets, like images, can be placed in the `public/` directory.

### Commands

All commands are run from the `Frontend/frontend/` root of the project via terminal:

| Command | Action |
| --- | --- |
| `npm install` | Installs dependencies |
| `npm run dev` | Starts local dev server at `localhost:4321` |
| `npm run build` | Build your production site to `./dist/` |
| `npm run preview` | Preview your build locally, before deploying |
| `npm run astro ...` | Run CLI commands like `astro add`, `astro check` |
| `npm run astro -- --help` | Get help using the Astro CLI |

### Development

When starting the dev server, you can use background mode:

```bash
astro dev --background

```

Manage the background server with `astro dev stop`, `astro dev status`, and `astro dev logs`.

### Documentation

Full documentation: https://docs.astro.build

Consult these guides before working on related tasks:

* [Adding pages, dynamic routes, or middleware](https://docs.astro.build/en/guides/routing/)
* [Working with Astro components](https://docs.astro.build/en/basics/astro-components/)
* [Using React, Vue, Svelte, or other framework components](https://docs.astro.build/en/guides/framework-components/)
* [Adding or managing content](https://docs.astro.build/en/guides/content-collections/)
* [Adding styles or using Tailwind](https://docs.astro.build/en/guides/styling/)
* [Supporting multiple languages](https://docs.astro.build/en/guides/internationalization/)
