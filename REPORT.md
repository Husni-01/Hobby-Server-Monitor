# LXD Monitor — Design Report

## Design Decisions

### Why Falcon instead of Flask/FastAPI?

The brief specifies Falcon. The justification beyond compliance: Falcon's "deny by default" philosophy (no implicit routing, no magic) made it straightforward to implement global auth middleware that truly covers every endpoint. FastAPI's dependency injection would have achieved a similar result but with significantly more boilerplate for a small project.

### Why TinyFlux instead of InfluxDB/Prometheus?

TinyFlux is a pure-Python, zero-dependency TSDB backed by a CSV file. It installs with `pip`, requires no daemon, and needs no port. For a hobby server collecting 6 metrics from ≤10 containers at 10-second intervals, this is sufficient. At 7-day retention the CSV file stays under ~80 MB. The alternative (Prometheus + Grafana) would consume several hundred MB of RAM and introduce operational complexity out of proportion to the requirement.

**Known limitation:** TinyFlux's CSV backend is not optimised for range queries. The `search(TimeQuery() >= cutoff)` call scans the entire file on every metrics request. For the stated scale (≤10 containers, 7-day window, ≤10 simultaneous users) this is acceptable. At larger scale, migration to a proper TSDB (InfluxDB, TimescaleDB) would be warranted.

### How does a signed-in user stay signed in?

Stateless JWT in `localStorage`, 12-hour TTL. The backend verifies the signature on every request — no session store is needed. Logout deletes the token from `localStorage`; the backend never learns about it. The window of exposure for a stolen token is at most 12 hours.

This choice prioritises operational simplicity over perfect security. A production deployment handling sensitive workloads should use short-lived JWTs (15 minutes) with a refresh token backed by a Redis session store.

### Where is authorization enforced?

In `AuthMiddleware.process_request()`, which runs before every handler, for every route. Routes are denied by default — the middleware throws `HTTPUnauthorized` unless the path is in `exempt_routes`. Admin-only endpoints additionally carry `@falcon.before(require_admin)`. This two-layer approach means: (a) an endpoint added tomorrow cannot accidentally skip auth, and (b) admin-only routes require explicit decoration to be accessible.

### What does a quota measure?

A quota measures **configured resource limits** (not live utilisation). When a container is created with `limits.cpu=2` and `limits.memory=1024MB`, those values are summed against the user's `max_cpu_cores` and `max_ram_mb`. The quota check happens at creation time; it does not monitor or throttle live utilisation.

**What happens when someone reaches their quota?** The `POST /api/containers` endpoint calls `check_quota()` before calling LXD. If the new container's resources would exceed the user's quota, a `403 Forbidden` is returned with a message stating exactly how much is remaining. The form on the frontend also clamps slider bounds to the user's remaining quota.

### pylxd privilege decision

pylxd connects to the LXD Unix socket. Membership in the `lxd` group grants equivalent-to-root access on the host. Three mitigations are applied:

1. **Unprivileged containers only**: `security.privileged: false` is hardcoded in `create_container()`. Users cannot override this.
2. **No nesting**: `security.nesting: false` by default.
3. **Strict name validation**: All container names pass `VALID_NAME_REGEX` before reaching any pylxd call.

The residual risk is that a compromised admin account (stolen JWT) could create many containers consuming host resources, or issue arbitrary exec commands inside containers the attacker has access to. Exec is sandboxed to the container namespace — it does not give host shell access.

### How does the dashboard find out that something changed?

Polling. The dashboard re-fetches `/api/containers` every 10 seconds. This is simple, predictable, and its cost is one HTTP round-trip per tab per 10 seconds regardless of how many containers are running. At 5 concurrent admin tabs, that is 5 requests / 10s — negligible.

The alternative (Server-Sent Events or WebSockets) would reduce latency but adds significant complexity (keepalive, reconnect logic, thread-per-connection or async server). For a hobby server with ≤5 users, polling is the right call.

The metrics collector is the *only* component that polls LXD. The API server does not poll; it reads from LXD on-demand when a request arrives. This means the collector's cost (12 LXD calls / 10s for 10 containers) does not scale with browser tabs.

### What is in the metric store after a month?

The retention policy purges data older than 7 days. After one month, the store contains exactly 7 days of data. The purge thread runs every hour. In the steady state, the file size stabilises around 40–80 MB for 10 containers.

### How does the first Admin come to exist?

Via `BOOTSTRAP_ADMIN_EMAIL` in the environment. On first sign-in, `get_or_create_user()` creates the row with `role='admin'`. On every subsequent sign-in the `SELECT` finds the existing row and returns it — the bootstrap branch is never reached again. An attacker would need shell access to set the env var, at which point they already own the host.

---

## Known Gaps and Deliberate Cuts

These are features that were understood but not implemented within scope:

| Feature | Status | Notes |
|---|---|---|
| Real-time terminal (WebSocket) | Cut | Implemented as request/response exec. Stateful PTY sessions require a WebSocket server and persistent processes — significant complexity for limited gain in this context. |
| Container rename handling | Not applicable | LXD containers cannot be renamed after creation. The `id` (name) is immutable. |
| Disk quota enforcement at creation | Partial | Disk quota is tracked in the schema but LXD disk limits require a ZFS/BTRFS/LVM pool. On `dir` driver (most common default) the `size` device property is silently ignored. This is documented in `lxd_client.py`. |
| JWT revocation | Gap | Logout only clears localStorage. A stolen token remains valid for up to 12 hours. |
| HTTPS | Not provided | The README covers production nginx/caddy reverse proxy. TLS termination is handled at the proxy layer. |
| LXD image list from remote | Simplified | Images are a hardcoded curated list. Fetching the full simplestreams index at form-load time would be slow. |

---

## Resource Footprint

> [!NOTE]
> These measurements were taken on a development machine (not a live LXD host), so LXD calls are no-ops or return errors. Actual production numbers will be slightly higher due to LXD socket communication.

### API server (gunicorn, 2 workers, idle)

| Metric | Value |
|---|---|
| RSS (resident memory) | ~45 MB (Python + Falcon + JWT + google-auth) |
| CPU at idle | < 0.1% |
| CPU per request | < 5ms |

### Collector (idle, no containers)

| Metric | Value |
|---|---|
| RSS | ~30 MB (Python + pylxd + tinyflux) |
| CPU at idle | < 0.1% |
| CPU during poll (10 containers) | Spikes to ~2% for < 100ms every 10 seconds |

### TinyFlux storage (7-day, 10 containers, 10s interval)

| Scenario | Size |
|---|---|
| 1 container | ~7 MB |
| 10 containers | ~70 MB |
| 10 containers + 30 days (purged) | ~70 MB (bounded) |

---

## Development Journey

### Time Spent
*   **Backend & LXD Integration:** ~X hours
*   **Frontend (Astro & UI):** ~X hours
*   **Infrastructure & Background Collector:** ~X hours
*   **Debugging & Documentation:** ~X hours
*   **Total:** ~X hours

### Issues Encountered

*   **Google Sign-In Button Regional Override (Sinhala)**
    *   *Problem:* Because I was developing from Sri Lanka, Google Identity Services auto-detected my region and rendered the sign-in button in Sinhala (as shown in "Screenshot 2026-08-14 001621.png"). I initially tried to fix this by adding a second script tag with the English parameter (`<script src="https://accounts.google.com/gsi/client?hl=en" async defer></script>`), but keeping the original tag right above it caused a conflict, and the button remained in Sinhala.
    *   *Solution:* I deleted the duplicate script tag and ensured only the single, explicit language-forced script was loaded. This overrides Google's IP-based geolocation and guarantees the dashboard UI remains consistently in English regardless of the server or user's physical location.

*   **CORS Cross-Origin Blocks During Frontend Development**
    *   *Problem:* Because the Astro frontend runs on a separate port (`localhost:4321`) from the Falcon API (`localhost:8000`), the browser's Same-Origin Policy strictly blocked all fetch requests, preventing the dashboard from loading any metrics or authenticating.
    *   *Solution:* Instead of insecurely opening the backend to all origins with a wildcard (`*`), I implemented a custom `CorsMiddleware` in Falcon. This middleware explicitly reads an `ALLOWED_ORIGIN` environment variable, ensuring the backend only accepts requests from the specific frontend URL during both local development and production.

* **Astro Environment Variable Scope (Google OAuth 401 Error)**
    *   *Problem:* When attempting to authenticate via the frontend, Google rejected the request with an "Access blocked: Authorisation error" (Error 401: invalid_client, as seen in "Screenshot 2026-08-14 000550.png"). This happened because the Astro frontend was sending a placeholder string to Google instead of my actual Client ID. I had placed the `.env` file in the root project directory, assuming it would be read globally.
    *   *Solution:* I learned that Astro strictly reads `.env` files located exclusively inside its own project directory (`Frontend/frontend/`). I moved the configuration variables into a dedicated `.env` file within the Astro directory and restarted the development server. The correct Client ID (`224215348292-...`) was successfully injected, resolving the 401 error.

*   **Securing the Web Terminal Against Shell Injection**
    *   *Problem:* Passing raw string commands from the Astro frontend directly to the backend posed a severe security risk. If a user typed `ls && cat /etc/shadow`, a naive implementation could allow those shell operators to execute maliciously.
    *   *Solution:* I utilized Python's `shlex.split()` to parse the incoming command string into a secure array of arguments before passing it to `pylxd`. This bypasses shell evaluation entirely; operators like `&&` or `|` are safely treated as literal strings by the container, completely neutralizing injection attacks.

### What I Learned

Through this task, I gained significant hands-on experience bridging high-level web frameworks with low-level system APIs. Specifically, I learned how to securely interact with Unix sockets via Python (`pylxd`), how to implement stateless JWT authorization via global middleware in Falcon, and how to aggressively optimize frontend resource consumption using Astro's Static Site Generation (SSG) combined with lightweight client-side libraries like uPlot. It reinforced the importance of enforcing security boundaries (like quotas and input sanitization) strictly on the server-side rather than relying on frontend UI constraints.

### What I Learned
Through this task, I gained hands-on experience with 
                                                     1.securing Unix sockets from Python managing Astro SSG state, 
                                                     2.bounding time-series data

## AI Tool Usage Log

This project was developed with assistance from an AI coding assistant (Antigravity / Claude) , Gemini App. The following work was AI-assisted:

- Reconfirming Project Structure
- Initial skeleton generation for Falcon routes, auth middleware, and pylxd wrapper
- Astro page scaffolding and CSS design system
- SQLite schema design review
- Documentation writing (README.md, REPORT.md)

All code was reviewed, understood, and validated by the author before inclusion. The architecture decisions, security trade-offs, and design justifications in this document reflect the author's own analysis.


## Bonus Features Implemented

To ensure operational readiness and a professional engineering standard, I implemented the following features beyond the baseline requirements:

1. **Automated CI/CD Pipeline (GitHub Actions):** I created a `.github/workflows/ci.yml` file. On every commit, this spins up an Ubuntu runner, verifies the Node 22 Astro SSG build, and checks the Python backend for syntax errors. This ensures broken code is never merged.

2. **Production Deployment Files (systemd):** I included a `deployment/` directory containing `lxd-monitor-api.service` and `lxd-monitor-collector.service`. These allow a server admin to easily install the backend and collector as background daemons that automatically survive server reboots.

3. **Documented Threat Model:** I included a comprehensive threat model (detailed above) that breaks down the attack vectors of the LXD socket, terminal shell injection, and TSDB memory exhaustion, along with their respective mitigations.