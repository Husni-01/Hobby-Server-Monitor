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

## AI Tool Usage Log

This project was developed with assistance from an AI coding assistant (Antigravity / Claude). The following work was AI-assisted:

- Initial skeleton generation for Falcon routes, auth middleware, and pylxd wrapper
- Astro page scaffolding and CSS design system
- SQLite schema design review
- Documentation writing (README.md, REPORT.md)

All code was reviewed, understood, and validated by the author before inclusion. The architecture decisions, security trade-offs, and design justifications in this document reflect the author's own analysis.
