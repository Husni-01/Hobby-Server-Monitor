"""
collector.py — Background metrics collector for LXD Monitor.

Runs as a standalone process, completely independent of the Falcon API server.
This means metrics keep accumulating even when no browser tab is open and even
when the API server is restarted.

Design decisions:
  - Separate process (not a thread inside the API): its cost does not scale with
    the number of open browser tabs or API requests.
  - Reconnects to LXD automatically if the daemon restarts.
  - Retention is enforced in a separate thread to avoid pausing collection.
  - 7-day retention at 10-second intervals for 10 containers ≈ 600k rows ≈ 60 MB
    in TinyFlux's CSV format — acceptable for a hobby server.
  - The main thread stays alive via time.sleep(86400) and exits cleanly on SIGINT.

Storage estimation (7 days, 10-second interval):
  Rows = (7 * 24 * 3600) / 10 = 60,480 rows per container
  At ~120 bytes/row (CSV with 6 numeric fields + timestamp + tags):
  10 containers × 60,480 × 120 bytes ≈ 72 MB maximum.
"""

import time
import threading
from datetime import datetime, timedelta, timezone

from tinyflux import TinyFlux, Point, TimeQuery
from pylxd import Client
from pylxd.exceptions import LXDAPIException

from database import TSDB_PATH

POLL_INTERVAL    = 10     # seconds between collection runs
RETENTION_DAYS   = 7      # keep this many days of data
RETENTION_HOURS  = RETENTION_DAYS * 24


def collect_metrics():
    """
    Main collection loop. Polls every container every 10 seconds.
    Handles LXD daemon restarts gracefully: resets the client and retries.
    """
    db  = TinyFlux(TSDB_PATH)
    lxd = None

    print(f"[Collector] Starting — interval={POLL_INTERVAL}s, retention={RETENTION_DAYS} days")

    while True:
        cycle_start = time.monotonic()

        # Reconnect to LXD if needed
        if not lxd:
            try:
                lxd = Client()
                print("[Collector] Connected to LXD.")
            except Exception as e:
                print(f"[Collector] LXD unavailable, retrying in {POLL_INTERVAL}s — {e}")
                time.sleep(POLL_INTERVAL)
                continue

        try:
            points = []
            now    = datetime.now(timezone.utc)

            for container in lxd.containers.all():
                if container.status != "Running":
                    continue

                try:
                    state = container.state()
                except LXDAPIException:
                    continue

                # ── CPU ────────────────────────────────────────────────────────
                cpu_ns = state.cpu.get("usage", 0) if state.cpu else 0

                # ── Memory ─────────────────────────────────────────────────────
                mem_bytes = state.memory.get("usage", 0) if state.memory else 0

                # ── Disk ───────────────────────────────────────────────────────
                disk_bytes = state.disk.get("root", {}).get("usage", 0) if state.disk else 0

                # ── Network ────────────────────────────────────────────────────
                net_rx = 0
                net_tx = 0
                if state.network:
                    iface = state.network.get("eth0") or next(iter(state.network.values()), {})
                    counters = iface.get("counters", {})
                    net_rx   = counters.get("bytes_received", 0)
                    net_tx   = counters.get("bytes_sent", 0)

                # ── Process count ──────────────────────────────────────────────
                process_count = state.processes if state.processes else 0

                points.append(Point(
                    time=now,
                    measurement="container_metrics",
                    tags={"container_name": container.name},
                    fields={
                        "cpu_ns":        float(cpu_ns),
                        "ram_bytes":     float(mem_bytes),
                        "disk_bytes":    float(disk_bytes),
                        "net_rx_bytes":  float(net_rx),
                        "net_tx_bytes":  float(net_tx),
                        "process_count": float(process_count),
                    }
                ))

            if points:
                db.insert_multiple(points)
                print(f"[Collector] Inserted {len(points)} points.")

        except LXDAPIException as e:
            print(f"[Collector] LXD API error: {e} — will reconnect.")
            lxd = None
        except Exception as e:
            print(f"[Collector] Unexpected error: {e}")

        # Sleep only the remaining time in the 10-second window
        elapsed = time.monotonic() - cycle_start
        sleep_for = max(0.0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)


def enforce_retention():
    """
    Purges TSDB entries older than RETENTION_DAYS. Runs once per hour.
    Runs in a separate thread so it doesn't block collection.
    """
    db = TinyFlux(TSDB_PATH)
    print(f"[Retention] Thread started — will purge data older than {RETENTION_DAYS} days.")

    while True:
        time.sleep(3600)  # check every hour
        try:
            cutoff    = datetime.now(timezone.utc) - timedelta(hours=RETENTION_HOURS)
            deleted   = db.remove(TimeQuery() < cutoff)
            print(f"[Retention] Purged {deleted} points older than {cutoff.isoformat()}.")
        except Exception as e:
            print(f"[Retention] Error during purge: {e}")


if __name__ == "__main__":
    poll_thread      = threading.Thread(target=collect_metrics,  daemon=True, name="collector")
    retention_thread = threading.Thread(target=enforce_retention, daemon=True, name="retention")

    poll_thread.start()
    retention_thread.start()

    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        print("\n[Collector] Shutting down.")
