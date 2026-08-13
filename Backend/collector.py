import time
import threading
from datetime import datetime, timedelta, timezone
from tinyflux import TinyFlux, Point, TimeQuery
from pylxd import Client
from pylxd.exceptions import LXDAPIException

TSDB_PATH = "metrics.csv"
POLL_INTERVAL = 10  # seconds
RETENTION_HOURS = 24  # How long we keep high-fidelity data

def collect_metrics():
    """
    Polls LXD every 10 seconds and writes to TinyFlux.
    Designed to survive LXD daemon restarts without crashing.
    """
    db = TinyFlux(TSDB_PATH)
    lxd = None

    while True:
        # Re-establish LXD connection if it was lost
        if not lxd:
            try:
                lxd = Client()
            except Exception as e:
                print(f"[Collector] LXD unavailable, retrying in {POLL_INTERVAL}s... ({e})")
                time.sleep(POLL_INTERVAL)
                continue
        
        try:
            points = []
            for container in lxd.containers.all():
                if container.status != 'Running':
                    continue
                    
                state = container.state()
                
                # Extract raw values. Note: CPU is in nanoseconds.
                cpu_ns = state.cpu.get('usage', 0) if state.cpu else 0
                mem_bytes = state.memory.get('usage', 0) if state.memory else 0
                disk_bytes = state.disk.get('root', {}).get('usage', 0) if state.disk else 0

                p = Point(
                    time=datetime.now(timezone.utc),
                    measurement="container_metrics",
                    tags={"container_name": container.name},
                    fields={
                        "cpu_ns": cpu_ns,
                        "ram_bytes": mem_bytes,
                        "disk_bytes": disk_bytes
                    }
                )
                points.append(p)
            
            if points:
                db.insert_multiple(points)
                
        except LXDAPIException as e:
            print(f"[Collector] LXD API Error: {e}")
            lxd = None # Force a reconnect on the next loop
        except Exception as e:
            print(f"[Collector] Unexpected Error: {e}")

        # Sleep exactly the remaining time to maintain a strict 10s cadence
        time.sleep(POLL_INTERVAL)


def enforce_retention():
    """
    Garbage collector thread. Wakes up once an hour to purge data
    older than RETENTION_HOURS, ensuring bounded storage growth.
    """
    db = TinyFlux(TSDB_PATH)
    while True:
        time.sleep(3600)  # Sleep for 1 hour
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=RETENTION_HOURS)
            # Remove all points older than the cutoff
            deleted_count = db.remove(TimeQuery() < cutoff_time)
            print(f"[Retention] Purged {deleted_count} old metric points.")
        except Exception as e:
            print(f"[Retention] Error during purge: {e}")


if __name__ == "__main__":
    print("Starting background metrics collector and retention enforcer...")
    
    # Run both loops as daemon threads so they exit if the main process is killed
    poll_thread = threading.Thread(target=collect_metrics, daemon=True)
    retention_thread = threading.Thread(target=enforce_retention, daemon=True)
    
    poll_thread.start()
    retention_thread.start()
    
    # Keep the main process alive
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        print("\nShutting down collector.")
