"""
lxd_client.py — Thin wrapper around pylxd for the LXD Monitor backend.

Design principles:
  - LXD is accessed via the local Unix socket (/var/snap/lxd/common/lxd/unix.socket
    or /var/lib/lxd/unix.socket depending on install method). No TCP port is opened.
  - All container name inputs are validated against a strict regex before being
    passed to pylxd. This prevents path-traversal style attacks.
  - The 'execute_in_container' function uses pylxd's exec API which runs the command
    inside the container's own namespace; it does NOT spawn a shell on the host.
  - If LXD is temporarily unavailable the functions degrade gracefully: they return
    empty results or raise informative errors rather than crashing the API.
"""

import re
from pylxd import Client
from pylxd.exceptions import LXDAPIException, NotFound

# ── LXD connection ─────────────────────────────────────────────────────────────
# Initialise once at module load. If LXD is not available (e.g. on a dev machine)
# the global is set to None and every function checks for it before proceeding.
try:
    lxd = Client()
except Exception as e:
    print(f"[LXD] Warning: Could not connect to LXD socket: {e}")
    lxd = None

# ── Validation ─────────────────────────────────────────────────────────────────
# LXD naming rules: 1–63 chars, lowercase alphanumeric or hyphens, must start
# with a letter and must not end with a hyphen.
VALID_NAME_REGEX = re.compile(r'^[a-z][a-z0-9-]{0,61}[a-z0-9]$|^[a-z]$')

def is_valid_name(name: str) -> bool:
    return bool(VALID_NAME_REGEX.match(name)) if name else False


# ── Container listing ──────────────────────────────────────────────────────────
def get_all_containers_summary() -> list:
    """
    Returns a list of dicts with live state for every container known to LXD.
    Called by the Admin dashboard (Main Process 1.1).
    Fields returned cover every metric listed in the project brief.
    """
    if not lxd:
        return []

    summary = []
    for container in lxd.containers.all():
        try:
            state = container.state()
            cfg   = container.config

            # ── Network ────────────────────────────────────────────────────────
            ipv4     = "N/A"
            net_rx   = 0
            net_tx   = 0
            if state.network:
                iface = state.network.get("eth0") or next(iter(state.network.values()), {})
                addrs = iface.get("addresses", [])
                ipv4  = next((a["address"] for a in addrs if a["family"] == "inet"), "N/A")
                counters = iface.get("counters", {})
                net_rx   = counters.get("bytes_received", 0)
                net_tx   = counters.get("bytes_sent", 0)

            # ── CPU ────────────────────────────────────────────────────────────
            cpu_ns = state.cpu.get("usage", 0) if state.cpu else 0

            # ── Memory ─────────────────────────────────────────────────────────
            mem_used  = state.memory.get("usage",      0) if state.memory else 0
            mem_total = state.memory.get("usage_peak", 0) if state.memory else 0
            # Derive allocated RAM from config (limits.memory may be e.g. "512MB")
            mem_limit_raw = cfg.get("limits.memory", "")

            # ── Disk ───────────────────────────────────────────────────────────
            disk_used = state.disk.get("root", {}).get("usage", 0) if state.disk else 0

            # ── Config limits ──────────────────────────────────────────────────
            cpu_limit   = cfg.get("limits.cpu",  "")    # could be "2" or "10%" etc.
            cpu_allowance = cfg.get("limits.cpu.allowance", "")

            # ── Uptime (seconds) ───────────────────────────────────────────────
            pid1_started = state.pid if container.status == "Running" else None

            summary.append({
                "name":          container.name,
                "status":        container.status,
                "architecture":  container.architecture,
                "created_at":    str(container.created_at),
                "profiles":      container.profiles,
                "ipv4":          ipv4,

                # Live resource metrics
                "cpu_ns":        cpu_ns,
                "mem_used":      mem_used,
                "mem_total":     mem_total,
                "mem_limit_raw": mem_limit_raw,
                "disk_used":     disk_used,
                "net_rx":        net_rx,
                "net_tx":        net_tx,
                "processes":     state.processes if container.status == "Running" else 0,

                # Configured limits (from LXD config)
                "cpu_limit":      cpu_limit,
                "cpu_allowance":  cpu_allowance,
            })
        except LXDAPIException:
            # Container transiently unavailable; include minimal stub
            summary.append({
                "name":   container.name,
                "status": "Error",
                "error":  "Could not fetch state",
            })
            continue

    return summary


def get_container_detail(name: str) -> dict:
    """Returns full detail for a single container, including OS info."""
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")
    try:
        container = lxd.containers.get(name)
        state = container.state()
        cfg   = container.config
        expanded_config = container.expanded_config
        return {
            "name":              container.name,
            "status":            container.status,
            "architecture":      container.architecture,
            "created_at":        str(container.created_at),
            "profiles":          container.profiles,
            "ephemeral":         container.ephemeral,
            "config":            dict(cfg),
            "expanded_config":   dict(expanded_config),
            "description":       container.description,
        }
    except NotFound:
        raise ValueError("Container not found.")


# ── Container creation ─────────────────────────────────────────────────────────
def create_container(name: str, image_alias: str, limits: dict) -> bool:
    """
    Creates and optionally starts a new container.

    Extra config options beyond the brief:
      - autostart (boot.autostart): persists across host reboots
      - security.nesting: False by default (prevents container-in-container privilege escalation)
      - security.privileged: always False (unprivileged containers only)
    """
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name. Use only a-z, 0-9, and hyphens, starting with a letter.")

    config = {
        # Never allow privileged containers — they share the host kernel namespace
        "security.privileged": "false",
        # Disable nested containers by default to reduce attack surface
        "security.nesting":    "false",
    }

    if limits.get("cpu_cores"):
        config["limits.cpu"]    = str(limits["cpu_cores"])
    if limits.get("cpu_allowance"):
        config["limits.cpu.allowance"] = str(limits["cpu_allowance"])
    if limits.get("ram_mb"):
        config["limits.memory"] = f"{limits['ram_mb']}MB"
    if limits.get("autostart", True):
        config["boot.autostart"] = "true"
    else:
        config["boot.autostart"] = "false"

    description = limits.get("description", "")
    profiles    = limits.get("profiles", ["default"])
    pool        = limits.get("pool", "default")

    container_config = {
        "name":        name,
        "description": description,
        "profiles":    profiles,
        "source": {
            "type":     "image",
            "alias":    image_alias,
            "server":   "https://images.linuxcontainers.org",
            "protocol": "simplestreams",
        },
        "config":    config,
        "ephemeral": bool(limits.get("ephemeral", False)),
    }

    # Disk size override (requires ZFS/BTRFS/LVM pool)
    if limits.get("disk_gb"):
        container_config["devices"] = {
            "root": {
                "path": "/",
                "pool": pool,
                "size": f"{limits['disk_gb']}GB",
                "type": "disk",
            }
        }

    try:
        container = lxd.containers.create(container_config, wait=True)
        if not limits.get("ephemeral", False) or limits.get("autostart", True):
            container.start(wait=True)
        return True
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")


# ── Lifecycle actions ──────────────────────────────────────────────────────────
ALLOWED_ACTIONS = {"start", "stop", "restart", "freeze", "unfreeze"}

def perform_lifecycle_action(name: str, action: str) -> dict:
    """
    Runs a lifecycle action on a container.
    Returns a dict with 'ok': True on success or raises.
    """
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unknown action '{action}'. Must be one of: {', '.join(ALLOWED_ACTIONS)}.")

    try:
        container = lxd.containers.get(name)
        getattr(container, action)(wait=True)
        return {"ok": True, "action": action, "container": name}
    except NotFound:
        raise ValueError("Container not found.")
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")


def delete_container(name: str) -> dict:
    """
    Stops a running container then deletes it. Non-recoverable.
    Callers are responsible for writing the audit log entry before calling this.
    """
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")

    try:
        container = lxd.containers.get(name)
        if container.status in ("Running", "Frozen"):
            container.stop(force=True, wait=True)
        container.delete(wait=True)
        return {"ok": True, "deleted": name}
    except NotFound:
        raise ValueError("Container not found.")
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")


# ── Resource limit update ──────────────────────────────────────────────────────
def update_container_limits(name: str, limits: dict) -> dict:
    """
    Updates CPU and/or RAM limits on a running container without restarting it.
    LXD applies cgroup limits live; the change takes effect immediately.
    """
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")

    try:
        container = lxd.containers.get(name)
        if limits.get("cpu_cores"):
            container.config["limits.cpu"] = str(limits["cpu_cores"])
        if limits.get("cpu_allowance"):
            container.config["limits.cpu.allowance"] = str(limits["cpu_allowance"])
        if limits.get("ram_mb"):
            container.config["limits.memory"] = f"{limits['ram_mb']}MB"
        container.save(wait=True)
        return {"ok": True, "updated": name, "limits": limits}
    except NotFound:
        raise ValueError("Container not found.")
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")


# ── Command execution ──────────────────────────────────────────────────────────
def execute_in_container(name: str, command: list) -> dict:
    """
    Executes a command inside the container namespace via pylxd's exec API.

    Security note: this does NOT invoke /bin/sh or any other shell on the host.
    The command list is passed directly to the container's init as an exec call.
    Shell operators (&&, |, ;) are treated as literal strings — they are passed
    as arguments to the first command, not interpreted by any shell.

    The caller (ContainerExecResource in app.py) uses shlex.split() to tokenise
    the raw string into the list before passing it here, removing any ambiguity
    about shell metacharacter interpretation.
    """
    if not lxd:
        raise RuntimeError("LXD unavailable.")
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")
    if not command or not isinstance(command, list):
        raise ValueError("Command must be a non-empty list.")

    try:
        container = lxd.containers.get(name)
        if container.status != "Running":
            raise RuntimeError("Container is not running.")

        result = container.execute(command)
        return {
            "exit_code": result.exit_code,
            "stdout":    result.stdout or "",
            "stderr":    result.stderr or "",
        }
    except NotFound:
        raise ValueError("Container not found.")
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")


# ── Host / infrastructure discovery ───────────────────────────────────────────
def get_host_resources() -> dict:
    """
    Returns the physical host's total resource capacity.
    Used to derive slider bounds in the container creation form.
    """
    if not lxd:
        return {"cpu_cores": 4, "ram_mb": 8192, "error": "LXD unavailable; using defaults."}

    try:
        resources = lxd.host_info.get("environment", {})
        # LXD reports kernel architecture but not raw CPU/RAM easily from host_info.
        # Use /api/1.0/resources instead.
        res = lxd.api.resources.get()
        cpu_total = res.json().get("metadata", {}).get("cpu", {}).get("total", 4)
        mem_total = res.json().get("metadata", {}).get("memory", {}).get("total", 8589934592)
        return {
            "cpu_cores": cpu_total,
            "ram_mb":    mem_total // (1024 * 1024),
        }
    except Exception:
        return {"cpu_cores": 4, "ram_mb": 8192, "error": "Could not read host resources."}


def get_storage_pools() -> list:
    """Returns a list of storage pools with their used/total bytes."""
    if not lxd:
        return [{"name": "default", "driver": "dir"}]

    try:
        pools = []
        for pool in lxd.storage_pools.all():
            try:
                resources = pool.resources.get()
                pools.append({
                    "name":       pool.name,
                    "driver":     pool.driver,
                    "space_used": resources.get("space", {}).get("used",  0),
                    "space_total":resources.get("space", {}).get("total", 0),
                })
            except Exception:
                pools.append({"name": pool.name, "driver": pool.driver})
        return pools
    except Exception:
        return [{"name": "default", "driver": "dir"}]


def get_network_profiles() -> list:
    """Returns the names of all LXD profiles (which define network attachment)."""
    if not lxd:
        return ["default"]

    try:
        return [p.name for p in lxd.profiles.all()]
    except Exception:
        return ["default"]


def get_available_images() -> list:
    """
    Returns a curated list of image aliases.
    We use a hardcoded list of well-known aliases rather than hitting the remote
    simplestreams index on every form load — that would be slow and fragile.
    The actual image is pulled from images.linuxcontainers.org at container-create time.
    """
    return [
        {"alias": "ubuntu/24.04", "description": "Ubuntu 24.04 LTS (Noble Numbat)"},
        {"alias": "ubuntu/22.04", "description": "Ubuntu 22.04 LTS (Jammy Jellyfish)"},
        {"alias": "ubuntu/20.04", "description": "Ubuntu 20.04 LTS (Focal Fossa)"},
        {"alias": "debian/12",    "description": "Debian 12 (Bookworm)"},
        {"alias": "debian/11",    "description": "Debian 11 (Bullseye)"},
        {"alias": "alpine/3.19",  "description": "Alpine Linux 3.19"},
        {"alias": "centos/9-Stream", "description": "CentOS Stream 9"},
        {"alias": "fedora/40",    "description": "Fedora 40"},
    ]
