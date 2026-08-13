import re
from pylxd import Client
from pylxd.exceptions import LXDAPIException, NotFound

# Initialize the LXD client using the local socket
try:
    lxd = Client()
except Exception as e:
    # We must handle this gracefully so the Falcon app doesn't crash if LXD is restarting
    print(f"Warning: Could not connect to LXD socket: {e}")
    lxd = None

# Strict regex for LXD container names (only lowercase alphanumeric and hyphens)
VALID_NAME_REGEX = re.compile(r'^[a-z0-9-]+$')

def is_valid_name(name: str) -> bool:
    return bool(VALID_NAME_REGEX.match(name))

def get_all_containers_summary():
    """
    Fetches the current state of all containers for the Admin dashboard.
    This fulfills Main Process 1.1.
    """
    if not lxd:
        return []

    summary = []
    for container in lxd.containers.all():
        try:
            state = container.state()
            
            # Extract IPs
            ipv4 = "N/A"
            if state.network and 'eth0' in state.network:
                addresses = state.network['eth0']['addresses']
                ipv4 = next((addr['address'] for addr in addresses if addr['family'] == 'inet'), "N/A")

            summary.append({
                "name": container.name,
                "status": container.status,
                "architecture": container.architecture,
                "created_at": container.created_at,
                "ipv4": ipv4,
                "cpu_usage": state.cpu.get('usage', 0) if state.cpu else 0,
                "memory_usage": state.memory.get('usage', 0) if state.memory else 0,
                "memory_peak": state.memory.get('usage_peak', 0) if state.memory else 0,
                "disk_usage": state.disk.get('root', {}).get('usage', 0) if state.disk else 0,
                "processes": state.processes
            })
        except LXDAPIException:
            # Container might be transiently unavailable
            continue

    return summary

def create_container(name: str, image_alias: str, limits: dict):
    """
    Creates a new container with specific resource bounds.
    Fulfills Main Process 1.2.
    """
    if not is_valid_name(name):
        raise ValueError("Invalid container name. Use only a-z, 0-9, and hyphens.")

    # Prepare configuration for resource limits
    config = {}
    if 'cpu_cores' in limits:
        config['limits.cpu'] = str(limits['cpu_cores'])
    if 'ram_mb' in limits:
        config['limits.memory'] = f"{limits['ram_mb']}MB"
    if 'disk_gb' in limits:
        # Note: Disk limits usually require a storage pool backed by ZFS, BTRFS, or LVM
        config['size'] = f"{limits['disk_gb']}GB"

    container_config = {
        'name': name,
        'source': {
            'type': 'image',
            'alias': image_alias, # e.g., 'ubuntu/22.04'
            'server': 'https://images.linuxcontainers.org',
            'protocol': 'simplestreams'
        },
        'config': config,
        'ephemeral': limits.get('ephemeral', False)
    }

    # Devices configuration for disk (requires 'root' device override)
    if 'disk_gb' in limits:
        container_config['devices'] = {
            'root': {
                'path': '/',
                'pool': 'default', # Assumes 'default' pool exists
                'size': f"{limits['disk_gb']}GB",
                'type': 'disk'
            }
        }

    try:
        # Create and start the container
        container = lxd.containers.create(container_config, wait=True)
        if limits.get('autostart', True):
            container.start(wait=True)
        return True
    except LXDAPIException as e:
        raise RuntimeError(f"LXD Error: {str(e)}")

def execute_in_container(name: str, command: list):
    """
    Executes a command inside the container without exposing the host.
    """
    if not is_valid_name(name):
        raise ValueError("Invalid container name.")

    try:
        container = lxd.containers.get(name)
        if container.status != 'Running':
            raise RuntimeError("Container is not running.")
        
        # This returns a tuple: (exit_code, stdout, stderr)
        result = container.execute(command)
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except NotFound:
        raise ValueError("Container not found.")
