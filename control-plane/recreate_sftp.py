"""One-off: recreate a tenant's SFTP container, preserving its existing
volumes/env/labels exactly as provisioner.py's create_tenant() set them
up originally. Needed for the same reason recreate_web.py/recreate_mail.py/
recreate_tenant_admin.py exist: docker won't pick up new container-create
kwargs (the SFTP_MEM_LIMIT/SFTP_NANO_CPUS cgroup limits added to
_create_sftp_container) for an already-running container -- there's no
image to rebuild here, just a fresh container with the new mem_limit/
nano_cpus applied.

Critically passes the tenant's EXISTING ssh_keys_volume rather than
omitting it -- _create_sftp_container's own docstring warns that
atmoz/sftp's entrypoint only builds authorized_keys from that volume's
*.pub files on a container's first-ever boot, so recreating with a fresh
(empty) keys volume instead of the real one would silently lock a
tenant out of SFTP until their key was re-installed.

Delegates to provisioner._create_sftp_container itself, same single-
source-of-truth reasoning as the other three recreate_*.py scripts.
"""
import sys

from docker.errors import NotFound

from vhsp_ctl import provisioner, registry

domain = sys.argv[1]
t = registry.get_tenant(domain)
if not t:
    print(f"no active tenant for {domain!r}", file=sys.stderr)
    sys.exit(1)

client = provisioner._client()

try:
    client.containers.get(t.sftp_container).remove(force=True)
    print(f"removed old {t.sftp_container}")
except NotFound:
    print(f"{t.sftp_container} not found, creating fresh")

container_name, keys_volume, keys_host_path = provisioner._create_sftp_container(
    client, t.slug, t.ssh_port, t.webroot_volume, t.sftp_user, t.logs_volume,
    keys_volume=t.ssh_keys_volume,
)
print(f"recreated {container_name} with cgroup limits applied (keys_volume={keys_volume})")
