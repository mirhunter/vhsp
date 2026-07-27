"""One-off: recreate a tenant's tenant-admin container on the current
vhsp-tenant-admin:latest image, preserving its existing volumes/env/labels
exactly as provisioner.py's create_tenant() set them up originally. Needed
because docker won't pick up a rebuilt image for an already-running
container.

Delegates to provisioner._create_tenant_admin_container itself now,
rather than duplicating its container-run call inline -- the previous
version of this script drifted stale against real provisioner.py logic
more than once already (missing DB_HOST/mail_volume/the public router at
different points, see vhsp-infra-access project memory), and recreate_mail.py
already got this same fix for the same reason. Single source of truth
from here on.
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
    client.containers.get(t.tenant_admin_container).remove(force=True)
    print(f"removed old {t.tenant_admin_container}")
except NotFound:
    print(f"{t.tenant_admin_container} not found, creating fresh")

container_name, admin_hostname, _admin_password = provisioner._create_tenant_admin_container(
    client, t.slug, t.domain, t.phpconf_volume, t.phpconf_host_path, t.logs_volume, t.webroot_volume,
    t.db_network, t.db_container, t.db_name, t.db_user, t.db_password, t.mail_volume,
    t.ssh_port, t.sftp_user,
)
print(f"recreated {container_name} on vhsp-tenant-admin:latest, admin_hostname={admin_hostname}")
