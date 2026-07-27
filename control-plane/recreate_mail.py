"""One-off: recreate a tenant's mail container on the current vhsp-mail:latest
image, preserving its existing maildir volume/env/labels exactly as
provisioner.py's create_tenant() set them up originally. Needed because
docker won't pick up a rebuilt image for an already-running container.

Delegates to provisioner._create_mail_container itself now, rather than
duplicating its container-run call inline -- this script drifted stale
against real provisioner.py logic more than once already (see
vhsp-infra-access project memory: the network-alias workaround, twice).
Single source of truth from here on; this script only handles the
remove-old-container step provisioner.py itself has no reason to do.
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
    client.containers.get(t.mail_container).remove(force=True)
    print(f"removed old {t.mail_container}")
except NotFound:
    print(f"{t.mail_container} not found, creating fresh")

container_name, mail_volume, mail_host_path, mail_hostname = provisioner._create_mail_container(
    client, t.slug, t.domain, t.mail_user, t.mail_password,
    t.logs_volume, t.phpconf_volume, t.phpconf_host_path,
    mail_volume=t.mail_volume, mail_host_path=t.mail_host_path,
)
print(f"recreated {container_name} on vhsp-mail:latest, mail_hostname={mail_hostname}")
