"""One-off: recreate a tenant's web container, preserving its existing
volumes/env/labels exactly as provisioner.py's create_tenant() set them
up originally. Needed for the same reason recreate_mail.py/
recreate_tenant_admin.py exist: docker won't pick up new container-create
kwargs for an already-running container -- there's no image to rebuild
here (no Dockerfile changed), just a fresh container with the new
kwargs applied.

Delegates to provisioner._create_web_container itself, same single-
source-of-truth reasoning as the other recreate_*.py scripts.

**Real footgun since the Coraza WAF feature shipped, not present
before**: _create_web_container no longer sets any `traefik.*` labels
at all -- the WAF sidecar (_create_waf_container) owns the tenant's
public Traefik router now, and the web container is only reachable
through it. Recreating the web container for a tenant that doesn't
already have a live WAF container removes that tenant's only public
routing with nothing to replace it -- their site goes offline until
recreate_waf.py is also run. Guarded below: refuses to proceed for a
tenant with no `waf_container` recorded (a pre-Coraza tenant -- run
recreate_waf.py for that tenant, or accept the brief cutover gap, per
the control-plane README's "Coraza WAF" Phase 2 rollout notes, not
this script silently).
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

if not t.waf_container:
    print(
        f"refusing: {domain!r} has no waf_container on record (a pre-Coraza tenant). "
        "Recreating the web container alone would remove its only public Traefik "
        "routing and take the site offline. Run recreate_waf.py for this tenant "
        "first (see the README's Coraza WAF Phase 2 rollout notes), then re-run this.",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    client.containers.get(t.waf_container)
except NotFound:
    print(
        f"refusing: {domain!r} has waf_container={t.waf_container!r} on record, but "
        "that container doesn't actually exist right now. Recreating the web "
        "container with no live WAF sidecar in front of it would take the site "
        "offline. Run recreate_waf.py for this tenant first.",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    client.containers.get(t.web_container).remove(force=True)
    print(f"removed old {t.web_container}")
except NotFound:
    print(f"{t.web_container} not found, creating fresh")

container_name = provisioner._create_web_container(
    client, t.slug, t.domain, t.webroot_volume, t.phpconf_volume, t.logs_volume,
    t.db_network, t.db_container, t.db_name, t.db_user, t.db_password,
)
print(f"recreated {container_name} -- WAF sidecar {t.waf_container} still routes to it by name, no manual reconnect needed")
