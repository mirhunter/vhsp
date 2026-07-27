"""One-off: create (or recreate) a tenant's Coraza WAF sidecar container,
for a tenant that either predates the Coraza WAF feature (no
waf_container on record) or needs its WAF container recreated to pick
up new provisioner._create_waf_container kwargs.

Delegates to provisioner._create_waf_container itself, same single-
source-of-truth reasoning as the other recreate_*.py scripts.

**Do NOT run this against an already-live tenant without a separate,
explicit go-ahead** -- see the control-plane README's "Coraza WAF"
section, Phase 2 rollout notes. The cutover isn't atomic: this script
creates the new WAF container (which claims the tenant's public
Host(<domain>) Traefik router via its own labels) while the existing
web container may still be carrying that same router's labels if
_create_web_container's Coraza-era version hasn't been deployed and
recreate_web.py hasn't been run yet for this tenant -- in that
in-between state Traefik sees two containers advertising the same
router, an ambiguous state that hasn't been characterized here. The
safe, tested order for retrofitting an already-live tenant is: deploy
the updated provisioner.py/entrypoint.sh first, run *this* script
(creates the WAF container; the old web container still has its labels
at this point since it hasn't been recreated yet -- brief double-routing
window, not a gap), then immediately run recreate_web.py (which now
refuses to run at all unless a live waf_container already exists,
specifically to prevent doing this out of order). For a brand-new
tenant, none of this applies -- create_tenant() already does both in
the right order with no live traffic at stake.
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

if t.waf_container:
    try:
        client.containers.get(t.waf_container).remove(force=True)
        print(f"removed old {t.waf_container}")
    except NotFound:
        print(f"{t.waf_container} not found, creating fresh")
else:
    print(f"{domain!r} has no waf_container on record yet -- creating for the first time")

container_name = provisioner._create_waf_container(client, t.slug, t.domain, t.phpconf_host_path)
registry.set_tenant_waf_container(domain, container_name)
print(f"recreated {container_name}, registry updated")
