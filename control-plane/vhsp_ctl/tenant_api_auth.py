"""Tenant-level API/MCP bearer-token validation -- the read-only half of
a token mechanism whose write half (mint/list/revoke) lives entirely
inside images/tenant-admin/app.py, not here.

Same cross-trust-boundary duplication this codebase already uses for
webauthn.py/totp.py/login_throttle.py: the tenant-admin container mints
and writes its own tokens to its own per-tenant file, and this module --
running in the shared operator-side process (vhsp_ctl/api.py,
vhsp_ctl/mcp_server.py) -- reads that same file directly by host path to
validate an incoming request, the same way toggles.py already reads/
writes tenant self-service state by host path without ever calling into
that tenant's own container.

Distinct from vhsp_ctl/api_auth.py (operator tokens, one shared global
store) in two ways: storage is per-tenant, one file per tenant under
that tenant's own phpconf_host_path, not one global file; and a token
carries a tenant-slug prefix (see validate_tenant_token's own docstring)
so validation can go straight to the one tenant's file it belongs to,
rather than scanning every tenant's tokens on every request -- fine for
api_auth.py's operator-token scan at operator scale, not fine here.
"""

import json
from pathlib import Path

from werkzeug.security import check_password_hash

from vhsp_ctl import registry

TENANT_API_TOKENS_FILENAME = "api_tokens.json"


def validate_tenant_token(token: str) -> registry.Tenant | None:
    """Returns the owning tenant if `token` is a live token for a
    currently-active tenant; None otherwise (unknown tenant, tenant not
    active, no token file yet, or hash mismatch -- deliberately no
    distinction in the return value, same "just None" shape
    api_auth.validate_token already uses).

    Tokens are minted (images/tenant-admin/app.py) as
    f"{slug}.{secrets.token_urlsafe(32)}" -- the slug prefix is public
    information (it's derived from the domain, already visible in every
    URL that tenant's own panel uses), not a secret; only the suffix
    after the first "." is the actual credential, checked against that
    one tenant's own stored hash. token_urlsafe's own alphabet
    (A-Za-z0-9-_) never produces a literal ".", so the first "." in the
    string is unambiguously the deliberate separator, not part of either
    half."""
    if "." not in token:
        return None
    slug, _, _ = token.partition(".")
    tenant = registry.get_tenant_by_slug(slug)
    if not tenant:
        return None
    tokens_path = Path(tenant.phpconf_host_path) / TENANT_API_TOKENS_FILENAME
    if not tokens_path.exists():
        return None
    try:
        entries = json.loads(tokens_path.read_text())
    except json.JSONDecodeError:
        return None
    for entry in entries.values():
        if check_password_hash(entry["hash"], token):
            return tenant
    return None
