"""Operator MCP server -- the exact same operations as vhsp_ctl/api.py's
REST Blueprint, wrapped as MCP tools instead of HTTP routes, kept in
sync by construction (both call the same provisioner.py/backup.py/
registry.py/audit.py functions directly, same "thin wrapper, no
business logic here" shape cli.py and web.py's own routes already use).

Runs as its own process, not a route inside vhsp-admin.service --
fastmcp is ASGI/Starlette-based, vhsp-admin.service is WSGI/gunicorn,
there's no clean way to mount one inside the other. Same "bare host
process + its own systemd unit + its own Traefik route" pattern
deploy/vhsp-admin.service itself already uses (see deploy/vhsp-mcp.service),
not new architecture.

Auth is vhsp_ctl/api_auth.py's own token store -- the exact same
bearer tokens the REST API validates, one token mechanism, two
front-ends. See ApiTokenVerifier below: fastmcp's TokenVerifier is the
SDK's own hook for "verify this raw token yourself" (distinct from its
OAuth2/JWT-provider classes, which don't apply here -- this codebase
mints its own opaque tokens, not JWTs from an external issuer).
"""

import sys
from dataclasses import asdict
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token

from vhsp_ctl import api_auth, audit, backup, provisioner, registry, tenant_api_auth, toggles
from vhsp_ctl.config import MCP_BIND_HOST, MCP_BIND_PORT, MCP_ENABLED


class ApiTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        # Operator tokens checked first, then tenant tokens (api_auth.py
        # and tenant_api_auth.py are two completely separate stores/
        # namespaces -- see tenant_api_auth.py's own docstring). scopes
        # is where the operator-vs-tenant distinction lives for the
        # tools below to check, since AccessToken has no dedicated
        # "kind" field of its own -- ["operator"] or ["tenant"], never
        # both, so a single token can never be treated as one kind by
        # one tool and the other kind by another.
        username = api_auth.validate_token(token)
        if username:
            return AccessToken(token=token, client_id=username, scopes=["operator"], subject=username)
        tenant = tenant_api_auth.validate_tenant_token(token)
        if tenant:
            return AccessToken(token=token, client_id=tenant.domain, scopes=["tenant"], subject=tenant.domain)
        return None


def _actor() -> str:
    """Same purpose as api.py's _actor() -- so provisioner.py/backup.py's
    audit logging shows which real operator did what through this
    surface, not a generic actor. get_access_token() is fastmcp's own
    per-request context accessor; only valid to call from inside a
    @mcp.tool function during a real, authenticated invocation. Operator
    tools only -- see _tenant_actor() for the tenant-scoped equivalent."""
    return f"mcp:{get_access_token().subject}"


def _require_operator_access() -> None:
    """Every operator tool below calls this first. A real bug, found
    live during this feature's own verification: adding tenant-scoped
    tools (each gated by _require_tenant_access, rejecting operator
    tokens) is only half of mutual isolation -- without this
    complementary check on the *existing* operator tools, a tenant token
    authenticated fine at the transport level (ApiTokenVerifier.verify_token
    succeeds for either kind) and nothing stopped it from calling
    create_tenant/destroy_tenant/list_tenants and every other operator
    tool, a full privilege escalation from tenant self-service to
    cross-tenant control. vhsp_ctl/api.py's REST routes never had this
    gap -- require_api_token and require_tenant_api_token are two
    separate decorators backed by two separate validation functions
    (api_auth.validate_token / tenant_api_auth.validate_tenant_token),
    so a tenant token simply fails operator validation outright and
    never reaches an operator route at all. MCP's single shared
    ApiTokenVerifier (one token namespace check, `scopes` distinguishing
    kind afterward) needed this explicit reverse check added instead."""
    access_token = get_access_token()
    if "operator" not in access_token.scopes:
        raise ValueError("this tool requires an operator token, not a tenant token")


def _require_tenant_access() -> registry.Tenant:
    """Every tenant-scoped tool below calls this first. Raises ValueError
    (fastmcp surfaces this as a normal tool-call error, not a crash --
    same convention get_tenant() above already uses) unless the caller
    holds a genuinely tenant-scoped token AND both halves of the
    two-layer permission model are true right now -- api.py's
    require_tenant_api_token decorator's own docstring explains why this
    is checked live, not cached, on every single call; this is the exact
    same check, just as a function instead of a decorator since fastmcp
    tools aren't Flask routes."""
    access_token = get_access_token()
    if "tenant" not in access_token.scopes:
        raise ValueError("this tool requires a tenant token, not an operator token")
    tenant = registry.get_tenant(access_token.subject)
    if not tenant:
        raise ValueError("this tenant no longer exists")
    access = provisioner.tenant_platform_access(tenant.domain)
    if not access["mcp_allowed"]:
        raise ValueError("MCP access has not been allowed for this tenant by its operator")
    if not access["mcp_enabled"]:
        raise ValueError("MCP access is allowed but not currently turned on -- enable it from this tenant's own panel")
    return tenant


def _tenant_actor() -> str:
    return f"mcp:tenant:{get_access_token().subject}"


mcp = FastMCP("vhsp-operator", auth=ApiTokenVerifier())


@mcp.tool
def list_tenants() -> list[dict]:
    """List active tenants."""
    _require_operator_access()
    return [registry.tenant_to_dict(t) for t in registry.list_tenants()]


@mcp.tool
def get_tenant(domain: str) -> dict:
    """Get one tenant's details. Credential fields (DB/mail/admin
    passwords) are redacted -- not available through this tool."""
    _require_operator_access()
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise ValueError(f"no active tenant for {domain!r}")
    return registry.tenant_to_dict(tenant)


@mcp.tool
def create_tenant(domain: str) -> dict:
    """Provision a new tenant -- web/waf/db/sftp/mail/tenant-admin
    containers, DNS routing, fail2ban jail, everything create_tenant()
    normally sets up."""
    _require_operator_access()
    tenant = provisioner.create_tenant(domain, actor=_actor())
    return registry.tenant_to_dict(tenant)


@mcp.tool
def destroy_tenant(domain: str) -> str:
    """Tear down a tenant and free every resource it holds. Not
    reversible -- there is no confirmation step at this layer, the same
    way the CLI's `vhsp tenant destroy` has none either."""
    _require_operator_access()
    provisioner.destroy_tenant(domain, actor=_actor())
    return f"destroyed {domain}"


@mcp.tool
def get_tenant_usage(domain: str) -> dict:
    """Combined web+db+mail disk usage for a tenant, in bytes."""
    _require_operator_access()
    return provisioner.get_tenant_disk_usage(domain)


@mcp.tool
def list_tenant_backups(domain: str) -> list[dict]:
    """List a tenant's existing backup snapshots."""
    _require_operator_access()
    return [asdict(b) for b in registry.list_backups(domain)]


@mcp.tool
def create_tenant_backup(domain: str) -> list[dict]:
    """Create a backup of a tenant right now (in addition to whatever
    its own scheduled interval already does)."""
    _require_operator_access()
    return [asdict(b) for b in backup.create_backup(domain, actor=_actor())]


@mcp.tool
def restore_tenant_backup(
    domain: str, snapshot_name: str, source: str = "operator", target_domain: str | None = None,
) -> dict:
    """Restore a backup snapshot. Omit target_domain to restore in
    place (overwriting the tenant's current content); set it to restore
    as a new, separate tenant instead."""
    _require_operator_access()
    tenant = backup.restore_backup(
        domain, snapshot_name, source=source, target_domain=target_domain, actor=_actor(),
    )
    return registry.tenant_to_dict(tenant)


@mcp.tool
def verify_audit() -> dict:
    """Verify the platform's audit log hash chain is intact -- a break
    means some past entry was edited or deleted after the fact."""
    _require_operator_access()
    intact, count = audit.verify_chain()
    return {"intact": intact, "entries_checked": count}


@mcp.tool
def get_fail2ban_log(lines: int = 200) -> str:
    """Tail fail2ban's own log -- every jail mixed together (host SSH,
    the admin UIs' login jails, every tenant's own SFTP jail)."""
    _require_operator_access()
    return provisioner.tail_fail2ban_log(lines)


# --- Tenant-scoped tools ---------------------------------------------
#
# Everything below requires a tenant token (see _require_tenant_access),
# never an operator one -- mirrors vhsp_ctl/api.py's /self/* routes tool
# for tool, same underlying toggles.py calls, same two-layer permission
# check. No tool here takes a domain parameter -- the tenant is always
# whatever _require_tenant_access() resolves from the token itself.

@mcp.tool
def self_overview() -> dict:
    """[Tenant-scoped] This tenant's own overview: domain, disk usage, quota."""
    tenant = _require_tenant_access()
    usage = provisioner.get_tenant_disk_usage(tenant.domain)
    quota_limit = provisioner.get_tenant_quota_limit(tenant.domain)
    return {"domain": tenant.domain, "usage": usage, "quota_limit_bytes": quota_limit}


@mcp.tool
def self_get_php_functions() -> dict:
    """[Tenant-scoped] Get enabled PHP functions and the full available set."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    return {"enabled": sorted(toggles.read_enabled_functions(phpconf_dir)), "available": [fn for fn, _ in toggles.FUNCTIONS]}


@mcp.tool
def self_set_php_functions(enabled: list[str]) -> dict:
    """[Tenant-scoped] Set enabled PHP functions (replaces the current set)."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    toggles.write_enabled_functions(phpconf_dir, set(enabled))
    return {"enabled": sorted(toggles.read_enabled_functions(phpconf_dir))}


@mcp.tool
def self_get_fallback() -> dict:
    """[Tenant-scoped] Get 404 fallback state."""
    tenant = _require_tenant_access()
    return {"enabled": toggles.fallback_enabled(Path(tenant.webroot_host_path))}


@mcp.tool
def self_set_fallback(enabled: bool) -> dict:
    """[Tenant-scoped] Set 404 fallback state."""
    tenant = _require_tenant_access()
    webroot_dir = Path(tenant.webroot_host_path)
    toggles.set_fallback_enabled(webroot_dir, enabled)
    return {"enabled": toggles.fallback_enabled(webroot_dir)}


@mcp.tool
def self_get_auth() -> dict:
    """[Tenant-scoped] Get password-protection (Basic Auth) state."""
    tenant = _require_tenant_access()
    username = toggles.read_basic_auth_user(Path(tenant.phpconf_host_path))
    return {"enabled": bool(username), "username": username}


@mcp.tool
def self_set_auth(username: str = "", password: str = "", disable: bool = False) -> dict:
    """[Tenant-scoped] Set or disable password protection. Set disable=true to turn it off."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    if disable:
        toggles.disable_basic_auth(phpconf_dir)
    else:
        error = toggles.set_basic_auth(phpconf_dir, username, password)
        if error:
            raise ValueError(error)
    current_username = toggles.read_basic_auth_user(phpconf_dir)
    return {"enabled": bool(current_username), "username": current_username}


@mcp.tool
def self_get_error_pages() -> dict:
    """[Tenant-scoped] Get custom error page mappings."""
    tenant = _require_tenant_access()
    return {"lines": toggles.read_lines_file(Path(tenant.phpconf_host_path), "error_pages.txt")}


@mcp.tool
def self_set_error_pages(lines: str) -> dict:
    """[Tenant-scoped] Set custom error page mappings -- one 'CODE /path' per line."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    error = toggles.write_lines_file(phpconf_dir, "error_pages.txt", lines, toggles.validate_error_page_line)
    if error:
        raise ValueError(error)
    return {"lines": toggles.read_lines_file(phpconf_dir, "error_pages.txt")}


@mcp.tool
def self_get_redirects() -> dict:
    """[Tenant-scoped] Get redirects."""
    tenant = _require_tenant_access()
    return {"lines": toggles.read_lines_file(Path(tenant.phpconf_host_path), "redirects.txt")}


@mcp.tool
def self_set_redirects(lines: str) -> dict:
    """[Tenant-scoped] Set redirects -- one '/from target' per line."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    error = toggles.write_lines_file(phpconf_dir, "redirects.txt", lines, toggles.validate_redirect_line)
    if error:
        raise ValueError(error)
    return {"lines": toggles.read_lines_file(phpconf_dir, "redirects.txt")}


@mcp.tool
def self_get_noexec_dirs() -> dict:
    """[Tenant-scoped] Get no-exec directories."""
    tenant = _require_tenant_access()
    return {"lines": toggles.read_lines_file(Path(tenant.phpconf_host_path), "noexec_dirs.txt")}


@mcp.tool
def self_set_noexec_dirs(lines: str) -> dict:
    """[Tenant-scoped] Set no-exec directories -- one relative path per line."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    error = toggles.write_lines_file(phpconf_dir, "noexec_dirs.txt", lines, toggles.validate_noexec_dir_line)
    if error:
        raise ValueError(error)
    return {"lines": toggles.read_lines_file(phpconf_dir, "noexec_dirs.txt")}


@mcp.tool
def self_get_ip_acl() -> dict:
    """[Tenant-scoped] Get IP allow/deny list."""
    tenant = _require_tenant_access()
    mode, lines = toggles.read_ip_acl(Path(tenant.phpconf_host_path))
    return {"mode": mode, "lines": lines}


@mcp.tool
def self_set_ip_acl(mode: str, lines: str) -> dict:
    """[Tenant-scoped] Set IP allow/deny list. mode is '', 'allow', or 'deny'."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    error = toggles.write_ip_acl(phpconf_dir, mode, lines)
    if error:
        raise ValueError(error)
    mode, lines = toggles.read_ip_acl(phpconf_dir)
    return {"mode": mode, "lines": lines}


@mcp.tool
def self_list_mailboxes() -> list[dict]:
    """[Tenant-scoped] List mailboxes."""
    tenant = _require_tenant_access()
    boxes = toggles.read_mailboxes(Path(tenant.phpconf_host_path))
    return [{"user": u, "quota_bytes": b["quota_bytes"]} for u, b in sorted(boxes.items())]


@mcp.tool
def self_add_mailbox(user: str, password: str) -> list[dict]:
    """[Tenant-scoped] Add a mailbox."""
    tenant = _require_tenant_access()
    phpconf_dir = Path(tenant.phpconf_host_path)
    error = toggles.add_mailbox(phpconf_dir, user, password)
    if error:
        raise ValueError(error)
    boxes = toggles.read_mailboxes(phpconf_dir)
    return [{"user": u, "quota_bytes": b["quota_bytes"]} for u, b in sorted(boxes.items())]


@mcp.tool
def self_reset_mailbox_password(user: str, password: str) -> str:
    """[Tenant-scoped] Reset a mailbox's password."""
    tenant = _require_tenant_access()
    error = toggles.reset_mailbox_password(Path(tenant.phpconf_host_path), user, password)
    if error:
        raise ValueError(error)
    return f"password reset for {user}"


@mcp.tool
def self_delete_mailbox(user: str) -> str:
    """[Tenant-scoped] Delete a mailbox."""
    tenant = _require_tenant_access()
    error = toggles.delete_mailbox(Path(tenant.phpconf_host_path), user)
    if error:
        raise ValueError(error)
    return f"deleted {user}"


@mcp.tool
def self_set_mailbox_quota(user: str, quota_mb: int | None = None) -> str:
    """[Tenant-scoped] Set a mailbox's quota in MB, or omit/null for unlimited."""
    tenant = _require_tenant_access()
    quota_bytes = quota_mb * 1024 * 1024 if quota_mb else None
    error = toggles.set_mailbox_quota(Path(tenant.phpconf_host_path), user, quota_bytes)
    if error:
        raise ValueError(error)
    return f"quota set for {user}"


@mcp.tool
def self_list_backups() -> list[dict]:
    """[Tenant-scoped] List this tenant's own backups (operator destination)."""
    tenant = _require_tenant_access()
    return [asdict(b) for b in registry.list_backups(tenant.domain, destination="operator")]


@mcp.tool
def self_create_backup() -> list[dict]:
    """[Tenant-scoped] Create a backup of this tenant right now."""
    tenant = _require_tenant_access()
    return [asdict(b) for b in backup.create_backup(tenant.domain, actor=_tenant_actor())]


@mcp.tool
def self_restore_backup(snapshot_name: str) -> str:
    """[Tenant-scoped] Restore a snapshot in place -- always this tenant's own domain, never a different one."""
    tenant = _require_tenant_access()
    backup.restore_backup(tenant.domain, snapshot_name, source="operator", target_domain=None, actor=_tenant_actor())
    return "restored"


@mcp.tool
def self_logs(file: str | None = None) -> dict:
    """[Tenant-scoped] Tail this tenant's own logs. Omit `file` for all of them."""
    tenant = _require_tenant_access()
    logs_dir = Path(tenant.logs_host_path)
    valid_files = [f for f, _ in toggles.LOG_FILES]
    if file:
        if file not in valid_files:
            raise ValueError(f"unknown log file, must be one of: {', '.join(valid_files)}")
        return {file: toggles.tail_log(logs_dir, file)}
    return {f: toggles.tail_log(logs_dir, f) for f in valid_files}


def main():
    # Same "opt-in means genuinely absent" posture as api.py not
    # registering its Blueprint when this is off -- refuses to bind at
    # all rather than starting and 401ing every call. Own flag, separate
    # from API_ENABLED (config.py's docstring on MCP_ENABLED explains why
    # they're no longer coupled) -- this unit can be installed/enabled by
    # provisioner.enable_mcp_server() without the REST API also being on.
    if not MCP_ENABLED:
        print(
            "VHSP_MCP_ENABLED is not set -- refusing to start (this is an "
            "opt-in feature; see config.py's MCP_ENABLED docstring)",
            file=sys.stderr,
        )
        sys.exit(1)
    mcp.run(transport="http", host=MCP_BIND_HOST, port=MCP_BIND_PORT)


if __name__ == "__main__":
    main()
