"""Operator REST API -- a Flask Blueprint, the first one in this
codebase (web.py is otherwise one flat module, ~50 routes directly on
`app`; this is kept separate given its size and because it has a
genuinely different auth model from the rest of web.py -- bearer
tokens, not session cookies).

Same "thin wrapper over provisioner.py/backup.py/registry.py/audit.py"
shape cli.py and web.py's own routes already both use -- no business
logic lives here, only request parsing, auth, and JSON shaping. See
architecture.md's "API and MCP access for operators and tenants"
section for why this exists and what it's deliberately scoped to (v1:
tenant list/get/create/destroy/usage, backups list/create/restore,
audit verify, fail2ban log -- NOT the secret-revealing incident-response
resets, which stay web-UI/CLI-only for now).

Only registered onto the app at all when config.API_ENABLED is true --
see web.py's own registration call. When it's false, none of these
routes exist, not just 401/403.
"""

import subprocess
from dataclasses import asdict
from pathlib import Path

from flask import Blueprint, g, jsonify, render_template_string, request, url_for

from vhsp_ctl import audit, backup, provisioner, registry, tenant_api_auth, toggles
from vhsp_ctl.api_auth import validate_token

api_bp = Blueprint("api", __name__)

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "VHSP Operator API",
        "version": "1",
        "description": (
            "Programmatic access to the same control-plane operations the operator admin UI "
            "exposes. Opt-in (disabled by default) and reachable only with a bearer token "
            "minted from an already-2FA-authenticated session -- see the admin UI's "
            "My account -> API access page. This is a deliberately conservative v1: read "
            "operations, tenant lifecycle, and backups only. Secret-revealing incident-response "
            "actions (password resets, etc.) are not exposed here yet. The /self/* paths are a "
            "separate, tenant-scoped surface: a tenant's own bearer token (minted from their own "
            "panel, not this one) reaches only their own self-service operations, gated by a "
            "two-layer permission model (operator-allowed, then tenant-enabled) -- an operator "
            "token can't reach /self/*, and a tenant token can't reach anything else."
        ),
    },
    "servers": [{"url": "/api/v1"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "Error": {
                "type": "object",
                "properties": {"error": {"type": "string"}},
            },
        },
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/tenants": {
            "get": {
                "summary": "List active tenants",
                "operationId": "listTenants",
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create a new tenant",
                "operationId": "createTenant",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["domain"],
                        "properties": {"domain": {"type": "string"}},
                    }}},
                },
                "responses": {
                    "201": {"description": "Created"},
                    "400": {"description": "Provisioning error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}},
                },
            },
        },
        "/tenants/{domain}": {
            "get": {
                "summary": "Get one tenant (secrets redacted)",
                "operationId": "getTenant",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}, "404": {"description": "Not found"}},
            },
            "delete": {
                "summary": "Destroy a tenant and free its resources",
                "operationId": "destroyTenant",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"204": {"description": "Destroyed"}, "400": {"description": "Provisioning error"}},
            },
        },
        "/tenants/{domain}/usage": {
            "get": {
                "summary": "Disk usage (web/db/mail/total, bytes)",
                "operationId": "getTenantUsage",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}, "400": {"description": "Provisioning error"}},
            },
        },
        "/tenants/{domain}/backups": {
            "get": {
                "summary": "List a tenant's backups",
                "operationId": "listTenantBackups",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "summary": "Create a backup now",
                "operationId": "createTenantBackup",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"201": {"description": "Created"}, "400": {"description": "Backup error"}},
            },
        },
        "/tenants/{domain}/restore": {
            "post": {
                "summary": "Restore a snapshot",
                "operationId": "restoreTenantBackup",
                "parameters": [{"name": "domain", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["snapshot_name"],
                        "properties": {
                            "snapshot_name": {"type": "string"},
                            "source": {"type": "string", "enum": ["operator", "tenant"], "default": "operator"},
                            "target_domain": {"type": "string", "description": "Restore as a different domain; omit to restore in place."},
                        },
                    }}},
                },
                "responses": {"200": {"description": "Restored"}, "400": {"description": "Backup error"}},
            },
        },
        "/audit/verify": {
            "get": {
                "summary": "Verify the audit log's hash chain is intact",
                "operationId": "verifyAudit",
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/fail2ban/log": {
            "get": {
                "summary": "Tail fail2ban's own log (every jail mixed together)",
                "operationId": "getFail2banLog",
                "parameters": [{"name": "lines", "in": "query", "required": False, "schema": {"type": "integer", "default": 200, "minimum": 1, "maximum": 2000}}],
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/self": {
            "get": {
                "summary": "[Tenant-scoped] This tenant's own overview: domain, disk usage, quota",
                "operationId": "selfOverview",
                "responses": {"200": {"description": "OK"}, "403": {"description": "Not allowed/enabled for this tenant"}},
            },
        },
        "/self/php-functions": {
            "get": {"summary": "[Tenant-scoped] Get enabled PHP functions", "operationId": "selfGetPhpFunctions", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set enabled PHP functions",
                "operationId": "selfSetPhpFunctions",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"enabled": {"type": "array", "items": {"type": "string"}}}}}}},
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/self/fallback": {
            "get": {"summary": "[Tenant-scoped] Get 404 fallback state", "operationId": "selfGetFallback", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set 404 fallback state",
                "operationId": "selfSetFallback",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"enabled": {"type": "boolean"}}}}}},
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/self/auth": {
            "get": {"summary": "[Tenant-scoped] Get password-protection (Basic Auth) state", "operationId": "selfGetAuth", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set or disable password protection",
                "operationId": "selfSetAuth",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                    "action": {"type": "string", "enum": ["save", "disable"]},
                    "username": {"type": "string"}, "password": {"type": "string"},
                }}}}},
                "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/error-pages": {
            "get": {"summary": "[Tenant-scoped] Get custom error page mappings", "operationId": "selfGetErrorPages", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set custom error page mappings",
                "operationId": "selfSetErrorPages",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"lines": {"type": "string", "description": "One 'CODE /path' per line"}}}}}},
                "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/redirects": {
            "get": {"summary": "[Tenant-scoped] Get redirects", "operationId": "selfGetRedirects", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set redirects",
                "operationId": "selfSetRedirects",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"lines": {"type": "string", "description": "One '/from target' per line"}}}}}},
                "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/noexec-dirs": {
            "get": {"summary": "[Tenant-scoped] Get no-exec directories", "operationId": "selfGetNoexecDirs", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set no-exec directories",
                "operationId": "selfSetNoexecDirs",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"lines": {"type": "string", "description": "One relative path per line"}}}}}},
                "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/ip-acl": {
            "get": {"summary": "[Tenant-scoped] Get IP allow/deny list", "operationId": "selfGetIpAcl", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Set IP allow/deny list",
                "operationId": "selfSetIpAcl",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                    "mode": {"type": "string", "enum": ["", "allow", "deny"]}, "lines": {"type": "string"},
                }}}}},
                "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/mailboxes": {
            "get": {"summary": "[Tenant-scoped] List mailboxes", "operationId": "selfListMailboxes", "responses": {"200": {"description": "OK"}}},
            "post": {
                "summary": "[Tenant-scoped] Add, reset, delete, or set quota on a mailbox",
                "operationId": "selfMailboxAction",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["action", "user"], "properties": {
                    "action": {"type": "string", "enum": ["add", "reset", "delete", "quota"]},
                    "user": {"type": "string"}, "password": {"type": "string"}, "quota_mb": {"type": "integer"},
                }}}}},
                "responses": {"200": {"description": "OK"}, "201": {"description": "Mailbox added"}, "400": {"description": "Validation error"}},
            },
        },
        "/self/backups": {
            "get": {"summary": "[Tenant-scoped] List this tenant's own backups (operator destination)", "operationId": "selfListBackups", "responses": {"200": {"description": "OK"}}},
            "post": {"summary": "[Tenant-scoped] Create a backup now", "operationId": "selfCreateBackup", "responses": {"201": {"description": "Created"}, "400": {"description": "Backup error"}}},
        },
        "/self/backups/restore": {
            "post": {
                "summary": "[Tenant-scoped] Restore a snapshot in place (always this tenant's own domain -- no target_domain option)",
                "operationId": "selfRestoreBackup",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["snapshot_name"], "properties": {"snapshot_name": {"type": "string"}}}}}},
                "responses": {"200": {"description": "Restored"}, "400": {"description": "Backup error"}},
            },
        },
        "/self/logs": {
            "get": {
                "summary": "[Tenant-scoped] Tail this tenant's own logs",
                "operationId": "selfLogs",
                "parameters": [{"name": "file", "in": "query", "required": False, "schema": {"type": "string"}, "description": "One of the known log filenames; omit for all of them"}],
                "responses": {"200": {"description": "OK"}, "400": {"description": "Unknown log file"}},
            },
        },
    },
}


def require_api_token(view):
    """Same shape as web.py's require_auth/require_2fa (a decorator
    checking one thing and aborting with a JSON error, not a redirect --
    there's no login page to send an API client to). Attaches the
    resolved operator username to flask.g so handlers can pass it as
    `actor` into provisioner.py/backup.py calls -- every one of those
    already accepts an actor parameter for the audit trail, same as the
    CLI passing "cli" and web.py passing "admin-ui:<username>"; API
    calls pass "api:<username>" so `vhsp audit verify`'s trail shows
    who actually did what, not a generic actor."""
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(error="missing or malformed Authorization header"), 401
        token = auth_header[len("Bearer "):].strip()
        username = validate_token(token)
        if not username:
            return jsonify(error="invalid or revoked token"), 401
        g.api_operator = username
        return view(*args, **kwargs)
    return wrapped


def _actor() -> str:
    return f"api:{g.api_operator}"


@api_bp.route("/openapi.json")
def openapi_spec():
    return jsonify(OPENAPI_SPEC)


DOCS_PAGE = """
<!doctype html>
<html>
<head>
  <title>VHSP Operator API</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='swagger-ui.css') }}">
  <style>body { margin: 0; }</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="{{ url_for('static', filename='swagger-ui-bundle.js') }}"></script>
  <script src="{{ url_for('static', filename='swagger-ui-standalone-preset.js') }}"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: "{{ url_for('api.openapi_spec') }}",
        dom_id: "#swagger-ui",
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout",
        persistAuthorization: true
      });
    };
  </script>
</body>
</html>
"""


@api_bp.route("/docs")
def docs_view():
    """No auth required to *load* this page -- it's a static UI shell,
    same as how a login page itself needs no login. Every actual API
    call it makes still needs a real bearer token, entered via Swagger
    UI's own "Authorize" button (wired automatically from
    OPENAPI_SPEC's securitySchemes.bearerAuth -- no custom JS needed for
    that part)."""
    return render_template_string(DOCS_PAGE)


@api_bp.route("/tenants", methods=["GET"])
@require_api_token
def list_tenants():
    tenants = registry.list_tenants()
    return jsonify([registry.tenant_to_dict(t) for t in tenants])


@api_bp.route("/tenants", methods=["POST"])
@require_api_token
def create_tenant():
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip()
    if not domain:
        return jsonify(error="domain is required"), 400
    try:
        tenant = provisioner.create_tenant(domain, actor=_actor())
    except provisioner.ProvisioningError as e:
        return jsonify(error=str(e)), 400
    return jsonify(registry.tenant_to_dict(tenant)), 201


@api_bp.route("/tenants/<domain>", methods=["GET"])
@require_api_token
def get_tenant(domain):
    tenant = registry.get_tenant(domain)
    if not tenant:
        return jsonify(error=f"no active tenant for {domain!r}"), 404
    return jsonify(registry.tenant_to_dict(tenant))


@api_bp.route("/tenants/<domain>", methods=["DELETE"])
@require_api_token
def destroy_tenant(domain):
    try:
        provisioner.destroy_tenant(domain, actor=_actor())
    except provisioner.ProvisioningError as e:
        return jsonify(error=str(e)), 400
    return "", 204


@api_bp.route("/tenants/<domain>/usage", methods=["GET"])
@require_api_token
def tenant_usage(domain):
    try:
        return jsonify(provisioner.get_tenant_disk_usage(domain))
    except provisioner.ProvisioningError as e:
        return jsonify(error=str(e)), 400


@api_bp.route("/tenants/<domain>/backups", methods=["GET"])
@require_api_token
def list_tenant_backups(domain):
    from dataclasses import asdict
    return jsonify([asdict(b) for b in registry.list_backups(domain)])


@api_bp.route("/tenants/<domain>/backups", methods=["POST"])
@require_api_token
def create_tenant_backup(domain):
    from dataclasses import asdict
    try:
        created = backup.create_backup(domain, actor=_actor())
    except backup.BackupError as e:
        return jsonify(error=str(e)), 400
    return jsonify([asdict(b) for b in created]), 201


@api_bp.route("/tenants/<domain>/restore", methods=["POST"])
@require_api_token
def restore_tenant_backup(domain):
    body = request.get_json(silent=True) or {}
    snapshot_name = (body.get("snapshot_name") or "").strip()
    if not snapshot_name:
        return jsonify(error="snapshot_name is required"), 400
    source = body.get("source", "operator")
    target_domain = body.get("target_domain") or None
    try:
        tenant = backup.restore_backup(
            domain, snapshot_name, source=source, target_domain=target_domain, actor=_actor(),
        )
    except backup.BackupError as e:
        return jsonify(error=str(e)), 400
    return jsonify(registry.tenant_to_dict(tenant))


@api_bp.route("/audit/verify", methods=["GET"])
@require_api_token
def verify_audit():
    intact, count = audit.verify_chain()
    return jsonify(intact=intact, entries_checked=count)


@api_bp.route("/fail2ban/log", methods=["GET"])
@require_api_token
def fail2ban_log():
    try:
        n = int(request.args.get("lines", 200))
    except ValueError:
        return jsonify(error="lines must be an integer"), 400
    try:
        content = provisioner.tail_fail2ban_log(n)
    except subprocess.CalledProcessError as e:
        return jsonify(error=(e.stderr or str(e)).strip()), 400
    return jsonify(log=content)


# --- Tenant-scoped API (/self/*) ------------------------------------
#
# Everything below is reached with a tenant token (tenant_api_auth.py),
# never an operator one -- see that module's own docstring for why
# storage/validation is a completely separate mechanism from
# api_auth.py's operator tokens, and require_tenant_api_token's own
# docstring for the two-layer permission check every one of these routes
# goes through before running at all. No route here accepts a domain
# parameter -- the tenant is always g.api_tenant, resolved entirely from
# the token itself, so a tenant token can never be used to address a
# different tenant's data even by a caller's mistake. Thin wrappers
# around the exact same toggles.py functions web.py's own operator-side
# tenant_php/tenant_email/etc. routes already call -- see toggles.py's
# own module docstring on why operating on host paths directly (not
# through the tenant's own container) is the established pattern here,
# not new for this feature.


def require_tenant_api_token(view):
    """Same shape as require_api_token above, but for tenant tokens.
    Also enforces both halves of the two-layer permission model live, on
    every single call -- api_allowed AND api_enabled must both be true
    right now, not just at some earlier point (see
    provisioner.tenant_platform_access's own docstring on why nothing in
    this model is cached) -- or this 403s regardless of whether the
    token itself is otherwise valid. An operator revoking Layer 1 takes
    effect on this tenant's very next call, not after any restart."""
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(error="missing or malformed Authorization header"), 401
        token = auth_header[len("Bearer "):].strip()
        tenant = tenant_api_auth.validate_tenant_token(token)
        if not tenant:
            return jsonify(error="invalid or revoked token"), 401
        access = provisioner.tenant_platform_access(tenant.domain)
        if not access["api_allowed"]:
            return jsonify(error="REST API access has not been allowed for this tenant by its operator"), 403
        if not access["api_enabled"]:
            return jsonify(error="REST API access is allowed but not currently turned on -- enable it from this tenant's own panel"), 403
        g.api_tenant = tenant
        return view(*args, **kwargs)
    return wrapped


def _tenant_actor() -> str:
    return f"api:tenant:{g.api_tenant.domain}"


def _tenant_dirs(tenant: registry.Tenant) -> tuple[Path, Path, Path]:
    return Path(tenant.phpconf_host_path), Path(tenant.webroot_host_path), Path(tenant.logs_host_path)


@api_bp.route("/self", methods=["GET"])
@require_tenant_api_token
def self_overview():
    tenant = g.api_tenant
    usage = provisioner.get_tenant_disk_usage(tenant.domain)
    quota_limit = provisioner.get_tenant_quota_limit(tenant.domain)
    return jsonify(domain=tenant.domain, usage=usage, quota_limit_bytes=quota_limit)


@api_bp.route("/self/php-functions", methods=["GET", "POST"])
@require_tenant_api_token
def self_php_functions():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        toggles.write_enabled_functions(phpconf_dir, set(body.get("enabled", [])))
    return jsonify(
        enabled=sorted(toggles.read_enabled_functions(phpconf_dir)),
        available=[fn for fn, _ in toggles.FUNCTIONS],
    )


@api_bp.route("/self/fallback", methods=["GET", "POST"])
@require_tenant_api_token
def self_fallback():
    _, webroot_dir, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        toggles.set_fallback_enabled(webroot_dir, bool(body.get("enabled", True)))
    return jsonify(enabled=toggles.fallback_enabled(webroot_dir))


@api_bp.route("/self/auth", methods=["GET", "POST"])
@require_tenant_api_token
def self_basic_auth():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        if body.get("action") == "disable":
            toggles.disable_basic_auth(phpconf_dir)
        else:
            error = toggles.set_basic_auth(phpconf_dir, body.get("username", ""), body.get("password", ""))
            if error:
                return jsonify(error=error), 400
    username = toggles.read_basic_auth_user(phpconf_dir)
    return jsonify(enabled=bool(username), username=username)


@api_bp.route("/self/error-pages", methods=["GET", "POST"])
@require_tenant_api_token
def self_error_pages():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        error = toggles.write_lines_file(phpconf_dir, "error_pages.txt", body.get("lines", ""), toggles.validate_error_page_line)
        if error:
            return jsonify(error=error), 400
    return jsonify(lines=toggles.read_lines_file(phpconf_dir, "error_pages.txt"))


@api_bp.route("/self/redirects", methods=["GET", "POST"])
@require_tenant_api_token
def self_redirects():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        error = toggles.write_lines_file(phpconf_dir, "redirects.txt", body.get("lines", ""), toggles.validate_redirect_line)
        if error:
            return jsonify(error=error), 400
    return jsonify(lines=toggles.read_lines_file(phpconf_dir, "redirects.txt"))


@api_bp.route("/self/noexec-dirs", methods=["GET", "POST"])
@require_tenant_api_token
def self_noexec_dirs():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        error = toggles.write_lines_file(phpconf_dir, "noexec_dirs.txt", body.get("lines", ""), toggles.validate_noexec_dir_line)
        if error:
            return jsonify(error=error), 400
    return jsonify(lines=toggles.read_lines_file(phpconf_dir, "noexec_dirs.txt"))


@api_bp.route("/self/ip-acl", methods=["GET", "POST"])
@require_tenant_api_token
def self_ip_acl():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        error = toggles.write_ip_acl(phpconf_dir, body.get("mode", ""), body.get("lines", ""))
        if error:
            return jsonify(error=error), 400
    mode, lines = toggles.read_ip_acl(phpconf_dir)
    return jsonify(mode=mode, lines=lines)


@api_bp.route("/self/mailboxes", methods=["GET"])
@require_tenant_api_token
def self_list_mailboxes():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    boxes = toggles.read_mailboxes(phpconf_dir)
    return jsonify([{"user": u, "quota_bytes": b["quota_bytes"]} for u, b in sorted(boxes.items())])


@api_bp.route("/self/mailboxes", methods=["POST"])
@require_tenant_api_token
def self_mailbox_action():
    phpconf_dir, _, _ = _tenant_dirs(g.api_tenant)
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    user = body.get("user", "")
    if action == "add":
        error = toggles.add_mailbox(phpconf_dir, user, body.get("password", ""))
        status_code = 201
    elif action == "reset":
        error = toggles.reset_mailbox_password(phpconf_dir, user, body.get("password", ""))
        status_code = 200
    elif action == "delete":
        error = toggles.delete_mailbox(phpconf_dir, user)
        status_code = 200
    elif action == "quota":
        quota_mb = body.get("quota_mb")
        quota_bytes = int(quota_mb) * 1024 * 1024 if quota_mb else None
        error = toggles.set_mailbox_quota(phpconf_dir, user, quota_bytes)
        status_code = 200
    else:
        return jsonify(error="unknown action -- must be one of: add, reset, delete, quota"), 400
    if error:
        return jsonify(error=error), 400
    boxes = toggles.read_mailboxes(phpconf_dir)
    return jsonify([{"user": u, "quota_bytes": b["quota_bytes"]} for u, b in sorted(boxes.items())]), status_code


@api_bp.route("/self/backups", methods=["GET"])
@require_tenant_api_token
def self_list_backups():
    return jsonify([asdict(b) for b in registry.list_backups(g.api_tenant.domain, destination="operator")])


@api_bp.route("/self/backups", methods=["POST"])
@require_tenant_api_token
def self_create_backup():
    try:
        created = backup.create_backup(g.api_tenant.domain, actor=_tenant_actor())
    except backup.BackupError as e:
        return jsonify(error=str(e)), 400
    return jsonify([asdict(b) for b in created]), 201


@api_bp.route("/self/backups/restore", methods=["POST"])
@require_tenant_api_token
def self_restore_backup():
    body = request.get_json(silent=True) or {}
    snapshot_name = (body.get("snapshot_name") or "").strip()
    if not snapshot_name:
        return jsonify(error="snapshot_name is required"), 400
    try:
        # source="operator", target_domain always None -- a tenant token
        # may only restore its own domain in place, never create or
        # overwrite an arbitrary other tenant, unlike the operator-level
        # restore route which accepts target_domain for exactly that use
        # case.
        backup.restore_backup(g.api_tenant.domain, snapshot_name, source="operator", target_domain=None, actor=_tenant_actor())
    except backup.BackupError as e:
        return jsonify(error=str(e)), 400
    return jsonify(status="restored")


@api_bp.route("/self/logs", methods=["GET"])
@require_tenant_api_token
def self_logs():
    _, _, logs_dir = _tenant_dirs(g.api_tenant)
    valid_files = [f for f, _ in toggles.LOG_FILES]
    fname = request.args.get("file")
    if fname:
        if fname not in valid_files:
            return jsonify(error=f"unknown log file, must be one of: {', '.join(valid_files)}"), 400
        return jsonify({fname: toggles.tail_log(logs_dir, fname)})
    return jsonify({f: toggles.tail_log(logs_dir, f) for f in valid_files})
