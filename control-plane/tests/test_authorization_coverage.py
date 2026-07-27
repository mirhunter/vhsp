"""Static checks over the authorization decorators and MCP tool guards.

These read source rather than importing and exercising the apps, on
purpose. The properties being asserted are structural -- "every tool
declares a scope", "this route is gated" -- and a source-level check
holds even for routes whose runtime needs (Docker, a live registry, a
real WebAuthn ceremony) make them awkward to drive in a unit test. That
tradeoff is what makes it cheap enough to cover *every* tool instead of
a sampled few.

Two of the three checks here are regression guards for bugs that were
actually found in this codebase rather than imagined:

  * the MCP scope split -- operator tools were once reachable with a
    tenant token, a full privilege escalation, found live during that
    feature's own verification;
  * the /email 2FA gate -- the operator-side route was ungated while the
    bulk mailbox-reset button beside it was gated, so the gate could be
    walked around one mailbox at a time.
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MCP_SERVER = REPO / "vhsp_ctl" / "mcp_server.py"
WEB = REPO / "vhsp_ctl" / "web.py"

OPERATOR_GUARD = "_require_operator_access"
TENANT_GUARD = "_require_tenant_access"


def _decorated_functions(source_path, decorator_name):
    """Every top-level function carrying the named decorator, as AST nodes."""
    tree = ast.parse(source_path.read_text())
    found = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name == decorator_name:
                found.append(node)
                break
    return found


def _calls_in(node):
    return {
        getattr(c.func, "id", None) or getattr(c.func, "attr", None)
        for c in ast.walk(node) if isinstance(c, ast.Call)
    }


def _mcp_tools():
    return _decorated_functions(MCP_SERVER, "tool")


def test_mcp_tools_are_discovered_at_all():
    """Guards the guard: if the decorator shape ever changes, the checks
    below would silently pass over an empty list."""
    assert len(_mcp_tools()) >= 30


@pytest.mark.parametrize("fn", _mcp_tools(), ids=lambda f: f.name)
def test_every_mcp_tool_declares_exactly_one_scope(fn):
    calls = _calls_in(fn)
    guards = {g for g in (OPERATOR_GUARD, TENANT_GUARD) if g in calls}
    assert guards, (
        f"MCP tool {fn.name!r} calls neither {OPERATOR_GUARD}() nor "
        f"{TENANT_GUARD}() -- an unguarded tool is reachable by BOTH token "
        f"kinds, since one shared verifier authenticates both."
    )
    assert len(guards) == 1, (
        f"MCP tool {fn.name!r} calls both scope guards; a tool must belong "
        f"to exactly one side of the operator/tenant boundary."
    )


@pytest.mark.parametrize("fn", _mcp_tools(), ids=lambda f: f.name)
def test_tenant_scoped_mcp_tools_take_no_domain_parameter(fn):
    """A tenant-scoped tool must derive its tenant from the token alone.
    Accepting a domain argument would reintroduce cross-tenant addressing
    even with the scope guard in place."""
    if TENANT_GUARD not in _calls_in(fn):
        pytest.skip("operator-scoped tool")
    params = [a.arg for a in fn.args.args]
    assert "domain" not in params, (
        f"tenant-scoped tool {fn.name!r} accepts a `domain` parameter"
    )


# Routes whose blast radius the project has decided warrants a second
# factor. Each entry is a view function name in web.py.
MUST_REQUIRE_2FA = [
    "tenant_destroy",
    "tenant_email",                     # resets individual mailbox passwords
    "tenant_reset_mailbox_passwords",
    "tenant_reset_db_password",
    "tenant_reset_panel_access",
    "tenant_reset_all_passwords",
    "tenant_set_admin_password",
    "tenant_set_ssh_key",
    "tenant_clear_webauthn",
    "tenant_clear_totp",
    "operator_add",
    "operator_remove",
    "operator_reset_password",
    "api_tokens_view",
    "platform_access_toggle",
    "tenant_platform_access_toggle",
]


@pytest.mark.parametrize("view_name", MUST_REQUIRE_2FA)
def test_high_blast_radius_operator_routes_require_2fa(view_name):
    gated = {fn.name for fn in _decorated_functions(WEB, "require_2fa")}
    assert view_name in gated, (
        f"{view_name!r} lost its @require_2fa decorator -- this route can "
        f"destroy a tenant, reveal or set a credential, or change who can "
        f"reach the control plane."
    )


def test_every_2fa_route_also_requires_auth():
    """require_2fa stacks with require_auth rather than replacing it."""
    authed = {fn.name for fn in _decorated_functions(WEB, "require_auth")}
    for fn in _decorated_functions(WEB, "require_2fa"):
        assert fn.name in authed, f"{fn.name!r} has @require_2fa without @require_auth"


def test_no_third_party_scripts_in_the_operator_ui():
    """The login page renders the operator credential form, so a remote
    script anywhere in this file runs with DOM access to it -- and there is
    no CSP to fall back on. Vendored assets are served from /static
    instead; see the login page's own comment."""
    remote = re.findall(r'<(?:script|link)[^>]+(?:src|href)="(https?://[^"]+)"', WEB.read_text())
    assert not remote, f"remote asset(s) referenced in the operator UI: {remote}"
