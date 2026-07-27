"""Admin web UI.

Thin Flask front-end over the same provisioner/registry code the `vhsp`
CLI uses -- same trust level, same host, just a second way in. Intended to
be bound to the isolated management-network interface (see config.py's
ADMIN_BIND_HOST), not the tenant-facing gateway. Auth is a single
credential (see auth.py) checked via a login form + server-side session,
not HTTP Basic -- the user's own requirement, to leave room for a 2FA
step between password verification and session establishment (see
login() below) the way Basic Auth's native browser dialog has no clean
way to support. Still a floor, not the MFA/RBAC architecture.md calls
for; see README's "Known gaps" before this goes anywhere less trusted
than a private management network.
"""

import hmac
import json
import secrets
import subprocess
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, get_flashed_messages, jsonify, redirect, render_template_string, request, session, url_for
from markupsafe import Markup, escape

from vhsp_ctl import api_auth, audit, auth, backup, dns_records, fail2ban_allowlist, login_throttle, platform_settings, provisioner, registry, toggles, totp, update_check, waf, webauthn
from vhsp_ctl.config import ADMIN_BIND_HOST, ADMIN_BIND_PORT, ADMIN_SESSION_LIFETIME_MINUTES, ADMIN_TRUST_PROXY, API_ENABLED, BACKUP_INTERVAL_CHOICES, DEFAULT_BACKUP_INTERVAL, DEFAULT_BACKUP_RETENTION_COUNT, TENANT_ADMIN_MGMTWEB_EXISTS, current_api_enabled, current_mcp_enabled, current_update_check_enabled

app = Flask(__name__)
app.secret_key = auth.ensure_secret_key()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Secure can't be hardcoded True: this app is deliberately allowed to run
# on a plain-HTTP-only management network with no proxy in front of it
# (see this file's own module docstring and config.py's ADMIN_TRUST_PROXY
# docstring) -- the same flag that already signals "there's a real
# TLS-terminating hop in front of this" is the right one to reuse here,
# rather than assuming HTTPS unconditionally.
app.config["SESSION_COOKIE_SECURE"] = ADMIN_TRUST_PROXY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=ADMIN_SESSION_LIFETIME_MINUTES)


@app.before_request
def _make_session_permanent():
    """Opts every session (including the pending-2FA, pre-`username` state)
    into PERMANENT_SESSION_LIFETIME above instead of Flask's default
    non-permanent cookie, which carries no expiry at all and would
    otherwise leave a stolen or left-open browser tab's session valid
    forever. Flask refreshes the cookie's expiry on each request by
    default (SESSION_REFRESH_EACH_REQUEST), so this is an idle timeout: an
    operator actively working never hits it, only a session that's sat
    untouched past ADMIN_SESSION_LIFETIME_MINUTES."""
    session.permanent = True


@app.after_request
def _security_headers(response):
    """Three headers with no legitimate reason to differ by deployment
    or page, unlike a real Content-Security-Policy (a follow-up security
    review flagged the header gap; CSP itself is deliberately not here
    -- this app leans on inline <script> throughout, so a CSP that
    actually restricts script-src needs a per-request nonce threaded
    into every one of them, a real refactor worth its own pass with a
    browser available to verify nothing silently breaks, not a one-line
    header add)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # No response here was ever cacheable in principle (every page reflects
    # live state -- tenant lists, credentials, audit entries, DNS-check
    # results), but nothing was ever saying so explicitly either, which a
    # browser can and does fill in with its own heuristics absent any
    # signal. Found while chasing a real report: a live DNS "Check
    # records" result appearing stale/not-live in a real browser when the
    # same request, made directly, correctly showed live -- consistent
    # with the browser serving an earlier cached response instead of
    # re-running the check. This closes that whole class of staleness,
    # not just the one page it was found on.
    response.headers["Cache-Control"] = "no-store"
    return response


# Applies only to self-chosen passwords (/account below) -- auth.create_operator()'s
# own generated passwords (secrets.token_urlsafe(18)) already exceed this by a wide
# margin, so there's nothing to enforce on that path.
MIN_PASSWORD_LENGTH = 12

# Lets TENANT_NAV show a persistent "Maintenance mode" badge on every
# tenant sub-page (not just Overview) without threading a new kwarg
# through all ten tenant_* route functions' render() calls -- they
# already all pass `t`, so the template can just call this itself.
app.jinja_env.globals["tenant_maintenance_enabled"] = provisioner.tenant_maintenance_enabled

if ADMIN_TRUST_PROXY:
    # See config.py's ADMIN_TRUST_PROXY docstring for why this is opt-in and
    # trusts exactly one hop. Werkzeug's own ProxyFix, not hand-rolled --
    # this is exactly the kind of header-trust logic worth using a
    # well-reviewed implementation for rather than parsing X-Forwarded-*
    # by hand.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# Off by default (config.API_ENABLED) -- when disabled, /api/v1/* routes
# don't exist at all, not just 401/403 if hit. See vhsp_ctl/api.py's own
# module docstring for the full design.
if API_ENABLED:
    from vhsp_ctl.api import api_bp
    app.register_blueprint(api_bp, url_prefix="/api/v1")


def csrf_token() -> str:
    """One unpredictable token per session, generated on first access and
    reused for the session's lifetime -- not hand-rolled crypto (it's
    secrets.token_urlsafe, same primitive every other generated credential
    here already uses), just session-scoped storage for it. Registered as
    a Jinja global (below) so every template can call `csrf_token()`
    without each of the ~50 render()/render_template_string() call sites
    needing to pass it explicitly -- same reasoning as this file's
    has_2fa injection into render()."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def _enforce_csrf():
    """Applies to every state-changing request platform-wide, before any
    view function (including its own require_auth/require_2fa decorators)
    ever runs -- deliberately checked even for anonymous requests like the
    login POST itself, since the token is already in the session from the
    login page's own GET. Real HTML forms get the token via a small
    injector script in LAYOUT/AUTH_PAGE (see BASE_CSS's neighboring
    templates) rather than a hidden field hand-added to every one of the
    ~50 forms in this file -- the injector only runs on a page this
    server actually rendered, so a cross-origin attacker page can never
    obtain the right value even though the check itself is simple. The
    WebAuthn JS fetch() calls set the same token as a header instead,
    since they're not native form submissions.

    Exempts the api Blueprint (vhsp_ctl/api.py): those routes authenticate
    with a bearer token in the Authorization header, never a session
    cookie, so they're not susceptible to CSRF in the first place (a
    forged cross-site request has no way to attach a header it doesn't
    know the value of) -- and since there's no browser session, there's
    no session-stored csrf_token to check against anyway, so leaving this
    check in place would reject every legitimate API POST/PUT/DELETE
    unconditionally.
    """
    if request.blueprint == "api":
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf_token")
        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not submitted or not hmac.compare_digest(expected, submitted):
            abort(403, description="csrf")


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def require_2fa(view):
    """Stacks with require_auth rather than replacing it -- operators are
    flat/equal-privilege (no RBAC, see architecture.md's control-plane-auth
    section), so unlike images/tenant-admin/'s identical decorator this
    isn't layered on top of a role check, just auth. Deliberate carrot for
    2FA adoption on genuinely destructive/high-blast-radius actions --
    tenant destroy, the incident-response nuke buttons, credential resets
    that hand an attacker-chosen value to a tenant, operator account
    management (add/remove/reset another operator -- the one category that
    enables persistence within the control plane itself), and the same
    self-service config knobs (PHP functions, redirects, no-exec dirs, IP
    restrictions, backups) images/tenant-admin/'s own file manager and
    those same knobs are gated behind on the tenant side. The idea: an
    operator account compromised without a second factor shouldn't be able
    to do any of this, even though every operator is otherwise
    equal-privilege. Routine, non-destructive actions (viewing a tenant,
    creating one, setting its quota, changing your own password) stay
    ungated -- this isn't a blanket floor, just where the blast radius is
    real. The CLI is a deliberate escape hatch, not an oversight: it
    doesn't go through this decorator at all, so a fresh install with zero
    operators having 2FA yet is never truly locked out of these actions,
    just off the web UI for them until someone registers a key or TOTP."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        if not (webauthn.has_credentials(session["username"]) or totp.has_totp(session["username"])):
            abort(403, description="no_2fa")
        return view(*args, **kwargs)
    return wrapped


@app.errorhandler(403)
def forbidden(e):
    if not session.get("username"):
        return redirect(url_for("login"))
    if getattr(e, "description", None) == "csrf":
        return render("<h2>Your session expired</h2><p class=\"muted\">That form was "
                      "from an old page load. Go back and try again -- reloading the "
                      "page first will pick up a fresh token.</p>"), 403
    if getattr(e, "description", None) == "no_2fa":
        return render("<h2>Two-factor authentication required</h2>"
                      "<p class=\"muted\">This action needs a second factor "
                      "registered on your own operator account first -- a "
                      "security key or an authenticator app, either one. Set "
                      "one up on the <a href=\"/account\">My account</a> page "
                      "(an authenticator app like Google Authenticator or Authy "
                      "takes about two minutes, no hardware needed), then come "
                      "back.</p>"), 403
    return render("<h2>Not available</h2><p class=\"muted\">That action isn't "
                  "available right now.</p>"), 403


# `prefers-color-scheme` rather than a manual toggle -- the user asked for
# "dark mode aware", i.e. follow the browser/OS setting, not a stateful
# preference to build UI for. Shared verbatim across every <style> block
# in this file (and independently duplicated, not imported, in
# images/tenant-admin/app.py -- separate trust boundary, same reasoning
# as every other cross-app duplication in this codebase) so light/dark
# look identical everywhere rather than drifting per-page.
DARK_AWARE_CSS = """
:root {
  /* Without this, Chromium/Firefox fall back to light-mode native
     rendering for residual form-control chrome even under
     appearance:none -- observed as the lone "Log out" button (the only
     submit control in its own bare <form>) rendering with a plain white
     native background no matter what background/color this stylesheet
     set. `light dark` tracks the same prefers-color-scheme media query
     already driving every custom property below, rather than hardcoding
     one branch. */
  color-scheme: light dark;
  --bg: #f6f7f9; --surface: #fff; --surface-2: #fafbfc;
  --fg: #1a1d23; --muted: #6b7280; --border: #e5e7eb;
  --link: #4f46e5; --link-hover: #4338ca;
  --accent: #4f46e5; --accent-fg: #fff; --accent-hover: #4338ca;
  --danger: #dc2626; --danger-fg: #fff; --danger-hover: #b91c1c;
  --danger-bg: #fef2f2; --danger-border: #fecaca; --danger-text: #991b1b;
  --ok-bg: #f0fdf4; --ok-border: #bbf7d0; --ok-text: #166534;
  --warn-bg: #fffbeb; --warn-border: #fde68a; --warn-text: #92400e;
  --code-bg: #f1f2f5; --code-border: #e5e7eb;
  --input-bg: #fff; --input-border: #d1d5db; --input-focus: #4f46e5;
  --row-hover: #f9fafb; --thead-bg: #fafbfc;
  --shadow: 0 1px 2px rgba(16,24,40,.04), 0 1px 3px rgba(16,24,40,.06);
  --radius: 10px; --radius-sm: 6px;
  --quota-track: #eef0f3; --quota-ok: #22c55e; --quota-warn: #eab308; --quota-danger: #ef4444;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101114; --surface: #17181c; --surface-2: #1c1e23;
    --fg: #e8e9ec; --muted: #9199a8; --border: #2a2d34;
    --link: #a5b4fc; --link-hover: #c7d2fe;
    --accent: #6366f1; --accent-fg: #fff; --accent-hover: #7c7ff2;
    --danger: #f87171; --danger-fg: #1a1114; --danger-hover: #fca5a5;
    --danger-bg: #2a1618; --danger-border: #4c2226; --danger-text: #fca5a5;
    --ok-bg: #12241a; --ok-border: #1f3d2a; --ok-text: #86efac;
    --warn-bg: #2a2113; --warn-border: #4a3820; --warn-text: #fcd34d;
    --code-bg: #1e2025; --code-border: #2a2d34;
    --input-bg: #1a1c21; --input-border: #33363e; --input-focus: #818cf8;
    --row-hover: #1c1e23; --thead-bg: #1a1c21;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 2px 6px rgba(0,0,0,.25);
    --quota-track: #262930; --quota-ok: #22c55e; --quota-warn: #eab308; --quota-danger: #ef4444;
  }
}
"""

BASE_CSS = DARK_AWARE_CSS + """
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    margin: 0; background: var(--bg); color: var(--fg); line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--link); text-decoration: none; }
  a:hover { color: var(--link-hover); text-decoration: underline; }
  h1, h2, h3, h4 { font-weight: 650; letter-spacing: -0.01em; line-height: 1.25; }
  h2 { font-size: 1.3rem; margin: 0 0 0.9rem; }
  h3 { font-size: 1.05rem; margin: 1.6rem 0 0.6rem; }
  h4 { font-size: 0.92rem; margin: 1.3rem 0 0.4rem; }
  p { color: var(--fg); }
  .shell { max-width: 1040px; margin: 0 auto; padding: 0 1.5rem 4rem; }

  /* Sticky: the tenant list is the one page here that can genuinely run
     to several thousand pixels, and without this the nav/account controls
     scroll away entirely -- getting anywhere meant scrolling all the way
     back to the top. z-index beats the sticky table header below, which
     has to slide under this rather than over it. */
  .topbar {
    background: var(--surface); border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
    position: sticky; top: 0; z-index: 20;
  }
  /* Two explicit rows -- brand/account on top, nav below -- rather than
     one row with brand+nav+userbar all competing for the same
     horizontal space. That single-row layout was the reason the nav
     needed its own wrap/scroll handling in the first place; splitting
     it into two rows gives the nav a full line to itself instead. */
  .topbar-row {
    max-width: 1040px; margin: 0 auto; padding: 0 1.5rem;
    display: flex; align-items: center; flex-wrap: wrap;
  }
  .topbar-row-account { justify-content: space-between; gap: 0.5rem 1rem; padding-top: 0.7rem; padding-bottom: 0.6rem; }
  .topbar-row-nav { border-top: 1px solid var(--border); padding-top: 0.4rem; padding-bottom: 0.4rem; }
  .brand { font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em; color: var(--fg); white-space: nowrap; }
  .brand:hover { text-decoration: none; color: var(--fg); }
  .topnav { display: flex; flex-wrap: wrap; gap: 0.25rem; }
  .topnav a {
    color: var(--muted); font-size: 0.9rem; font-weight: 500; padding: 0.4rem 0.7rem;
    border-radius: var(--radius-sm); white-space: nowrap;
  }
  .topnav a:hover { color: var(--fg); background: var(--surface-2); text-decoration: none; }
  .topnav a.active { color: var(--accent); background: var(--surface-2); }
  .userbar { display: flex; align-items: center; gap: 0.6rem; font-size: 0.85rem; color: var(--muted); white-space: nowrap; }
  .userbar .btn-ghost { padding: 0.35rem 0.7rem; }

  .subnav { display: flex; flex-wrap: wrap; gap: 0.35rem; margin: 0 0 1.5rem; }
  .subnav a {
    font-size: 0.85rem; font-weight: 500; color: var(--muted); padding: 0.4rem 0.75rem;
    border-radius: 999px; border: 1px solid var(--border); background: var(--surface);
  }
  .subnav a:hover { color: var(--fg); border-color: var(--muted); text-decoration: none; }
  .subnav a.active { color: var(--accent-fg); background: var(--accent); border-color: var(--accent); }

  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: var(--shadow); padding: 1.5rem; margin: 0 0 1.5rem;
  }
  .card > h2:first-child, .card > h3:first-child { margin-top: 0; }

  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  /* Sticky under the (also sticky) topbar -- --topbar-h is measured live
     in LAYOUT's script rather than hardcoded, since the topbar's own
     height changes when its nav wraps on a narrow viewport. The
     border-bottom is redrawn as an inset box-shadow because a collapsed
     table border doesn't travel with a sticky cell (border-collapse
     assigns the shared edge to the row below it, which scrolls away),
     leaving the header visually detached from the rows underneath. */
  thead th {
    background: var(--thead-bg); font-size: 0.78rem; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--muted); font-weight: 600;
    position: sticky; top: var(--topbar-h, 0px); z-index: 10;
    box-shadow: inset 0 -1px 0 var(--border);
  }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--row-hover); }
  /* Client-side row filter (see LAYOUT's script). Deliberately not
     server-side search+pagination: list_tenants() already materializes
     every row anyway, so paginating only the template would save nothing,
     and this platform's container-per-tenant footprint caps a realistic
     deployment well below where that machinery would start to pay for
     itself. Revisit at several hundred tenants with ORDER BY + LIMIT. */
  /* QR codes stay black-on-white in BOTH themes. The SVG qrcode emits
     has a transparent background and a path with no fill attribute (so
     it renders black), which against the dark theme's surface is black
     on near-black -- invisible, and unscannable. The white is padded
     out past the code itself because scanners need that light quiet
     zone to find the symbol at all. Fill is pinned explicitly rather
     than left to the SVG default so a future global `svg { fill:
     currentColor }` rule can't silently break it again. */
  .qr-code { background: #fff; padding: 0.75rem; border-radius: var(--radius-sm); }
  .qr-code svg { display: block; width: 100%; height: auto; }
  .qr-code svg path { fill: #000; }
  .table-filter { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.9rem; }
  .table-filter input[type=search] { max-width: 300px; }
  .table-filter .filter-count { font-size: 0.85rem; white-space: nowrap; }
  /* No overflow-x here, and not because it isn't wanted: `overflow` has
     no effect on a `display: table` element at all, so the rule that used
     to live here was inert -- which is why the one page that genuinely
     needed sideways scrolling had ended up putting `overflow-x:auto` on
     its .card instead. That did work, and broke the sticky header on that
     page (see the DNS table's own comment). If a table ever does need to
     scroll horizontally, wrap it in a real block-level div and set
     `thead th { position: static }` inside that wrapper -- a sticky
     header cannot pin to the topbar from inside a scroll container, and
     silently offsetting it is exactly the bug this replaced. */
  .card table { margin: -1.5rem; width: calc(100% + 3rem); }
  .card table th:first-child, .card table td:first-child { padding-left: 1.5rem; }
  .card table th:last-child, .card table td:last-child { padding-right: 1.5rem; }
  .kv td:first-child { width: 1%; white-space: nowrap; font-weight: 600; color: var(--muted); font-size: 0.85rem; }

  code, pre { background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 4px; }
  code { padding: 0.1rem 0.4rem; font-size: 0.87em; }
  pre { padding: 0.9rem 1rem; overflow-x: auto; }
  pre code { border: none; padding: 0; background: none; }

  form.inline { display: inline; }
  .muted { color: var(--muted); font-size: 0.9em; }
  .badge {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .badge-ok { background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-border); }
  .badge-warn { background: var(--warn-bg); color: var(--warn-text); border: 1px solid var(--warn-border); }
  .dns-row-ok td { background: var(--ok-bg); border-color: var(--ok-border); }
  code.copyable { cursor: pointer; }
  code.copyable:hover { border-color: var(--accent); }
  code.copyable:focus-visible { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent); }
  code.copyable.copied { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok-text); }

  .flash, .warn {
    border-radius: var(--radius-sm); padding: 0.7rem 1rem; margin: 0 0 1.25rem;
    border: 1px solid var(--ok-border); border-left-width: 3px;
    background: var(--ok-bg); color: var(--ok-text); font-size: 0.9rem;
  }
  .flash.error { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger-text); }
  .warn { background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn-text); }

  label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem; }
  .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
  textarea, input[type=text], input[type=password], input[type=email], input[type=number], input[type=search], select {
    width: 100%; font-family: inherit; font-size: 0.92rem; background: var(--input-bg); color: var(--fg);
    border: 1px solid var(--input-border); border-radius: var(--radius-sm); padding: 0.5rem 0.65rem;
    transition: border-color .12s ease, box-shadow .12s ease;
  }
  textarea:focus, input:focus, select:focus {
    outline: none; border-color: var(--input-focus); box-shadow: 0 0 0 3px color-mix(in srgb, var(--input-focus) 22%, transparent);
  }
  textarea { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }
  input::placeholder, textarea::placeholder { color: var(--muted); opacity: 0.7; }
  input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus {
    -webkit-text-fill-color: var(--fg); -webkit-box-shadow: 0 0 0 1000px var(--input-bg) inset; caret-color: var(--fg);
    transition: background-color 5000s ease-in-out 0s;
  }

  button {
    appearance: none; -webkit-appearance: none;
    background: var(--accent); color: var(--accent-fg); border: 1px solid transparent;
    border-radius: var(--radius-sm); padding: 0.5rem 0.9rem; font-size: 0.88rem; font-weight: 600;
    cursor: pointer; transition: background-color .12s ease, box-shadow .12s ease;
  }
  button:hover { background: var(--accent-hover); }
  button:focus-visible { outline: none; box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 30%, transparent); }
  button.danger, button.btn-ghost.danger { background: transparent; color: var(--danger); border-color: var(--danger-border); }
  button.danger:hover { background: var(--danger-bg); }
  button.btn-ghost { background: var(--surface); color: var(--fg); border-color: var(--border); }
  button.btn-ghost:hover { background: var(--surface-2); }
  .danger { color: var(--danger); }

  .quota-bar { background: var(--quota-track); border-radius: 999px; height: 0.6rem; overflow: hidden; margin: 0.5rem 0; max-width: 320px; }
  .quota-bar-fill { height: 100%; border-radius: 999px; }
  .quota-bar-fill.ok { background: var(--quota-ok); }
  .quota-bar-fill.warn { background: var(--quota-warn); }
  .quota-bar-fill.danger { background: var(--quota-danger); }

  .field { margin-bottom: 1rem; }
  .field:last-child { margin-bottom: 0; }
  .actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }

  .docs { max-width: 720px; }
  .docs h3 { scroll-margin-top: 1.25rem; padding-top: 1.75rem; border-top: 1px solid var(--border); }
  .docs h3:first-of-type { padding-top: 0; border-top: none; }
  .docs h4 { scroll-margin-top: 1.25rem; }
  .docs p, .docs li { color: var(--fg); }
  .docs .toc { columns: 2; column-gap: 2rem; }
  .docs .toc li { break-inside: avoid; margin-bottom: 0.3rem; font-size: 0.9rem; }
  .docs .eyebrow { text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; font-weight: 700; color: var(--muted); margin: 0 0 0.25rem; }
"""

LAYOUT = """
<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><title>VHSP Admin</title>
<style>""" + BASE_CSS + """</style>
<div class="topbar">
  <div class="topbar-row topbar-row-account">
    <a class="brand" href="{{ url_for('index') }}">VHSP Admin</a>
    {% if session.get('username') %}
    <div class="userbar">
      <span>{{ session['username'] }}{% if has_2fa %} <span title="Two-factor authentication enabled" aria-label="Two-factor authentication enabled" style="display:inline-flex;vertical-align:middle"><svg width="18" height="15" viewBox="0 0 26 22" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 8V5a4 4 0 0 1 8 0v3"></path><rect x="11" y="8" width="14" height="9" rx="1.6"></rect></g><g stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path fill="none" d="M5 10V7a4 4 0 0 1 8 0v3"></path><rect fill="var(--surface)" x="3" y="10" width="14" height="9" rx="1.6"></rect></g></svg></span>{% endif %}</span>
      <a href="{{ url_for('account') }}" class="btn-ghost" style="border:1px solid var(--border);border-radius:var(--radius-sm);padding:0.35rem 0.7rem;">Account</a>
      <form class="inline" method="post" action="{{ url_for('logout') }}"><button type="submit" class="btn-ghost">Log out</button></form>
    </div>
    {% endif %}
  </div>
  <div class="topbar-row topbar-row-nav">
    <nav class="topnav">
      <a href="{{ url_for('index') }}" class="{{ 'active' if request.path == url_for('index') }}">Tenants</a>
      <a href="{{ url_for('backups_browse') }}" class="{{ 'active' if request.path.startswith('/backups') }}">Backups</a>
      <a href="{{ url_for('dns_view') }}" class="{{ 'active' if request.path == url_for('dns_view') }}">DNS</a>
      <a href="{{ url_for('operators_view') }}" class="{{ 'active' if request.path == url_for('operators_view') }}">Operators</a>
      <a href="{{ url_for('audit_view') }}" class="{{ 'active' if request.path == url_for('audit_view') }}">Audit log</a>
      <a href="{{ url_for('fail2ban_log_view') }}" class="{{ 'active' if request.path == url_for('fail2ban_log_view') }}">fail2ban</a>
      <a href="{{ url_for('fail2ban_allowlist_view') }}" class="{{ 'active' if request.path == url_for('fail2ban_allowlist_view') }}">Allowlist</a>
      <a href="{{ url_for('manual_view') }}" class="{{ 'active' if request.path == url_for('manual_view') }}">Manual</a>
    </nav>
  </div>
</div>
<div class="shell">
{% if update_banner %}
  {# Above the flash loop deliberately: a flash is the result of what you
     just did and is read immediately, this is standing state. Putting it
     below would let a routine "Saved." push it out of view. Only the tag
     and URL are rendered -- never the release body, which is
     attacker-influenced text if a maintainer account is compromised (see
     update_check.py). #}
  <div class="flash" style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap">
    <span>vhsp <strong>{{ update_banner.latest_tag }}</strong> is available.
    This deployment is running {{ update_banner.current_version }}.</span>
    <a href="{{ updating_doc_url }}" target="_blank" rel="noopener noreferrer">How to update</a>
    <a href="{{ update_banner.latest_url }}" target="_blank" rel="noopener noreferrer">Release notes</a>
  </div>
{% endif %}
{% for category, message in get_flashed_messages(with_categories=true) %}
  <div class="flash {{ category }}">{{ message }}</div>
{% endfor %}
{{ body|safe }}
</div>
<script>
  // CSRF: injects the current session's token into every state-changing
  // form on the page rather than a hidden field hand-added to each one --
  // see _enforce_csrf's docstring for why this is a sound defense (this
  // script only ever runs on a page this server actually rendered, so a
  // cross-origin attacker's forged form can never carry the right value
  // even though it doesn't need to guess anything clever). GET forms
  // (e.g. DNS's "Check records") are deliberately skipped -- _enforce_csrf
  // never checks GET requests, so injecting one here only leaked it into
  // the resulting URL/browser history/referrer/access logs for no reason.
  //
  // Also disables + relabels whichever button actually triggered a
  // submit, so a slow action (tenant creation, an API/MCP toggle) reads
  // as "working," not "did my click not register?" -- some destructive
  // buttons cancel via a confirm() dialog first; e.defaultPrevented is
  // already true by the time this listener runs if that happened
  // (inline onsubmit="" handlers run before addEventListener ones), so
  // a cancelled confirm correctly leaves the button alone. Skipped
  // entirely for GET forms, same as the CSRF injection above, and for a
  // stronger reason than "unnecessary": disabling a submitter inside its
  // own submit handler removes it from the form's entry list per the
  // HTML spec (disabled controls don't get submitted), so for a GET form
  // whose whole point IS the clicked button's own name=value (DNS's
  // "Check records": name="check" value="1", no other inputs) this
  // silently turned every click into a plain reload with no query string
  // at all -- confirmed live, this is exactly what broke it.
  document.querySelectorAll('form').forEach(function (f) {
    var isGet = f.method.toLowerCase() === 'get';
    if (!isGet) {
      var i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = '{{ csrf_token() }}';
      f.appendChild(i);
    }
    f.addEventListener('submit', function (e) {
      if (e.defaultPrevented || isGet) return;
      var btn = e.submitter;
      if (btn && btn.tagName === 'BUTTON' && !btn.disabled) {
        btn.disabled = true;
        btn.textContent = 'Working…';
      }
    });
  });

  // Click-to-copy for any <code class="copyable">. Swaps the element's
  // own text to "Copied!" briefly rather than a separate tooltip/toast --
  // no extra DOM element needed, and it's obvious which one just got
  // copied even in a long list. Lives in LAYOUT rather than beside the
  // DNS table it started in: the tenant detail page's generated-password
  // panel needs the same behavior, and a function defined inside one
  // page's own fragment isn't callable from another's.
  function vhspCopyDns(el) {
    const text = el.dataset.full || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      el.dataset.full = text;
      el.textContent = "Copied!";
      el.classList.add("copied");
      setTimeout(() => {
        el.textContent = el.dataset.full;
        el.classList.remove("copied");
      }, 1200);
    });
  }
  // Enter/Space activates the same copy as a click -- these elements are
  // focusable (tabindex="0", role="button") specifically so keyboard-only
  // users can reach the copy action too, not just mouse users.
  function vhspCopyDnsKey(event, el) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      vhspCopyDns(el);
    }
  }

  // Publishes the sticky topbar's real height as --topbar-h so the
  // sticky table headers can sit exactly beneath it. Measured rather
  // than hardcoded because the topbar grows a line whenever its nav
  // wraps, which depends on viewport width and on how many nav entries
  // this build has.
  (function () {
    var bar = document.querySelector('.topbar');
    if (!bar) return;
    var sync = function () {
      document.documentElement.style.setProperty('--topbar-h', bar.offsetHeight + 'px');
    };
    sync();
    if (window.ResizeObserver) new ResizeObserver(sync).observe(bar);
    else window.addEventListener('resize', sync);
  })();

  // Client-side row filter: an <input data-filter-target="some-table-id">
  // hides non-matching rows of that table as you type. Matches against
  // the row's whole text content, so a tenant list filters on domain,
  // account ID, port or date without needing per-column config. Rows
  // marked data-filter-skip (the "nothing here yet" placeholder row) are
  // never filtered or counted.
  document.querySelectorAll('[data-filter-target]').forEach(function (input) {
    var table = document.getElementById(input.getAttribute('data-filter-target'));
    if (!table || !table.tBodies.length) return;
    var rows = Array.prototype.filter.call(table.tBodies[0].rows, function (r) {
      return !r.hasAttribute('data-filter-skip');
    });
    var out = document.querySelector('[data-filter-count="' + input.getAttribute('data-filter-target') + '"]');
    var noun = input.getAttribute('data-filter-noun') || 'row';
    var apply = function () {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (r) {
        var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.hidden = !hit;
        if (hit) shown++;
      });
      if (out) {
        out.textContent = !q ? (rows.length + ' ' + noun + (rows.length === 1 ? '' : 's'))
          : shown ? ('showing ' + shown + ' of ' + rows.length)
          : ('no matches out of ' + rows.length);
      }
    };
    apply();
    input.addEventListener('input', apply);
    // Esc clears, matching what a native search field's own clear
    // affordance does -- with rows hidden there may be nothing left on
    // screen to click, so a keyboard escape hatch matters here.
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && input.value) { input.value = ''; apply(); }
    });
  });
</script>
"""


# Shared shell for the two pre-session pages (login, WebAuthn challenge) --
# same brand/card language as LAYOUT but centered and narrow, since there's
# no nav/session to show yet.
AUTH_PAGE = """
<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1"><title>VHSP Admin -- {{ heading }}</title>
<style>""" + BASE_CSS + """
  body { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .auth-card { width: 100%; max-width: 340px; padding: 0 1.5rem; }
  .auth-brand { text-align: center; font-weight: 700; font-size: 1.15rem; margin-bottom: 1.5rem; letter-spacing: -0.01em; }
</style>
<div class="auth-card">
  <div class="auth-brand">VHSP Admin</div>
  <div class="card">
    <h2>{{ heading }}</h2>
    {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
    {{ body|safe }}
  </div>
</div>
<script>
  document.querySelectorAll('form').forEach(function (f) {
    var isGet = f.method.toLowerCase() === 'get';
    if (!isGet) {
      var i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = '{{ csrf_token() }}';
      f.appendChild(i);
    }
    f.addEventListener('submit', function (e) {
      if (e.defaultPrevented || isGet) return;
      var btn = e.submitter;
      if (btn && btn.tagName === 'BUTTON' && !btn.disabled) {
        btn.disabled = true;
        btn.textContent = 'Working…';
      }
    });
  });
</script>
"""


def humanize_ts(value):
    """Jinja filter: every timestamp in this codebase is generated via
    datetime.now(timezone.utc).isoformat() (added_at, created_at, audit
    ts, token created_at, ...) -- shown raw everywhere, microseconds and
    all (e.g. "2026-07-25T15:27:00.139935+00:00"), found during a real
    usability pass to read as unfinished/developer-facing throughout an
    otherwise polished UI. Falls back to the original value unchanged on
    anything that doesn't parse -- this is display-only, never used for
    anything that depends on the value staying exact."""
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC")


app.jinja_env.filters["humanize_ts"] = humanize_ts


def _update_banner():
    """Banner state for LAYOUT, or None to render nothing.

    Reads only the cached result the timer wrote -- never makes the HTTP
    request itself. A page render must not depend on GitHub being
    reachable, and doing the fetch here would put a network round trip in
    front of every operator page load and hammer the API once per
    request rather than once per day.

    Gated on the live toggle, not the frozen constant, so turning the
    check off hides the banner immediately rather than at the next
    process restart. Never raises: a broken or unreadable cache file
    means no banner, not a 500 on every page in the admin UI.
    """
    if not current_update_check_enabled():
        return None
    try:
        return update_check.banner_state()
    except Exception:
        return None


def render(body_template, **ctx):
    # Available to every template rendered this way without each of the
    # ~15 call sites needing to pass it explicitly -- used by TENANT_NAV
    # to flag which tabs require_2fa gates, same "make the requirement
    # visible before you click, not just after" idea as the tenant-admin
    # side's identical nav treatment.
    has_2fa = webauthn.has_credentials(session.get("username", "")) or totp.has_totp(session.get("username", ""))
    ctx.setdefault("has_2fa", has_2fa)
    body = render_template_string(body_template, **ctx)
    return render_template_string(LAYOUT, body=body, has_2fa=has_2fa,
                                  update_banner=_update_banner(),
                                  updating_doc_url=update_check.UPDATING_DOC_URL)


def get_tenant_or_404(domain):
    t = registry.get_tenant(domain)
    if not t:
        return None, (render("<p class='danger'>no active tenant for {{ domain }}</p>", domain=domain), 404)
    return t, None


def format_mb(n_bytes: int) -> str:
    return f"{n_bytes / (1024 * 1024):.1f} MB"


def format_bytes(n_bytes) -> str:
    """Scales to the unit that actually reads well, unlike format_mb's
    fixed MB -- a real snapshot of a small tenant is tens of KB, which
    format_mb renders as a flat, useless "0.0 MB".
    """
    if n_bytes is None:
        return "--"
    size = float(n_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


app.jinja_env.filters["format_bytes"] = format_bytes


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if login_throttle.is_locked(username):
            error = "Too many failed attempts for this account. Try again in a few minutes."
        elif auth.check(username, password):
            login_throttle.record_success(username)
            if webauthn.has_credentials(username) or totp.has_totp(username):
                # The 2FA seam this comment used to describe -- now
                # actually wired up. Password alone doesn't complete
                # login: stash the username as *pending* and hand off to
                # the 2FA challenge page, which is the only thing that
                # can still set session['username'] from here. Whichever
                # of WebAuthn/TOTP (or both) this operator has registered,
                # that page offers.
                session['pending_username'] = username
                return redirect(url_for("login_2fa", next=request.args.get("next")))
            # No second factor registered yet -- e.g. this deployment's
            # very first-ever login, before there's anything to
            # challenge for. Log straight in; register one from /account
            # afterward to start requiring it.
            session['username'] = username
            audit.log_action("admin.login", username, username, ip=request.remote_addr)
            return redirect(request.args.get("next") or url_for("index"))
        else:
            login_throttle.record_failure(username)
            audit.log_action("admin.login_failed", username, username, ip=request.remote_addr)
            error = "Invalid username or password."
    return render_template_string(AUTH_PAGE, error=error, heading="Log in", body="""
      <form method="post" autocomplete="off">
        <div class="field"><label>Username</label><input name="username" placeholder="username" autocomplete="username" required></div>
        <div class="field"><label>Password</label><input type="password" name="password" placeholder="password" autocomplete="current-password" required></div>
        <button type="submit" style="width:100%">Log in</button>
      </form>
      <!-- A plain link, deliberately not the vendor's own <script> widget.
           Nothing on this page may load third-party JavaScript: it renders
           the operator credential form, so any remote script here runs with
           DOM access to the username/password fields, and a CDN compromise
           or a vendor-side change would be indistinguishable from normal
           operation. There's also no CSP to fall back on (see
           _security_headers' docstring for why that's still outstanding).
           Same reasoning that already keeps CodeMirror and Swagger UI
           vendored locally rather than pulled from a CDN at runtime. -->
      <div style="margin-top:1.25rem;padding-top:1.25rem;border-top:1px solid var(--border);text-align:center">
        <a class="muted" style="font-size:0.85rem" href="https://buymeacoffee.com/AllenStJohn"
           target="_blank" rel="noopener noreferrer">Buy me a coffee</a>
      </div>
    """)


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending = session.get('pending_username')
    if not pending:
        return redirect(url_for("login"))
    has_key = webauthn.has_credentials(pending)
    has_totp = totp.has_totp(pending)
    error = None
    if request.method == "POST":
        if login_throttle.is_locked(pending):
            error = "Too many failed attempts for this account. Try again in a few minutes."
        else:
            code = request.form.get("code", "").strip().replace(" ", "")
            if totp.verify(pending, code):
                login_throttle.record_success(pending)
                session.pop('pending_username', None)
                session['username'] = pending
                audit.log_action("admin.login", pending, pending, ip=request.remote_addr)
                return redirect(request.args.get("next") or url_for("index"))
            login_throttle.record_failure(pending)
            audit.log_action("admin.login_failed", pending, pending, ip=request.remote_addr)
            error = "That code didn't verify -- check the time on your phone/authenticator and try again."
    # Built as a plain Python string, NOT Jinja conditionals inside the
    # string -- AUTH_PAGE only ever substitutes `body` via `{{ body|safe }}`,
    # a single-pass render that inserts this string's characters verbatim
    # rather than re-parsing them as a nested template. `{% if %}` markers
    # written directly into this string are therefore inert text, not
    # logic -- a real bug this exact shape had here until this fix (both
    # sections rendered unconditionally, literal "{% if %}" visible on the
    # page) -- images/tenant-admin/app.py's own login_2fa already got this
    # right by using if/+= in Python instead, which is what this now matches.
    # Same reason the fetch() calls below embed `token` as an f-string
    # value rather than `{{ csrf_token() }}` -- that Jinja syntax would be
    # equally inert here.
    token = csrf_token()
    body = ""
    if has_key:
        body += f"""
      <p class="muted" style="margin-top:0">Insert/tap your security key.</p>
      <div id="webauthn-error" class="flash error" style="display:none"></div>
      <button id="go" type="button" style="width:100%">Use security key</button>
      <script>
        async function go() {{
          const errEl = document.getElementById('webauthn-error');
          errEl.style.display = 'none';
          try {{
            const beginResp = await fetch('/webauthn/authenticate/begin', {{method: 'POST', headers: {{'X-CSRF-Token': '{token}'}}}});
            if (!beginResp.ok) throw new Error((await beginResp.json()).error || 'Could not start authentication.');
            const options = (await beginResp.json()).publicKey;
            const credential = await navigator.credentials.get({{
              publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options)
            }});
            const completeResp = await fetch('/webauthn/authenticate/complete', {{
              method: 'POST',
              headers: {{'Content-Type': 'application/json', 'X-CSRF-Token': '{token}'}},
              body: JSON.stringify(credential.toJSON())
            }});
            const result = await completeResp.json();
            if (!completeResp.ok || !result.ok) throw new Error(result.error || 'Verification failed.');
            window.location = result.next || '/';
          }} catch (e) {{
            errEl.textContent = e.message || String(e);
            errEl.style.display = 'block';
          }}
        }}
        document.getElementById('go').addEventListener('click', go);
      </script>
    """
    if has_key and has_totp:
        body += """<p class="muted" style="text-align:center;margin:1.25rem 0">or</p>"""
    if has_totp:
        body += """
      <form method="post" autocomplete="off">
        <div class="field"><label>Code from your authenticator app</label>
          <input name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="123456" autofocus required></div>
        <button type="submit" style="width:100%">Verify code</button>
      </form>
    """
    return render_template_string(AUTH_PAGE, error=error, heading="Second factor", body=body)


@app.route("/webauthn/authenticate/begin", methods=["POST"])
def webauthn_authenticate_begin():
    if not session.get('pending_username'):
        return jsonify(error="Not in a pending login."), 400
    options, state = webauthn.authenticate_begin(session['pending_username'])
    session['webauthn_state'] = state
    return jsonify(options)


@app.route("/webauthn/authenticate/complete", methods=["POST"])
def webauthn_authenticate_complete():
    pending = session.get('pending_username')
    state = session.get('webauthn_state')
    if not pending or not state:
        return jsonify(ok=False, error="Not in a pending login."), 400
    # Same short-circuit login_2fa's TOTP branch already does. Not because a
    # WebAuthn assertion is guessable -- it isn't -- but because
    # login_throttle.record_failure's contract is "only call this when
    # is_locked() was already False", and without this check the failure
    # path below was extending a lockout it wasn't enforcing.
    if login_throttle.is_locked(pending):
        return jsonify(ok=False, error="Too many failed attempts for this account. Try again in a few minutes."), 400
    if webauthn.authenticate_complete(pending, state, request.get_json(force=True)):
        session.pop('webauthn_state', None)
        session['username'] = session.pop('pending_username')
        audit.log_action("admin.login", session['username'], session['username'], ip=request.remote_addr)
        return jsonify(ok=True, next=request.args.get("next") or url_for("index"))
    audit.log_action("admin.login_failed", pending, pending, ip=request.remote_addr)
    return jsonify(ok=False, error="Security key verification failed."), 400


@app.route("/logout", methods=["POST"])
def logout():
    if session.get('username'):
        audit.log_action("admin.logout", session['username'], session['username'], ip=request.remote_addr)
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@require_auth
def account():
    error = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not auth.check(session['username'], current):
            error = "Current password is incorrect."
        elif not new:
            error = "Enter a new password."
        elif len(new) < MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {MIN_PASSWORD_LENGTH} characters."
        elif new != confirm:
            error = "New password and confirmation don't match."
        else:
            auth.set_password(session['username'], new, actor=f"admin-ui:{session['username']}")
            flash("Password updated.", "ok")
            return redirect(url_for("account"))
    return render("""
      <h2 style="margin-bottom:1.25rem">My account</h2>

      <div class="card">
        <h3 style="margin-top:0">Password</h3>
        <p class="muted">Change the operator login password (username stays <code>{{ username }}</code>).</p>
        {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
        <form method="post" autocomplete="off">
          <div class="field"><label>Current password</label><input type="password" name="current_password" autocomplete="current-password" required></div>
          <div class="field"><label>New password</label><input type="password" name="new_password" autocomplete="new-password" required></div>
          <div class="field"><label>Confirm new password</label><input type="password" name="confirm_password" autocomplete="new-password" required></div>
          <button type="submit">Update password</button>
        </form>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Security keys (WebAuthn)</h3>
        <p class="muted">Only works over the real public hostname
        (<code>https://{{ rp_id }}</code>) -- WebAuthn ties a key to the
        exact origin it was registered on, and that has to be a real domain
        over HTTPS, not the management-network IP.
        {% if keys %}Logging in currently requires one of these keys as a
        second factor.{% else %}No key registered yet -- login is
        password-only until you add one.{% endif %}</p>
        {% if keys|length == 1 %}
        <div class="warn">Only one security key registered. If you lose
        it, there's no self-service recovery for the operator account
        (unlike a tenant's, which you can clear from their own tenant
        page) -- only direct server access. Register a backup key now.</div>
        {% endif %}
        <div id="webauthn-error" class="flash error" style="display:none"></div>
        <div id="webauthn-flash" class="flash" style="display:none"></div>
        <table>
          <thead><tr><th>Name</th><th>Added</th><th></th></tr></thead>
          <tbody>
          {% for k in keys %}
          <tr>
            <td>{{ k.name }}</td>
            <td class="muted">{{ k.added_at|humanize_ts }}</td>
            <td style="text-align:right">
              <form class="inline" method="post" action="{{ url_for('webauthn_remove') }}"
                    onsubmit="return confirm('Remove security key ' + '{{ k.name }}' + '?');">
                <input type="hidden" name="name" value="{{ k.name }}">
                <button class="danger" type="submit">Remove</button>
              </form>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="muted">none registered</td></tr>
          {% endfor %}
          </tbody>
        </table>
        <div class="actions" style="margin-top:1.25rem">
          <input id="key-name" type="text" placeholder="name this key, e.g. YubiKey 5C" style="max-width:260px">
          <button id="register-btn">Register new security key</button>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Authenticator app (TOTP)</h3>
        <p class="muted">An alternative second factor to a security key above -- Google
        Authenticator, Authy, 1Password, or anything else that reads a standard
        <code>otpauth://</code> QR code. Either this or a security key (or both) satisfies
        login's second-factor check; you don't need both.</p>
        {% if totp_enabled %}
        <p>Enabled since <span class="muted">{{ totp_added_at }}</span>.</p>
        <form method="post" action="{{ url_for('totp_remove') }}"
              onsubmit="return confirm('Remove your authenticator app? You will need to set it up again to use it as a second factor.');">
          <button class="danger" type="submit">Remove authenticator app</button>
        </form>
        {% else %}
        <p class="muted">Not set up.</p>
        <a href="{{ url_for('totp_setup') }}"><button type="button">Set up authenticator app</button></a>
        {% endif %}
      </div>

      <div class="card">
        <h3 style="margin-top:0">API access</h3>
        <p class="muted">Programmatic access to this control plane -- REST API and MCP,
        same operations the pages above expose, for scripts or AI agents instead of a browser.
        Currently: REST API <strong>{{ 'on' if api_enabled else 'off' }}</strong>,
        MCP server <strong>{{ 'on' if mcp_enabled else 'off' }}</strong>.
        {% if keys or totp_enabled %}<a href="{{ url_for('api_tokens_view') }}">Manage API &amp; MCP access, and tokens</a>.
        {% else %}Requires a second factor on this account first -- set up a security key or
        authenticator app above, then <a href="{{ url_for('api_tokens_view') }}">manage access and tokens</a>.{% endif %}</p>
      </div>
      <script>
        document.getElementById('register-btn').addEventListener('click', async () => {
          const errEl = document.getElementById('webauthn-error');
          const okEl = document.getElementById('webauthn-flash');
          errEl.style.display = 'none';
          okEl.style.display = 'none';
          const name = document.getElementById('key-name').value.trim();
          if (!name) { errEl.textContent = 'Name the key first.'; errEl.style.display = 'block'; return; }
          try {
            const beginResp = await fetch('/webauthn/register/begin', {method: 'POST', headers: {'X-CSRF-Token': '{{ csrf_token() }}'}});
            if (!beginResp.ok) throw new Error((await beginResp.json()).error || 'Could not start registration.');
            const options = (await beginResp.json()).publicKey;
            const credential = await navigator.credentials.create({
              publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)
            });
            const completeResp = await fetch('/webauthn/register/complete', {
              method: 'POST',
              headers: {'Content-Type': 'application/json', 'X-CSRF-Token': '{{ csrf_token() }}'},
              body: JSON.stringify({name: name, credential: credential.toJSON()})
            });
            const result = await completeResp.json();
            if (!completeResp.ok || !result.ok) throw new Error(result.error || 'Registration failed.');
            window.location.reload();
          } catch (e) {
            errEl.textContent = e.message || String(e);
            errEl.style.display = 'block';
          }
        });
      </script>
    """, error=error, username=session['username'], keys=webauthn.list_credentials(session['username']), rp_id=webauthn.RP_ID,
        totp_enabled=totp.has_totp(session['username']), totp_added_at=totp.get_added_at(session['username']),
        api_enabled=current_api_enabled(), mcp_enabled=current_mcp_enabled())


@app.route("/account/api-tokens", methods=["GET", "POST"])
@require_auth
@require_2fa
def api_tokens_view():
    """Separate route (not folded into /account itself) specifically so
    @require_2fa can gate it -- /account can't be 2FA-gated wholesale
    since it's also where a 2FA-less operator sets one up in the first
    place. This is the concrete mechanism architecture.md's "API and
    MCP access" section anticipated: a token mintable only from an
    already-2FA-authenticated session, not a per-request challenge (not
    a natural fit for API calls, per that section's own reasoning)."""
    error = None
    new_token = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            label = request.form.get("label", "").strip()
            if not label:
                error = "Name this token (e.g. \"laptop script\", \"ops agent\")."
            else:
                new_token = api_auth.mint_token(session["username"], label, actor=f"admin-ui:{session['username']}")
        elif action == "revoke":
            token_id = request.form.get("token_id", "")
            try:
                api_auth.revoke_token(token_id, actor=f"admin-ui:{session['username']}")
                flash("Token revoked.", "ok")
            except api_auth.ApiAuthError as e:
                error = str(e)
    return render("""
      <h2 style="margin-bottom:1.25rem">API &amp; MCP access</h2>
      <p class="muted">Bearer tokens for the REST API (<code>/api/v1</code>{% if api_blueprint_live %}, see
      <a href="{{ url_for('api.docs_view') }}">API docs</a>{% endif %}) and the MCP server -- same
      operations the pages in this admin UI expose, for scripts or AI agents instead of a
      browser. Anyone holding a token can act as you through those two surfaces; treat one
      like a password, not like a bookmark.</p>
      {% if error %}<div class="flash error">{{ error }}</div>{% endif %}

      <div class="card">
        <h3 style="margin-top:0">Platform access</h3>
        <p class="muted">Both off by default platform-wide. Turning the REST API on or off
        restarts this admin UI to apply it -- reload this page in a few seconds afterward.
        Turning MCP on installs and starts its own systemd service, opens a firewall rule
        scoped to the internal Traefik network only (never the public interface), and adds
        its routing entry; turning it off reverses all three.</p>
        <table class="kv">
          <tr>
            <td>REST API</td>
            <td>
              {% if api_enabled %}<span class="badge badge-ok">On</span>{% else %}<span class="muted">Off</span>{% endif %}
              <form class="inline" method="post" action="{{ url_for('platform_access_toggle') }}"
                    onsubmit="return confirm('{{ 'Turn off the REST API? This restarts the admin UI.' if api_enabled else 'Turn on the REST API? This restarts the admin UI.' }}');">
                <input type="hidden" name="action" value="{{ 'disable_api' if api_enabled else 'enable_api' }}">
                <button type="submit" class="{{ 'danger' if api_enabled else '' }}">{{ 'Turn off' if api_enabled else 'Turn on' }}</button>
              </form>
            </td>
          </tr>
          <tr>
            <td>MCP server</td>
            <td>
              {% if mcp_enabled %}<span class="badge badge-ok">On</span>{% else %}<span class="muted">Off</span>{% endif %}
              <form class="inline" method="post" action="{{ url_for('platform_access_toggle') }}"
                    onsubmit="return confirm('{{ 'Turn off the MCP server? This stops it, disables its systemd unit, and removes its firewall rule and routing entry.' if mcp_enabled else 'Turn on the MCP server? This installs and starts its systemd unit, opens a firewall rule, and adds its routing entry.' }}');">
                <input type="hidden" name="action" value="{{ 'disable_mcp' if mcp_enabled else 'enable_mcp' }}">
                <button type="submit" class="{{ 'danger' if mcp_enabled else '' }}">{{ 'Turn off' if mcp_enabled else 'Turn on' }}</button>
              </form>
            </td>
          </tr>
        </table>
      </div>
      {% if new_token %}
      <div class="flash">
        <strong>New token -- shown once, copy it now:</strong><br>
        <code style="word-break:break-all">{{ new_token }}</code>
        <p style="margin-bottom:0">Use it right away:</p>
        <pre style="margin:0.4rem 0 0">curl -H "Authorization: Bearer {{ new_token }}" https://{{ rp_id }}/api/v1/tenants</pre>
      </div>
      {% endif %}
      <div class="card">
        <h3 style="margin-top:0">Existing tokens</h3>
        <table>
          <thead><tr><th>Label</th><th>Created</th><th></th></tr></thead>
          <tbody>
          {% for t in tokens %}
          <tr>
            <td>{{ t.label }}</td>
            <td class="muted">{{ t.created_at|humanize_ts }}</td>
            <td style="text-align:right">
              <form class="inline" method="post" onsubmit="return confirm('Revoke ' + '{{ t.label }}' + '? Anything using it will stop working immediately.');">
                <input type="hidden" name="action" value="revoke">
                <input type="hidden" name="token_id" value="{{ t.token_id }}">
                <button class="danger" type="submit">Revoke</button>
              </form>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="3" class="muted">none yet</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
      <div class="card">
        <h3 style="margin-top:0">Create a new token</h3>
        <form method="post">
          <input type="hidden" name="action" value="create">
          <div class="field"><label>Label</label>
            <input type="text" name="label" placeholder="e.g. laptop script, ops agent" required></div>
          <button type="submit">Create token</button>
        </form>
      </div>
    """, error=error, new_token=new_token, tokens=api_auth.list_tokens(),
        api_enabled=current_api_enabled(), mcp_enabled=current_mcp_enabled(),
        # Deliberately the FROZEN constant, not current_api_enabled() --
        # url_for('api.docs_view') only resolves if the api Blueprint was
        # actually registered on *this* process, which only happens once,
        # at startup, based on API_ENABLED as it was then. A real crash
        # was hit here: right after clicking "Turn on," the settings file
        # (and so current_api_enabled()) already says True, but the old
        # worker -- still finishing this very request during its restart
        # grace period -- never had the Blueprint registered at all,
        # so calling url_for() for it raised BuildError. api_enabled
        # above is fine to be live (it only drives text/badges); this one
        # has to track what's actually routable on the process handling
        # the request right now.
        api_blueprint_live=API_ENABLED, rp_id=webauthn.RP_ID)


def _restart_admin_service_deferred() -> None:
    """Restarts vhsp-admin.service ~2 seconds from now, not immediately.

    A real bug, found live: an immediate `sudo systemctl restart
    vhsp-admin.service` right before returning this route's redirect
    left a genuine race -- the redirect response itself reaches the
    browser fine (gunicorn treats SIGTERM as its own graceful-shutdown
    signal, so the in-flight request completes), but the browser then
    auto-follows that redirect with a brand-new request, and *that* one
    has no such guarantee. `systemctl restart` briefly leaves nothing
    listening on the port at all while it stops the old process and
    starts a new one -- if the redirect-follow lands in that ~1s gap,
    Traefik can't reach any backend and returns a real 502, before the
    new process has even finished booting.

    `sh -c "sleep 2 && sudo systemctl restart ..."` as a detached child
    needs no new sudo grant (the sleep runs as the plain control-plane user; only the
    already-granted systemctl call inside needs privilege) and gives the
    redirect-follow request time to land on the still-alive old worker
    -- showing stale toggle state for a couple seconds, matching the
    flash message's own "reload in a few seconds" wording, rather than a
    hard failure."""
    subprocess.Popen(["sh", "-c", "sleep 2 && sudo systemctl restart vhsp-admin.service"])


@app.route("/account/platform-access", methods=["POST"])
@require_auth
@require_2fa
def platform_access_toggle():
    """Same decorator stack as api_tokens_view() above (2FA required,
    same reasoning) -- structural opt-in for the toggle action itself,
    not just the surfaces it flips. REST API and MCP are two genuinely
    different kinds of action here: enabling/disabling the REST API only
    ever restarts the already-running, already-sudo-granted
    vhsp-admin.service (platform_settings.py + the existing VHSP_RESTART
    grant); MCP additionally installs/removes a systemd unit, a firewall
    rule, and a Traefik route (provisioner.enable_mcp_server()/
    disable_mcp_server(), the new VHSP_MCP_TOGGLE/VHSP_MCP_FIREWALL
    grants) -- see platform_settings.py and provisioner.py's own
    docstrings for why each half exists."""
    action = request.form.get("action")
    actor = f"admin-ui:{session['username']}"
    if action == "enable_update_check":
        # No restart and no infrastructure change, unlike the two below:
        # the banner reads the toggle live on every render, and the timer
        # re-reads it on each run.
        platform_settings.set_update_check_enabled(True, actor)
        flash("Update checks turned on. The first check runs within a day, "
              "or run `vhsp update check` to check now.", "ok")
    elif action == "disable_update_check":
        platform_settings.set_update_check_enabled(False, actor)
        flash("Update checks turned off.", "ok")
    elif action == "enable_api":
        platform_settings.set_api_enabled(True, actor)
        _restart_admin_service_deferred()
        flash("REST API turned on -- this admin UI is restarting to apply it. Reload in a few seconds.", "ok")
    elif action == "disable_api":
        platform_settings.set_api_enabled(False, actor)
        _restart_admin_service_deferred()
        flash("REST API turned off -- this admin UI is restarting to apply it. Reload in a few seconds.", "ok")
    elif action == "enable_mcp":
        platform_settings.set_mcp_enabled(True, actor)
        try:
            provisioner.enable_mcp_server(actor)
            flash("MCP server enabled and started.", "ok")
        except provisioner.ProvisioningError as e:
            flash(f"error enabling MCP: {e}", "error")
    elif action == "disable_mcp":
        platform_settings.set_mcp_enabled(False, actor)
        try:
            provisioner.disable_mcp_server(actor)
            flash("MCP server disabled and stopped.", "ok")
        except provisioner.ProvisioningError as e:
            flash(f"error disabling MCP: {e}", "error")
    return redirect(url_for("api_tokens_view"))


@app.route("/webauthn/register/begin", methods=["POST"])
@require_auth
def webauthn_register_begin():
    options, state = webauthn.register_begin(session['username'])
    session['webauthn_state'] = state
    return jsonify(options)


@app.route("/webauthn/register/complete", methods=["POST"])
@require_auth
def webauthn_register_complete():
    state = session.get('webauthn_state')
    if not state:
        return jsonify(ok=False, error="No registration in progress."), 400
    body = request.get_json(force=True)
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, error="Name required."), 400
    if webauthn.name_taken(session['username'], name):
        return jsonify(ok=False, error=f"A key named {name!r} already exists."), 400
    try:
        credential_data = webauthn.register_complete(state, body["credential"])
    except Exception as e:
        return jsonify(ok=False, error=f"Registration failed: {e}"), 400
    session.pop('webauthn_state', None)
    webauthn.add_credential(session['username'], name, credential_data, datetime.now(timezone.utc).isoformat())
    audit.log_action("admin.webauthn_register", name, f"admin-ui:{session['username']}")
    return jsonify(ok=True)


@app.route("/webauthn/remove", methods=["POST"])
@require_auth
def webauthn_remove():
    name = request.form.get("name", "")
    webauthn.remove_credential(session['username'], name)
    audit.log_action("admin.webauthn_remove", name, f"admin-ui:{session['username']}")
    flash(f"Removed security key {name!r}.", "ok")
    return redirect(url_for("account"))


@app.route("/totp/setup", methods=["GET", "POST"])
@require_auth
def totp_setup():
    error = None
    if request.method == "POST":
        pending_secret = session.get('pending_totp_secret')
        code = request.form.get("code", "").strip().replace(" ", "")
        if not pending_secret:
            return redirect(url_for("totp_setup"))
        if totp.confirm_and_enable(session['username'], pending_secret, code, datetime.now(timezone.utc).isoformat()):
            session.pop('pending_totp_secret', None)
            audit.log_action("admin.totp_enable", session['username'], f"admin-ui:{session['username']}")
            flash("Authenticator app enabled.", "ok")
            return redirect(url_for("account"))
        error = "That code didn't verify -- check the time on your phone/authenticator and try again."
        secret = pending_secret
        qr_svg = totp.qr_svg_for_secret(session['username'], secret)
    else:
        secret, qr_svg = totp.generate_setup(session['username'])
        session['pending_totp_secret'] = secret

    return render("""
      <h2 style="margin-bottom:1.25rem">Set up an authenticator app</h2>
      <div class="card">
        <p class="muted">Scan this with Google Authenticator, Authy, 1Password, or
        anything else that reads a standard TOTP QR code, then enter the 6-digit code
        it shows to confirm.</p>
        {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
        <div class="qr-code" style="max-width:220px;margin:0 auto 1rem">{{ qr_svg|safe }}</div>
        <p class="muted" style="text-align:center">Can't scan? Enter this key manually: <code>{{ secret }}</code></p>
        <form method="post" autocomplete="off" style="max-width:280px;margin:0 auto">
          <div class="field"><label>6-digit code</label>
            <input name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="123456" autofocus required></div>
          <button type="submit" style="width:100%">Confirm</button>
        </form>
      </div>
    """, error=error, secret=secret, qr_svg=qr_svg)


@app.route("/totp/remove", methods=["POST"])
@require_auth
def totp_remove():
    totp.remove(session['username'])
    audit.log_action("admin.totp_remove", session['username'], f"admin-ui:{session['username']}")
    flash("Authenticator app removed.", "ok")
    return redirect(url_for("account"))


@app.route("/operators", methods=["GET"])
@require_auth
def operators_view():
    operators = auth.list_operators()
    key_counts = {o["username"]: len(webauthn.list_credentials(o["username"])) for o in operators}
    totp_enabled = {o["username"]: totp.has_totp(o["username"]) for o in operators}
    return render("""
      <h2>Operators</h2>
      <p class="muted">
        Flat, equal-privilege accounts -- every operator can do everything
        any other operator can, including managing operators here. No
        per-operator permissions exist yet.
      </p>
      {% if not has_2fa %}
      <div class="warn">
        Adding, removing, or resetting another operator's password needs
        <strong>your own</strong> account to have a second factor registered
        first. Set one up on the <a href="{{ url_for('account') }}">My
        account</a> page.
      </div>
      {% endif %}
      <div class="card">
        <table>
          <thead><tr><th>Username</th><th>Created</th><th>Security keys</th><th>Authenticator app</th><th></th></tr></thead>
          <tbody>
          {% for o in operators %}
          <tr>
            <td>{{ o.username }}{% if o.username == session['username'] %} <span class="muted">(you)</span>{% endif %}</td>
            <td class="muted">{{ o.created_at|humanize_ts }}</td>
            <td>{{ key_counts[o.username] }}</td>
            <td>{{ 'yes' if totp_enabled[o.username] else '—' }}</td>
            <td style="text-align:right">
              <form class="inline" method="post" action="{{ url_for('operator_reset_password', username=o.username) }}"
                    onsubmit="return confirm('Generate a new password for ' + '{{ o.username }}' + '? Their current password stops working immediately.');">
                <button class="btn-ghost" type="submit">Reset password</button>
              </form>
              {% if operators|length > 1 %}
              <form class="inline" method="post" action="{{ url_for('operator_remove', username=o.username) }}"
                    onsubmit="return confirm('Remove operator ' + '{{ o.username }}' + '? They will no longer be able to log in.');">
                <button class="danger" type="submit">Remove</button>
              </form>
              {% else %}
              <span class="muted">last operator -- cannot remove</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
      <div class="card">
        <h3 style="margin-top:0">Add operator</h3>
        <p class="muted">Generates a password shown once here -- pass it to the new operator directly, they should change it (and register their own security key) on first login.</p>
        <form method="post" action="{{ url_for('operator_add') }}">
          <div class="actions">
            <label class="sr-only" for="new-operator-username">Username</label>
            <input id="new-operator-username" type="text" name="username" placeholder="username" required style="max-width:220px">
            <button type="submit">Add operator</button>
          </div>
        </form>
      </div>
    """, operators=operators, key_counts=key_counts, totp_enabled=totp_enabled)


@app.route("/operators/add", methods=["POST"])
@require_auth
@require_2fa
def operator_add():
    username = request.form.get("username", "").strip()
    if not username:
        flash("Username required.", "error")
        return redirect(url_for("operators_view"))
    try:
        password = auth.create_operator(username, actor=f"admin-ui:{session['username']}")
    except auth.AuthError as e:
        flash(str(e), "error")
        return redirect(url_for("operators_view"))
    # Markup + explicit escape() on both interpolated values (not an f-string
    # into flash() directly) -- LAYOUT's flash loop renders {{ message }}
    # with Jinja's normal autoescaping, so a plain string here would show
    # literal "<code>" text instead of a formatted tag; Markup opts this one
    # message out of that, so the two dynamic values must be escaped by hand
    # first to avoid reopening the exact HTML-injection risk autoescaping
    # exists to close (username is operator-chosen input, not generated).
    flash(Markup(f"Operator '{escape(username)}' created. Password (shown once): <code>{escape(password)}</code>"), "ok")
    return redirect(url_for("operators_view"))


@app.route("/operators/<username>/remove", methods=["POST"])
@require_auth
@require_2fa
def operator_remove(username):
    try:
        auth.remove_operator(username, actor=f"admin-ui:{session['username']}")
    except auth.AuthError as e:
        flash(str(e), "error")
        return redirect(url_for("operators_view"))
    flash(f"Removed operator {username!r}.", "ok")
    if username == session['username']:
        session.clear()
        return redirect(url_for("login"))
    return redirect(url_for("operators_view"))


@app.route("/operators/<username>/reset-password", methods=["POST"])
@require_auth
@require_2fa
def operator_reset_password(username):
    password = secrets.token_urlsafe(18)
    try:
        auth.set_password(username, password, actor=f"admin-ui:{session['username']}")
    except auth.AuthError as e:
        flash(str(e), "error")
        return redirect(url_for("operators_view"))
    flash(f"New password for {username!r} (shown once): {password}", "ok")
    return redirect(url_for("operators_view"))


# Same knobs images/tenant-admin/ exposes per-tenant (network-isolated,
# no login of its own), mirrored here so an operator doesn't need to hop
# to each tenant's own admin.<domain>:8090 -- see toggles.py's docstring
# for why this reads/writes the identical underlying files directly by
# host path instead of going through that container.
TENANT_NAV = """
<div style="margin-bottom:1.5rem">
  <h2 style="margin-bottom:0.9rem">
    {{ t.domain }}
    {% if tenant_maintenance_enabled(t.domain) %}
    <span class="badge badge-warn" style="vertical-align:middle;margin-left:0.5rem">Maintenance mode</span>
    {% endif %}
  </h2>
  <div class="subnav">
    {% for endpoint, label, needs_2fa in [
      ('tenant_detail', 'Overview', False), ('tenant_php', 'PHP functions', True),
      ('tenant_fallback', '404 handling', False), ('tenant_auth', 'Password protection', False),
      ('tenant_error_pages', 'Error pages', False), ('tenant_redirects', 'Redirects', True),
      ('tenant_noexec_dirs', 'No-exec dirs', True), ('tenant_ip_acl', 'IP restrictions', True),
      ('tenant_email', 'Email', True), ('tenant_backups', 'Backups', True),
      ('tenant_dns', 'DNS', False), ('tenant_logs', 'Logs', False),
      ('tenant_audit', 'Panel audit log', True),
    ] %}
    <a href="{{ url_for(endpoint, domain=t.domain) }}" class="{{ 'active' if request.path == url_for(endpoint, domain=t.domain) }}">{{ label }}{% if needs_2fa and not has_2fa %} <span class="muted">(2FA required)</span>{% endif %}</a>
    {% endfor %}
  </div>
</div>
"""


@app.route("/")
@require_auth
def index():
    tenants = registry.list_tenants()
    # Maintenance mode lives in a marker file per tenant, NOT in the
    # registry's own status column -- that column is the lifecycle state
    # (active/destroyed) and list_tenants() already filters it to
    # 'active', so rendering it raw made the Status column a constant
    # that silently contradicted a tenant actually being held offline.
    maintenance = {
        t.domain for t in tenants if provisioner.tenant_maintenance_enabled_for(t)
    }
    last_backup = registry.latest_backup_times(destination="operator")
    return render("""
      <h2>Tenants</h2>

      <div class="card">
        <form method="post" action="{{ url_for('tenant_create') }}">
          <div class="actions">
            <label class="sr-only" for="new-tenant-domain">Domain</label>
            <input id="new-tenant-domain" name="domain" placeholder="example.com" required style="max-width:320px">
            <button type="submit">Create tenant</button>
          </div>
        </form>
      </div>

      <div class="table-filter">
        <label class="sr-only" for="tenant-filter">Filter tenants</label>
        <input type="search" id="tenant-filter" placeholder="Filter by domain, account, port&hellip;"
               data-filter-target="tenant-table" data-filter-noun="tenant" autocomplete="off">
        <span class="muted filter-count" data-filter-count="tenant-table" aria-live="polite"></span>
      </div>
      <div class="card">
        <table id="tenant-table">
          <thead><tr><th>Domain</th><th>Account ID</th><th>Status</th><th>SSH Port</th><th>Last backup</th></tr></thead>
          <tbody>
          {% for t in tenants %}
          <tr>
            <td><a href="{{ url_for('tenant_detail', domain=t.domain) }}">{{ t.domain }}</a></td>
            <td>{% if t.billing_account_id %}<code>{{ t.billing_account_id }}</code>{% else %}<span class="muted">&mdash;</span>{% endif %}</td>
            <td>
              {%- if t.domain in maintenance -%}
                <span class="badge badge-warn">Maintenance</span>
              {%- elif t.status == 'active' -%}
                <span class="badge badge-ok">Active</span>
              {%- else -%}
                <span class="badge badge-warn">{{ t.status }}</span>
              {%- endif -%}
            </td>
            <td>{{ t.ssh_port }}</td>
            <td>
              {%- if last_backup.get(t.domain) -%}
                <span class="muted">{{ last_backup[t.domain]|humanize_ts }}</span>
              {%- else -%}
                <span class="badge badge-warn">Never</span>
              {%- endif -%}
            </td>
          </tr>
          {% else %}
          <tr data-filter-skip><td colspan="5" class="muted">No tenants yet.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, tenants=tenants, maintenance=maintenance, last_backup=last_backup)


@app.route("/tenants", methods=["GET", "POST"])
@require_auth
def tenant_create():
    # GET is a real thing a new operator will type/bookmark -- it's a
    # very natural, guessable URL for "the tenants page," even though
    # this route only ever existed as the create-tenant form's POST
    # target. Redirecting instead of leaving it POST-only avoids a bare,
    # unstyled 405 error page for a URL an operator has every reason to
    # expect works.
    if request.method == "GET":
        return redirect(url_for("index"))
    domain = request.form["domain"].strip()
    try:
        provisioner.create_tenant(domain, actor=f"admin-ui:{session['username']}")
    except provisioner.ProvisioningError as e:
        return render("<p class='danger'>error: {{ e }}</p><p><a href='{{ url_for('index') }}'>back</a></p>", e=str(e)), 400
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>")
@require_auth
def tenant_detail(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    webauthn_key_count = provisioner.count_tenant_webauthn_keys(domain)
    totp_count = provisioner.count_tenant_totp(domain)
    usage = provisioner.get_tenant_disk_usage(domain)
    quota_limit = provisioner.get_tenant_quota_limit(domain)
    quota_percent = min(100, round(usage["total"] / quota_limit * 100)) if quota_limit else 0
    quota_status = "danger" if quota_percent >= 100 else "warn" if quota_percent >= 80 else "ok"
    maintenance_enabled = provisioner.tenant_maintenance_enabled(domain)
    # One-shot: popped so a refresh (or navigating back here later) never
    # redisplays a credential, and scoped to the domain it was generated
    # for so it can't leak onto a different tenant's page.
    stashed = session.pop("new_tenant_admin_password", None)
    new_admin_password = stashed["password"] if stashed and stashed.get("domain") == domain else None
    stashed_token = session.pop("new_operator_token", None)
    new_operator_token = (
        stashed_token["token"] if stashed_token and stashed_token.get("domain") == domain else None
    )
    operator_access = provisioner.operator_access_status(domain)
    waf_mode = waf.tenant_mode(domain)
    waf_allowlist = waf.read_allowlist()
    return render(TENANT_NAV + """
      {% if not has_2fa %}
      <div class="warn">
        Several actions below -- setting an SSH key or admin password, clearing
        WebAuthn keys, maintenance mode, every incident-response button, and
        Destroy -- need <strong>your own</strong> operator account to have a
        second factor registered first (a security key or an authenticator app,
        either one). Set one up on the <a href="{{ url_for('account') }}">My
        account</a> page.
      </div>
      {% endif %}
      <div class="card">
        <table class="kv">
          <tr><td>Live site</td><td><a href="https://{{ t.domain }}/" target="_blank" rel="noopener noreferrer">https://{{ t.domain }}/</a></td></tr>
          <tr><td>slug</td><td><code>{{ t.slug }}</code></td></tr>
          <tr><td>status</td><td><span class="badge badge-ok">{{ t.status }}</span></td></tr>
          <tr><td>created</td><td class="muted">{{ t.created_at|humanize_ts }}</td></tr>
          <tr><td>billing account id</td><td>{% if t.billing_account_id %}<code>{{ t.billing_account_id }}</code>{% else %}<span class="muted">not set</span>{% endif %}</td></tr>
          <tr><td>ssh/sftp port</td><td>{{ t.ssh_port }}</td></tr>
          <tr><td>web container</td><td><code>{{ t.web_container }}</code></td></tr>
          <tr><td>db container</td><td><code>{{ t.db_container }}</code></td></tr>
          <tr><td>sftp container</td><td><code>{{ t.sftp_container }}</code></td></tr>
          <tr><td>db network</td><td><code>{{ t.db_network }}</code> <span class="muted">(internal, web-only)</span></td></tr>
          <tr><td>webroot volume</td><td><code>{{ t.webroot_volume }}</code><br><span class="muted">{{ t.webroot_host_path }}</span></td></tr>
          <tr><td>db volume</td><td><code>{{ t.db_volume }}</code><br><span class="muted">{{ t.db_host_path }}</span></td></tr>
          <tr><td>db name / user</td><td>{{ t.db_name }} / {{ t.db_user }}</td></tr>
          <tr><td>db password</td><td><code>{{ t.db_password }}</code></td></tr>
          <tr><td>db root password</td><td><code>{{ t.db_root_password }}</code></td></tr>
          <tr><td>sftp user</td><td>{{ t.sftp_user }}</td></tr>
          <tr><td>sftp auth</td><td>key-only <span class="muted">(password login disabled -- no fallback)</span></td></tr>
          <tr><td>sftp connect</td><td><code>sftp -P {{ t.ssh_port }} {{ t.sftp_user }}@{{ t.domain }}</code><br><span class="muted">uploads land in ~/www, served live -- SFTP is routed by port, not hostname (see the DNS tab), so the tenant's own domain works once its A record points at the platform IP</span></td></tr>
          <tr><td>ssh public key</td><td>
            {% if t.ssh_key_fingerprint %}installed: <code>{{ t.ssh_key_fingerprint }}</code>{% else %}<span class="danger">none set -- SFTP is inaccessible until a key is installed below</span>{% endif %}
          </td></tr>
          <tr><td>mail container</td><td><code>{{ t.mail_container }}</code></td></tr>
          <tr><td>mail hostname</td><td>{{ t.mail_hostname }} <span class="muted">(IMAPS 993 / SMTPS 465, SNI-routed via Traefik)</span></td></tr>
          <tr><td>mailbox</td><td>{{ t.mail_user }}@{{ t.domain }}</td></tr>
          <tr><td>mail password</td><td><code>{{ t.mail_password }}</code></td></tr>
          <tr><td>tenant admin page</td><td><a href="https://{{ t.admin_hostname }}/" target="_blank" rel="noopener noreferrer">https://{{ t.admin_hostname }}/</a> <span class="muted">(public, real cert -- needed for WebAuthn{% if mgmtweb_exists %}; also reachable mgmt-network-only at <code>http://{{ t.admin_hostname }}:8090/</code>{% endif %})</span></td></tr>
          <tr><td>webmail</td><td><a href="https://webmail.{{ t.domain }}/" target="_blank" rel="noopener noreferrer">https://webmail.{{ t.domain }}/</a> <span class="muted">(shared Roundcube instance, one for every tenant)</span></td></tr>
        </table>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Disk usage</h3>
        <p class="muted">Combined web + database + mail, checked live on page load -- a soft quota
        (nothing currently blocks writes past it, just visibility here and on the tenant's own admin page).</p>
        <div class="quota-bar"><div class="quota-bar-fill {{ quota_status }}" style="width:{{ quota_percent }}%"></div></div>
        <p>{{ usage_total_mb }} / {{ quota_limit_mb }} ({{ quota_percent }}%) &mdash;
        web {{ usage_web_mb }}, db {{ usage_db_mb }}, mail {{ usage_mail_mb }}</p>
        <form method="post" action="{{ url_for('tenant_set_quota', domain=t.domain) }}">
          <div class="actions">
            <input type="number" name="quota_mb" min="1" style="width:8rem" placeholder="200" required>
            <button type="submit">Set quota</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Billing account ID</h3>
        <p class="muted">Ties this tenant to an account in external billing software -- operator-set only, not shown or editable anywhere on the tenant's own admin page. Optional; leave blank to clear it.</p>
        <form method="post" action="{{ url_for('tenant_set_billing_account_id', domain=t.domain) }}">
          <div class="actions">
            <input name="billing_account_id" value="{{ t.billing_account_id }}" placeholder="e.g. cus_A1b2C3" style="max-width:280px">
            <button type="submit">Save</button>
          </div>
        </form>
      </div>

      <div class="card" id="platform-access">
        <h3 style="margin-top:0">API &amp; MCP access{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">Allows this tenant to mint their own bearer tokens
        (from their own panel's "API &amp; MCP access" page) for programmatic/
        AI-agent access to their own self-service operations -- mailboxes,
        PHP function toggles, redirects, backups, and the rest of what their
        panel already exposes, deliberately excluding Files and Database (the
        two highest-trust actions even in their own panel). Two layers, both
        must be on for anything to actually work: this is Layer 1, an
        operator-only allow -- the tenant still has to turn it on themselves
        (Layer 2) before any token they mint actually does anything.
        Allowing here does not by itself turn on the platform's REST API/MCP
        server if either is currently off platform-wide -- see
        <a href="{{ url_for('api_tokens_view') }}">My account -&gt; API &amp;
        MCP access</a> for that separate, platform-wide switch.</p>
        <table class="kv">
          <tr>
            <td>REST API</td>
            <td>
              {% if platform_access.api_allowed %}<span class="badge badge-ok">Allowed</span>{% else %}<span class="muted">Not allowed</span>{% endif %}
              <form class="inline" method="post" action="{{ url_for('tenant_platform_access_toggle', domain=t.domain) }}">
                <input type="hidden" name="action" value="{{ 'disallow_api' if platform_access.api_allowed else 'allow_api' }}">
                <button type="submit" class="{{ 'danger' if platform_access.api_allowed else '' }}">{{ 'Disallow' if platform_access.api_allowed else 'Allow' }}</button>
              </form>
            </td>
          </tr>
          <tr>
            <td>MCP server</td>
            <td>
              {% if platform_access.mcp_allowed %}<span class="badge badge-ok">Allowed</span>{% else %}<span class="muted">Not allowed</span>{% endif %}
              <form class="inline" method="post" action="{{ url_for('tenant_platform_access_toggle', domain=t.domain) }}">
                <input type="hidden" name="action" value="{{ 'disallow_mcp' if platform_access.mcp_allowed else 'allow_mcp' }}">
                <button type="submit" class="{{ 'danger' if platform_access.mcp_allowed else '' }}">{{ 'Disallow' if platform_access.mcp_allowed else 'Allow' }}</button>
              </form>
            </td>
          </tr>
          <tr>
            <td class="muted">Tenant has turned on</td>
            <td class="muted">REST API: {{ 'yes' if platform_access.api_enabled else 'no' }}, MCP: {{ 'yes' if platform_access.mcp_enabled else 'no' }}</td>
          </tr>
        </table>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Set SSH public key{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">Replaces any previously-set key. Validated with <code>ssh-keygen</code> before installing; the SFTP container is restarted to pick it up.</p>
        <form method="post" action="{{ url_for('tenant_set_ssh_key', domain=t.domain) }}">
          <div class="field"><textarea name="public_key" rows="3" placeholder="ssh-ed25519 AAAA... user@host" required></textarea></div>
          <button type="submit">Set key</button>
        </form>
      </div>

      <div class="card" id="reset-admin-password">
        <h3 style="margin-top:0">Reset tenant admin password{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">Generates a random single-use password for the original <code>admin</code> login on this tenant's admin.{{ t.domain }} panel and shows it to you once, here. The tenant is forced to replace it the moment they next log in, before they can reach any other page -- so the value you hand over stops working as soon as they use it, and you never hold their real password. You can't choose the value: an operator-chosen password is one the operator would still know indefinitely.</p>
        <p class="muted">This only touches the original <code>admin</code> login -- the tenant may have added their own team-member logins (see their own Team page), which this doesn't touch or show you. Takes effect immediately, no restart needed.</p>
        {% if new_admin_password %}
        <div class="flash ok" style="margin-bottom:0.9rem">
          <p style="margin:0 0 0.4rem"><strong>Copy this now -- it isn't stored anywhere you can read it back, and won't be shown again.</strong></p>
          <code class="copyable" title="Click to copy" tabindex="0" role="button"
                onclick="vhspCopyDns(this)" onkeydown="vhspCopyDnsKey(event, this)"
                style="font-size:1rem">{{ new_admin_password }}</code>
        </div>
        {% endif %}
        <form method="post" action="{{ url_for('tenant_set_admin_password', domain=t.domain) }}"
              onsubmit="return confirm('Generate a new admin password for {{ t.domain }}? The current one stops working immediately.');">
          <button type="submit">Generate new password</button>
        </form>
      </div>

      <div class="card" id="waf">
        <h3 style="margin-top:0">Web application firewall (Coraza / OWASP CRS){% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">
          Inspects requests to this tenant's site for SQL injection, XSS, RCE and
          similar. Applies with a reload, no downtime for the site.
          <a href="{{ url_for('tenant_logs', domain=t.domain) }}">See what it's detecting</a>
          before switching to blocking -- OWASP CRS is known to false-positive on real
          application traffic, and unlike a fail2ban ban (which self-heals) a WAF false
          positive stays broken until someone changes it back.
        </p>
        <p>
          {% if waf_mode == 'On' %}<span class="badge badge-ok">Blocking</span>
          <span class="muted">Malicious requests are refused.</span>
          {% elif waf_mode == 'DetectionOnly' %}<span class="badge badge-warn">Detect only</span>
          <span class="muted">Logging what it would block, but letting everything through.</span>
          {% else %}<span class="badge badge-warn">Off</span>
          <span class="muted">Not inspecting anything.</span>{% endif %}
        </p>
        <form method="post" action="{{ url_for('tenant_waf', domain=t.domain) }}">
          <div class="actions">
            <label class="sr-only" for="waf-mode">WAF mode</label>
            <select id="waf-mode" name="mode" style="max-width:200px;display:inline-block">
              <option value="DetectionOnly" {% if waf_mode == 'DetectionOnly' %}selected{% endif %}>Detect only (log)</option>
              <option value="On" {% if waf_mode == 'On' %}selected{% endif %}>Blocking (enforce)</option>
              <option value="Off" {% if waf_mode == 'Off' %}selected{% endif %}>Off</option>
            </select>
            <button type="submit">Apply</button>
          </div>
        </form>
        {% if waf_allowlist %}
        <p class="muted" style="margin-bottom:0">
          Skipping inspection entirely for {{ waf_allowlist|length }}
          allowlisted address{{ 'es' if waf_allowlist|length != 1 }}
          (<a href="{{ url_for('fail2ban_allowlist_view') }}">manage</a>):
          {% for e in waf_allowlist %}<code>{{ e }}</code>{% if not loop.last %} {% endif %}{% endfor %}
        </p>
        {% endif %}
      </div>

      <div class="card" id="operator-access">
        <h3 style="margin-top:0">Temporary tenant-admin access{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">
          Opens this tenant's own admin panel as a temporary owner, without touching their
          password or logins. <strong>They are told:</strong> a banner shows in their panel for
          the whole window naming you, and the grant, every action you take, and the session
          ending are all written to <a href="{{ url_for('tenant_audit', domain=t.domain) }}">their
          audit log</a> as well as yours. Access ends by itself when the window runs out.
        </p>
        {% if operator_access.active %}
        <p>
          <span class="badge badge-warn">Active</span>
          <span class="muted">Granted to <code>{{ operator_access.operator }}</code>, expires
          {{ operator_access.expires_at|humanize_ts }}.
          {% if operator_access.token_used_at %}Link already used.{% else %}Link not opened yet.{% endif %}</span>
        </p>
        {% endif %}
        {% if new_operator_token %}
        <div class="flash ok" style="margin-bottom:0.9rem">
          <p style="margin:0 0 0.5rem"><strong>Access granted.</strong> This button opens their panel
          in a new tab. It works once — after that, grant a new window.</p>
          <form method="post" action="https://{{ t.admin_hostname }}/operator-access" target="_blank" rel="noopener">
            <input type="hidden" name="token" value="{{ new_operator_token }}">
            <button type="submit">Open {{ t.admin_hostname }} as operator</button>
          </form>
        </div>
        {% endif %}
        <div class="actions">
          <form class="inline" method="post" action="{{ url_for('tenant_operator_access', domain=t.domain) }}"
                onsubmit="return confirm('Grant yourself temporary admin access to {{ t.domain }}? The tenant is notified in their panel and audit log.');">
            <input type="hidden" name="action" value="grant">
            <label class="sr-only" for="op-minutes">Minutes</label>
            <select id="op-minutes" name="minutes" style="max-width:130px;display:inline-block;margin-right:0.5rem">
              <option value="15">15 minutes</option>
              <option value="30" selected>30 minutes</option>
              <option value="60">1 hour</option>
              <option value="240">4 hours</option>
            </select>
            <button type="submit">{% if operator_access.active %}Replace with new grant{% else %}Grant access{% endif %}</button>
          </form>
          {% if operator_access.active %}
          <form class="inline" method="post" action="{{ url_for('tenant_operator_access', domain=t.domain) }}">
            <input type="hidden" name="action" value="revoke">
            <button class="danger" type="submit">End access now</button>
          </form>
          {% endif %}
        </div>
      </div>

      <div class="card" id="tenant-2fa">
        <h3 style="margin-top:0">Tenant admin second factors{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">
          Lockout recovery for this tenant's admin panel. Resetting the password above does
          <strong>not</strong> help someone locked out of a second factor -- both checks below are
          separate, with no in-app fallback once enrolled. Each button wipes that factor for EVERY
          login on this tenant's panel (not just <code>admin</code>), dropping them to password-only
          immediately. No restart needed; the tenant re-enrols from their own security page.
        </p>
        <table>
          <thead><tr><th>Factor</th><th>Enrolled</th><th></th></tr></thead>
          <tbody>
            <tr>
              <td>Authenticator app (TOTP)</td>
              <td>{% if totp_count == 0 %}<span class="muted">none</span>{% else %}<span class="badge badge-ok">{{ totp_count }} login{{ 's' if totp_count != 1 }}</span>{% endif %}</td>
              <td style="text-align:right">
                {% if totp_count > 0 %}
                <form class="inline" method="post" action="{{ url_for('tenant_clear_totp', domain=t.domain) }}"
                      onsubmit="return confirm('Clear the authenticator app enrolment for all {{ totp_count }} login(s) on {{ t.domain }}? They will need to re-enrol.');">
                  <button class="danger" type="submit">Clear TOTP</button>
                </form>
                {% else %}<span class="muted">&mdash;</span>{% endif %}
              </td>
            </tr>
            <tr>
              <td>Security keys (WebAuthn)</td>
              <td>{% if webauthn_key_count == 0 %}<span class="muted">none</span>{% else %}<span class="badge badge-ok">{{ webauthn_key_count }} key{{ 's' if webauthn_key_count != 1 }}</span>{% endif %}</td>
              <td style="text-align:right">
                {% if webauthn_key_count > 0 %}
                <form class="inline" method="post" action="{{ url_for('tenant_clear_webauthn', domain=t.domain) }}"
                      onsubmit="return confirm('Clear all ' + {{ webauthn_key_count }} + ' WebAuthn key(s) for this tenant? They will need to re-register.');">
                  <button class="danger" type="submit">Clear keys</button>
                </form>
                {% else %}<span class="muted">&mdash;</span>{% endif %}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card" style="border-color:var(--danger-border)">
        <h3 style="margin-top:0">Incident response{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">
          For a suspected compromise, not routine lockout recovery -- for that, use
          "Reset tenant admin password" above instead, which leaves everything else
          alone. Everything below is coarse on purpose: the operator has no way to
          tell which specific login/mailbox/credential is the compromised one, and
          an attacker with panel access could have added a backdoor of their own --
          so each of these resets <strong>all</strong> of its category at once, not
          one at a time. New credentials are generated and shown once each; none are
          saved anywhere else in this UI.
        </p>

        <h4>Admin password nuke</h4>
        <p class="muted">Wipes every admin-panel login (not just <code>admin</code>) down
        to one fresh, randomly-generated <code>admin</code> account, and rotates the
        panel's session-signing secret so anyone already logged in right now is kicked
        out immediately too -- a password reset alone wouldn't touch an existing
        session. The tenant re-adds their team from scratch afterward. No downtime.</p>
        <form method="post" action="{{ url_for('tenant_reset_panel_access', domain=t.domain) }}"
              onsubmit="return confirm('Wipe every admin-panel login for this tenant and end all active sessions? This cannot be undone -- the tenant will need to re-add their team.');">
          <button class="danger" type="submit">Admin password nuke</button>
        </form>

        <h4>Email password nuke</h4>
        <p class="muted">Regenerates a fresh random password for <strong>every</strong>
        mailbox on this tenant at once. Panel access already shows the DB password in
        plain text to any logged-in panel user, and mailbox self-service isn't
        owner-restricted either, so a compromised panel login is also a plausible
        route to a compromised mailbox. Existing mail clients need reconfiguring. No
        downtime.</p>
        <form method="post" action="{{ url_for('tenant_reset_mailbox_passwords', domain=t.domain) }}"
              onsubmit="return confirm('Reset every mailbox password for this tenant? Every mail client will need reconfiguring.');">
          <button class="danger" type="submit">Email password nuke</button>
        </form>

        <h4>Database nuke</h4>
        <p class="muted">Rotates this tenant's application DB password with a live
        <code>ALTER USER</code>, then recreates the web and tenant-admin containers so
        both pick up the new value -- env vars aren't hot-reloadable. The one with a
        real cost: <strong>brief downtime on the tenant's actual website</strong> while
        those two containers restart. Doesn't touch panel logins or mailboxes.</p>
        <form method="post" action="{{ url_for('tenant_reset_db_password', domain=t.domain) }}"
              onsubmit="return confirm('Rotate this tenant\\'s database password? This briefly takes their website down while the web and tenant-admin containers restart.');">
          <button class="danger" type="submit">Database nuke</button>
        </form>

        <h4>Nuke all passwords</h4>
        <p class="muted">All three above in one action -- admin password, then
        mailboxes, then the DB last, since it's the only one with downtime. Use this
        when you don't know which credential is compromised, or assume all of them
        might be.</p>
        <form method="post" action="{{ url_for('tenant_reset_all_passwords', domain=t.domain) }}"
              onsubmit="return confirm('Nuke EVERYTHING for this tenant -- admin panel access, every mailbox password, and the database password? This briefly takes their website down and every login/mailbox will need reconfiguring. This cannot be undone.');">
          <button class="danger" type="submit">Nuke all passwords</button>
        </form>
      </div>

      <div class="card"{% if maintenance_enabled %} style="border-color:var(--warn-border)"{% endif %}>
        <h3 style="margin-top:0">Maintenance mode{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <p class="muted">
          An operator-only hold, not a tenant-visible setting -- e.g. for a lapsed
          bill, without it looking like a punishment. While on: site visitors see a
          plain "temporarily undergoing maintenance" page (no error details, no
          mention of why) instead of the real site; the tenant can't log into IMAP
          or send mail (submission, port 465). Inbound email keeps being delivered
          normally the whole time -- nothing bounces or gets lost. The tenant's own
          admin panel and SFTP access are unaffected, so they can still see what's
          going on and reach you.
        </p>
        {% if maintenance_enabled %}
        <p><span class="badge badge-warn">Currently on</span></p>
        <form method="post" action="{{ url_for('tenant_set_maintenance', domain=t.domain) }}">
          <input type="hidden" name="action" value="disable">
          <button type="submit">Turn off maintenance mode</button>
        </form>
        {% else %}
        <form method="post" action="{{ url_for('tenant_set_maintenance', domain=t.domain) }}">
          <input type="hidden" name="action" value="enable">
          <button type="submit" class="btn-ghost">Turn on maintenance mode</button>
        </form>
        {% endif %}
      </div>

      <div class="card" style="border-color:var(--danger-border)">
        <h3 style="margin-top:0">Destroy{% if not has_2fa %} <span class="muted" style="font-weight:400;font-size:0.78rem">(2FA required)</span>{% endif %}</h3>
        <form method="post" action="{{ url_for('tenant_destroy', domain=t.domain) }}"
              onsubmit="return confirm('Destroy ' + '{{ t.domain }}' + '? This deletes its data.');">
          <button class="danger" type="submit">Destroy tenant</button>
        </form>
      </div>
    """, t=t, webauthn_key_count=webauthn_key_count, totp_count=totp_count,
        quota_percent=quota_percent, quota_status=quota_status,
        usage_total_mb=format_mb(usage["total"]), usage_web_mb=format_mb(usage["web"]),
        usage_db_mb=format_mb(usage["db"]), usage_mail_mb=format_mb(usage["mail"]),
        quota_limit_mb=format_mb(quota_limit), maintenance_enabled=maintenance_enabled,
        mgmtweb_exists=TENANT_ADMIN_MGMTWEB_EXISTS,
        platform_access=provisioner.tenant_platform_access(domain),
        new_admin_password=new_admin_password,
        new_operator_token=new_operator_token, operator_access=operator_access,
        waf_mode=waf_mode, waf_allowlist=waf_allowlist)


@app.route("/tenants/<domain>/ssh-key", methods=["POST"])
@require_auth
@require_2fa
def tenant_set_ssh_key(domain):
    public_key = request.form["public_key"]
    try:
        fingerprint = provisioner.set_ssh_public_key(
            domain, public_key, actor=f"admin-ui:{session['username']}"
        )
        flash(f"SSH key installed -- fingerprint {fingerprint}", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/admin-password", methods=["POST"])
@require_auth
@require_2fa
def tenant_set_admin_password(domain):
    # _anchor scrolls the browser straight back to this card -- found
    # during a real usability pass that a plain redirect back to the top
    # of this (long) page left the success/error banner far from the
    # control that was just used, with no visual confirmation the
    # specific field actually changed without scrolling back down.
    dest = url_for("tenant_detail", domain=domain, _anchor="reset-admin-password")
    try:
        # No operator-chosen value: password=None generates one and flags
        # the account must-change. See set_tenant_admin_password's docstring.
        new_password = provisioner.set_tenant_admin_password(
            domain, actor=f"admin-ui:{session['username']}"
        )
        # Handed to the next render via the session, NOT a query parameter:
        # a URL carrying a live credential lands in browser history, the
        # Referer header of every asset on the page, and Traefik's access
        # log. Popped on read, so a refresh doesn't redisplay it.
        session["new_tenant_admin_password"] = {"domain": domain, "password": new_password}
        flash("New admin password generated -- copy it below, it won't be shown again.", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(dest)


@app.route("/tenants/<domain>/webauthn-clear", methods=["POST"])
@require_auth
@require_2fa
def tenant_clear_webauthn(domain):
    dest = url_for("tenant_detail", domain=domain, _anchor="tenant-2fa")
    try:
        count = provisioner.clear_tenant_webauthn_keys(domain, actor=f"admin-ui:{session['username']}")
        flash(f"Cleared {count} WebAuthn key(s).", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(dest)


@app.route("/tenants/<domain>/waf", methods=["POST"])
@require_auth
@require_2fa
def tenant_waf(domain):
    """Per-tenant WAF engine mode. @require_2fa: turning this Off removes
    a protection layer from a live site, and turning it On can break one
    -- both are consequential enough to sit at the same tier as the other
    per-tenant security controls on this page."""
    dest = url_for("tenant_detail", domain=domain, _anchor="waf")
    mode = request.form.get("mode", "")
    try:
        waf.set_tenant_mode(domain, mode, actor=f"admin-ui:{session['username']}")
        if mode == "On":
            flash("WAF is now blocking. Watch this tenant's WAF log for false "
                  "positives on real traffic.", "ok")
        elif mode == "Off":
            flash("WAF is now off for this tenant -- requests are no longer inspected.", "ok")
        else:
            flash("WAF is detect-only: logging what it would block, blocking nothing.", "ok")
    except ValueError as e:
        flash(f"error: {e}", "error")
    return redirect(dest)


@app.route("/tenants/<domain>/operator-access", methods=["POST"])
@require_auth
@require_2fa
def tenant_operator_access(domain):
    """Grant/revoke temporary tenant-admin access for the signed-in
    operator. @require_2fa: this is the single most consequential thing
    an operator can do to a tenant short of destroying them -- it's full
    owner access to somebody else's site, mail and database."""
    dest = url_for("tenant_detail", domain=domain, _anchor="operator-access")
    action = request.form.get("action")
    actor = f"admin-ui:{session['username']}"
    try:
        if action == "revoke":
            was_active = provisioner.revoke_operator_access(domain, actor=actor)
            flash("Operator access ended." if was_active
                  else "No active grant to end (it had already expired).", "ok")
        else:
            try:
                minutes = int(request.form.get("minutes", "30"))
            except ValueError:
                minutes = 30
            token = provisioner.grant_operator_access(
                domain, operator=session["username"], minutes=minutes, actor=actor,
            )
            # Session, never the URL: this token is a credential, and a
            # query string lands in history, Referer and the proxy log.
            session["new_operator_token"] = {"domain": domain, "token": token}
            flash(f"Access granted for {minutes} minutes. The tenant has been notified in "
                  "their panel and audit log.", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(dest)


@app.route("/tenants/<domain>/totp-clear", methods=["POST"])
@require_auth
@require_2fa
def tenant_clear_totp(domain):
    dest = url_for("tenant_detail", domain=domain, _anchor="tenant-2fa")
    try:
        count = provisioner.clear_tenant_totp(domain, actor=f"admin-ui:{session['username']}")
        flash(f"Cleared authenticator app enrolment for {count} login(s).", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(dest)


@app.route("/tenants/<domain>/reset-panel-access", methods=["POST"])
@require_auth
@require_2fa
def tenant_reset_panel_access(domain):
    try:
        password = provisioner.reset_tenant_panel_access(domain, actor=f"admin-ui:{session['username']}")
        flash(f"Panel access reset -- every prior login is gone, all sessions ended. "
              f"New admin login (shown once): admin / {password}", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/reset-mailbox-passwords", methods=["POST"])
@require_auth
@require_2fa
def tenant_reset_mailbox_passwords(domain):
    try:
        new_passwords = provisioner.reset_tenant_mailbox_passwords(domain, actor=f"admin-ui:{session['username']}")
        if not new_passwords:
            flash("No mailboxes to reset.", "ok")
        else:
            shown = ", ".join(f"{user}: {pw}" for user, pw in sorted(new_passwords.items()))
            flash(f"Reset {len(new_passwords)} mailbox password(s) (shown once): {shown}", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/reset-db-password", methods=["POST"])
@require_auth
@require_2fa
def tenant_reset_db_password(domain):
    try:
        password = provisioner.reset_tenant_db_password(domain, actor=f"admin-ui:{session['username']}")
        flash(f"Database password rotated -- web and tenant-admin containers recreated. "
              f"New DB password (shown once): {password}", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/reset-all-passwords", methods=["POST"])
@require_auth
@require_2fa
def tenant_reset_all_passwords(domain):
    try:
        result = provisioner.reset_tenant_all_passwords(domain, actor=f"admin-ui:{session['username']}")
        mailboxes = result["mailbox_passwords"]
        mailbox_str = (", ".join(f"{user}: {pw}" for user, pw in sorted(mailboxes.items()))
                       if mailboxes else "none")
        flash(f"Everything reset for this tenant (shown once each) -- "
              f"admin: admin / {result['admin_password']} -- "
              f"mailboxes: {mailbox_str} -- "
              f"db password: {result['db_password']}", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/quota", methods=["POST"])
@require_auth
def tenant_set_quota(domain):
    try:
        quota_mb = int(request.form.get("quota_mb", ""))
        if quota_mb < 1:
            raise ValueError
    except ValueError:
        flash("Enter a positive number of MB.", "error")
        return redirect(url_for("tenant_detail", domain=domain))
    try:
        provisioner.set_tenant_quota_limit(domain, quota_mb * 1024 * 1024, actor=f"admin-ui:{session['username']}")
        flash(f"Quota set to {quota_mb} MB.", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/billing-account-id", methods=["POST"])
@require_auth
def tenant_set_billing_account_id(domain):
    billing_account_id = request.form.get("billing_account_id", "").strip()
    provisioner.set_tenant_billing_account_id(domain, billing_account_id, actor=f"admin-ui:{session['username']}")
    flash("Billing account ID updated." if billing_account_id else "Billing account ID cleared.", "ok")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/maintenance", methods=["POST"])
@require_auth
@require_2fa
def tenant_set_maintenance(domain):
    enabled = request.form.get("action") == "enable"
    try:
        provisioner.set_tenant_maintenance_mode(domain, enabled, actor=f"admin-ui:{session['username']}")
        flash("Maintenance mode turned on." if enabled else "Maintenance mode turned off.", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain))


@app.route("/tenants/<domain>/platform-access", methods=["POST"])
@require_auth
@require_2fa
def tenant_platform_access_toggle(domain):
    """Layer 1 of the tenant API/MCP two-layer permission model -- see
    provisioner.set_tenant_api_allowed/set_tenant_mcp_allowed's own
    docstrings. Unlike the operator's own platform_access_toggle (which
    restarts vhsp-admin.service for the REST API half), nothing here
    needs a restart at all -- vhsp_ctl/api.py and mcp_server.py's
    tenant-scoped routes/tools check this flag live on every call, so
    the effect is immediate."""
    action = request.form.get("action")
    actor = f"admin-ui:{session['username']}"
    try:
        if action == "allow_api":
            provisioner.set_tenant_api_allowed(domain, True, actor)
            flash("REST API access allowed for this tenant.", "ok")
        elif action == "disallow_api":
            provisioner.set_tenant_api_allowed(domain, False, actor)
            flash("REST API access disallowed for this tenant.", "ok")
        elif action == "allow_mcp":
            provisioner.set_tenant_mcp_allowed(domain, True, actor)
            flash("MCP access allowed for this tenant.", "ok")
        elif action == "disallow_mcp":
            provisioner.set_tenant_mcp_allowed(domain, False, actor)
            flash("MCP access disallowed for this tenant.", "ok")
    except provisioner.ProvisioningError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_detail", domain=domain, _anchor="platform-access"))


@app.route("/tenants/<domain>/destroy", methods=["POST"])
@require_auth
@require_2fa
def tenant_destroy(domain):
    try:
        provisioner.destroy_tenant(domain, actor=f"admin-ui:{session['username']}")
    except provisioner.ProvisioningError as e:
        return render("<p class='danger'>error: {{ e }}</p><p><a href='{{ url_for('index') }}'>back</a></p>", e=str(e)), 400
    return redirect(url_for("index"))


@app.route("/audit")
@require_auth
def audit_view():
    # Basic filter + limit -- found missing during a real usability pass:
    # this log is a single flat table with no way to narrow it down,
    # already ~150+ rows on a lightly-used deployment and only grows.
    # Deliberately simple (substring match, no full search index) rather
    # than a bigger feature -- matches this codebase's existing posture
    # of hand-rolling only what's actually needed.
    if audit.AUDIT_LOG_PATH.exists():
        lines = audit.AUDIT_LOG_PATH.read_text().splitlines()[::-1]
    else:
        lines = []
    all_entries = [json.loads(line) for line in lines]

    domain_filter = request.args.get("domain", "").strip().lower()
    actor_filter = request.args.get("actor", "").strip().lower()
    action_filter = request.args.get("action", "").strip().lower()
    entries = [
        e for e in all_entries
        if (not domain_filter or domain_filter in (e.get("domain") or "").lower())
        and (not actor_filter or actor_filter in (e.get("actor") or "").lower())
        and (not action_filter or action_filter in (e.get("action") or "").lower())
    ]
    total_matching = len(entries)

    try:
        limit = int(request.args.get("limit", 200))
    except ValueError:
        limit = 200
    showing_all = limit <= 0 or limit >= total_matching
    if not showing_all:
        entries = entries[:limit]

    return render("""
      <h2>Audit log</h2>
      <div class="card">
        <form method="get" class="actions">
          <input type="text" name="domain" placeholder="filter by domain" value="{{ domain_filter }}" style="max-width:200px">
          <input type="text" name="actor" placeholder="filter by actor" value="{{ actor_filter }}" style="max-width:200px">
          <input type="text" name="action" placeholder="filter by action" value="{{ action_filter }}" style="max-width:200px">
          <button type="submit">Filter</button>
          {% if domain_filter or actor_filter or action_filter %}<a href="{{ url_for('audit_view') }}">Clear</a>{% endif %}
        </form>
      </div>
      <p class="muted">
        {% if showing_all %}Showing all {{ total_matching }} matching entr{{ 'y' if total_matching == 1 else 'ies' }}.
        {% else %}Showing the most recent {{ entries|length }} of {{ total_matching }} matching entries --
        <a href="{{ url_for('audit_view', domain=domain_filter, actor=actor_filter, action=action_filter, limit=0) }}">show all</a>.{% endif %}
      </p>
      <div class="card">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Domain</th><th>Actor</th></tr></thead>
          <tbody>
          {% for entry in entries %}
          <tr><td class="muted">{{ entry.ts|humanize_ts }}</td><td><code>{{ entry.action }}</code></td><td>{{ entry.domain }}</td><td>{{ entry.actor }}</td></tr>
          {% else %}
          <tr><td colspan="4" class="muted">No matching entries.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, entries=entries, total_matching=total_matching, showing_all=showing_all,
        domain_filter=domain_filter, actor_filter=actor_filter, action_filter=action_filter)


@app.route("/fail2ban")
@require_auth
def fail2ban_log_view():
    """Read-only, same decorator shape as /audit above (no @require_2fa
    -- unlike /allowlist below, which POSTs data and can affect who
    gets banned, this can't change anything). Distinct function name
    from fail2ban_allowlist_view (the /allowlist route) -- easy to
    confuse, named carefully. Mixes every jail together (sshd, this
    admin UI's own login jail, the shared tenant-admin-login jail, and
    every tenant's own SFTP jail) since that's what /var/log/fail2ban.log
    itself does -- no per-jail filtering in this pass."""
    try:
        content = provisioner.tail_fail2ban_log(200)
    except subprocess.CalledProcessError as e:
        content = None
        error = e.stderr.strip() if e.stderr else str(e)
    else:
        error = None
    return render("""
      <h2>fail2ban</h2>
      <p class="muted">Last 200 lines of /var/log/fail2ban.log -- every jail mixed together
      (host SSH, this admin UI's own login jail, the shared tenant-admin-login jail, and
      every tenant's own SFTP jail). Reload the page to refresh.</p>
      {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
      <div class="card" style="padding:0">
      {% if content %}
        <pre style="margin:0; max-height:600px; overflow-y:auto; font-size:0.8rem; border:none; border-radius:var(--radius);">{{ content }}</pre>
      {% else %}
        <p class="muted" style="padding:1.25rem 1.5rem;margin:0">No entries yet.</p>
      {% endif %}
      </div>
    """, content=content, error=error)


@app.route("/allowlist", methods=["GET", "POST"])
@require_auth
@require_2fa
def fail2ban_allowlist_view():
    """Platform-wide fail2ban allowlist -- IPs/CIDRs never banned by any
    jail (SSH, this admin UI, any tenant's SFTP/admin login). Gated
    behind require_2fa for the same reason the tenant-facing IP
    restrictions page is: a compromised no-2FA account misusing this
    could exempt an attacker's own IP from ever being banned platform-
    wide, not just from one tenant's surface -- see
    vhsp_ctl/fail2ban_allowlist.py for the file this reads/writes and
    deploy/vhsp-fail2ban-allowlist-check for how fail2ban itself
    consults it on every ban decision."""
    error = None
    saved = False
    stale = []
    entries = fail2ban_allowlist.read_entries()
    waf_entries = set(waf.read_allowlist())
    current = "\n".join(entries)
    if request.method == "POST":
        current = request.form.get("entries", "")
        entries = [ln.strip() for ln in current.splitlines() if ln.strip()]
        # Intersected with the submitted list, so deleting an entry from
        # the textarea also drops its WAF bypass rather than leaving an
        # orphaned exemption behind for an IP no longer on the page.
        checked = set(request.form.getlist("waf")) & set(entries)
        error = fail2ban_allowlist.write_entries(entries)
        if not error:
            error = waf.write_allowlist(sorted(checked))
        if not error:
            waf_entries = checked
            saved = True
            stale = waf.apply_allowlist_everywhere()
    return render("""
      <h2>Allowlist</h2>
      <p class="muted">
        IPs/CIDRs here are never banned by any jail on this platform --
        SSH, this admin UI's own login, or any tenant's SFTP/admin-panel
        login. Checked live on every ban decision, no restart needed.
        Tenants can separately allowlist IPs for their own site/panel
        only (see their own Backups/Email-adjacent settings) -- this
        list is platform-wide and takes precedence over nothing, it's
        purely additive.
      </p>
      {% if saved %}<div class="flash">Saved.</div>{% endif %}
      {% if error %}<div class="flash error">{{ error }}</div>{% endif %}
      {% if stale %}<div class="flash warn">Saved, but these tenants' WAF containers
        weren't running so they'll pick the change up on next start:
        {{ stale|join(', ') }}</div>{% endif %}
      <div class="card">
        <form method="post">
          <div class="field">
            <label for="entries">Never ban these (one IP or CIDR per line)</label>
            <textarea id="entries" name="entries" rows="8" placeholder="203.0.113.4&#10;198.51.100.0/24">{{ current }}</textarea>
          </div>

          <h3>Also skip WAF inspection</h3>
          <p class="muted" style="margin-top:0">
            Separate, deliberately. Not being banned means "don't lock this IP out for
            failed logins." Skipping the WAF means "send this IP's requests to the site
            without checking them for SQL injection, XSS or RCE" -- a much bigger
            allowance. Tick it only for an address you control and trust to that level;
            an office or VPN egress covers everyone behind it, including a colleague's
            compromised laptop. Off by default, including for entries added above.
          </p>
          {% if known %}
          <div style="margin-bottom:1rem">
            {% for e in known %}
            <label style="display:block;margin-bottom:0.35rem;font-weight:400">
              <input type="checkbox" name="waf" value="{{ e }}" style="width:auto;margin-right:0.5rem"
                     {% if e in waf_entries %}checked{% endif %}>
              <code>{{ e }}</code>
              {% if e in waf_entries %}<span class="badge badge-warn">WAF bypassed</span>{% endif %}
            </label>
            {% endfor %}
          </div>
          {% else %}
          <p class="muted">Add an IP above and save; it'll appear here to tick.</p>
          {% endif %}
          <button type="submit">Save</button>
        </form>
      </div>
    """, current=current, error=error, saved=saved, stale=stale,
        known=entries, waf_entries=waf_entries)


@app.route("/tenants/<domain>/php", methods=["GET", "POST"])
@require_auth
@require_2fa
def tenant_php(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        submitted = set(request.form.getlist("fn"))
        toggles.write_enabled_functions(phpconf_dir, submitted)
        flash("Saved.", "ok")
        return redirect(url_for("tenant_php", domain=domain))
    return render(TENANT_NAV + """
      <p>Disabled by default. Re-enabling any of these gives PHP code
      running on this tenant's site the ability to run arbitrary programs
      on the server -- only enable what the tenant's application genuinely
      needs.</p>
      <div class="warn">Changes take effect within a few seconds (the web
      container reloads PHP-FPM automatically).</div>
      <form method="post">
        <div class="card">
          <table>
            <thead><tr><th style="width:2.5rem"></th><th>Function</th><th>What it does</th></tr></thead>
            <tbody>
            {% for fn, desc in functions %}
            <tr>
              <td><input type="checkbox" name="fn" value="{{ fn }}" {% if fn in enabled %}checked{% endif %}></td>
              <td><code>{{ fn }}</code></td>
              <td class="muted">{{ desc }}</td>
            </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
        <button type="submit">Save</button>
      </form>
    """, t=t, functions=toggles.FUNCTIONS, enabled=toggles.read_enabled_functions(phpconf_dir))


@app.route("/tenants/<domain>/fallback", methods=["GET", "POST"])
@require_auth
def tenant_fallback(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    webroot_dir = Path(t.webroot_host_path)
    if request.method == "POST":
        toggles.set_fallback_enabled(webroot_dir, "enabled" in request.form)
        flash("Saved.", "ok")
        return redirect(url_for("tenant_fallback", domain=domain))
    return render(TENANT_NAV + """
      <p>By default, a request that doesn't match a real file falls back
      to the tenant's front controller -- <code>index.php</code> if they
      have one (WordPress/Laravel/etc.-style pretty permalinks), otherwise
      <code>index.html</code>.</p>
      <div class="warn">Takes effect immediately -- no reload, no downtime.</div>
      <div class="card">
        <form method="post">
          <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400">
            <input type="checkbox" name="enabled" style="width:auto" {% if enabled %}checked{% endif %}>
            Fall back to index.php / index.html on 404 (recommended)
          </label>
          <div style="margin-top:1rem"><button type="submit">Save</button></div>
        </form>
      </div>
    """, t=t, enabled=toggles.fallback_enabled(webroot_dir))


@app.route("/tenants/<domain>/auth", methods=["GET", "POST"])
@require_auth
def tenant_auth(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        if request.form.get("action") == "disable":
            toggles.disable_basic_auth(phpconf_dir)
            flash("Password protection disabled.", "ok")
        else:
            problem = toggles.set_basic_auth(
                phpconf_dir, request.form.get("username", "").strip(), request.form.get("password", "")
            )
            flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_auth", domain=domain))
    current_user = toggles.read_basic_auth_user(phpconf_dir)
    return render(TENANT_NAV + """
      <p>Locks the entire site behind a single username/password (HTTP
      Basic Auth). Applies to every page, including PHP.</p>
      <div class="warn">Takes effect within a few seconds (the web
      container reloads nginx automatically).</div>
      <div class="card">
        {% if current_user %}<p style="margin-top:0">Currently <span class="badge badge-ok">enabled</span> for user <code>{{ current_user }}</code>.</p>
        {% else %}<p class="muted" style="margin-top:0">Currently disabled -- the site is public.</p>{% endif %}
        <form method="post">
          <div class="field"><label>Username</label><input type="text" name="username" value="{{ current_user }}" autocomplete="off"></div>
          <div class="field"><label>New password</label><input type="password" name="password" placeholder="leave blank to keep disabled/unchanged" autocomplete="new-password"></div>
          <div class="actions">
            <button type="submit" name="action" value="save">Save</button>
            {% if current_user %}<button type="submit" name="action" value="disable" class="btn-ghost">Disable protection</button>{% endif %}
          </div>
        </form>
      </div>
    """, t=t, current_user=current_user)


@app.route("/tenants/<domain>/error-pages", methods=["GET", "POST"])
@require_auth
def tenant_error_pages(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        problem = toggles.write_lines_file(
            phpconf_dir, "error_pages.txt", request.form.get("lines", ""), toggles.validate_error_page_line
        )
        flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_error_pages", domain=domain))
    return render(TENANT_NAV + """
      <p>Maps an HTTP error code to a page in the tenant's own webroot,
      e.g. a custom 404. One per line: <code>CODE /path/to/page.html</code>.</p>
      <div class="warn">Takes effect within a few seconds.</div>
      <div class="card">
        <form method="post">
          <div class="field"><textarea name="lines" rows="6" placeholder="404 /custom-404.html">{{ current }}</textarea></div>
          <button type="submit">Save</button>
        </form>
      </div>
    """, t=t, current=toggles.read_lines_file(phpconf_dir, "error_pages.txt"))


@app.route("/tenants/<domain>/redirects", methods=["GET", "POST"])
@require_auth
@require_2fa
def tenant_redirects(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        problem = toggles.write_lines_file(
            phpconf_dir, "redirects.txt", request.form.get("lines", ""), toggles.validate_redirect_line
        )
        flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_redirects", domain=domain))
    return render(TENANT_NAV + """
      <p>Permanent (301) redirects for exact paths. One per line:
      <code>/old-path https://example.com/new-path</code> (the target can
      also be an absolute path on the tenant's own site).</p>
      <div class="warn">Takes effect within a few seconds. Only exact-path
      matches are supported (no wildcards).</div>
      <div class="card">
        <form method="post">
          <div class="field"><textarea name="lines" rows="6" placeholder="/old-page https://example.com/new-page">{{ current }}</textarea></div>
          <button type="submit">Save</button>
        </form>
      </div>
    """, t=t, current=toggles.read_lines_file(phpconf_dir, "redirects.txt"))


@app.route("/tenants/<domain>/noexec-dirs", methods=["GET", "POST"])
@require_auth
@require_2fa
def tenant_noexec_dirs(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        problem = toggles.write_lines_file(
            phpconf_dir, "noexec_dirs.txt", request.form.get("lines", ""), toggles.validate_noexec_dir_line
        )
        flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_noexec_dirs", domain=domain))
    return render(TENANT_NAV + """
      <p>Denies PHP execution under these directories (relative to the
      webroot), regardless of what gets uploaded there -- one directory per
      line, no leading/trailing slash, e.g. <code>wp-content/uploads</code>.
      Seeded with common upload/writable directory names at creation; a
      tenant's effective PHP-FPM user is the same as their SFTP user, so a
      dropped executable file anywhere writable is a full compromise, not a
      contained one -- this is meant to stay on for any tenant serving
      user-uploaded content.</p>
      <div class="warn">Takes effect within a few seconds.</div>
      <div class="card">
        <form method="post">
          <div class="field"><textarea name="lines" rows="6" placeholder="wp-content/uploads">{{ current }}</textarea></div>
          <button type="submit">Save</button>
        </form>
      </div>
    """, t=t, current=toggles.read_lines_file(phpconf_dir, "noexec_dirs.txt"))


@app.route("/tenants/<domain>/ip-acl", methods=["GET", "POST"])
@require_auth
@require_2fa
def tenant_ip_acl(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        problem = toggles.write_ip_acl(phpconf_dir, request.form.get("mode", ""), request.form.get("lines", ""))
        flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_ip_acl", domain=domain))
    mode, current = toggles.read_ip_acl(phpconf_dir)
    return render(TENANT_NAV + """
      <p>Restricts the whole site to specific IPs/CIDRs, or blocks
      specific ones -- everyone else is treated the opposite way.</p>
      <div class="warn">Takes effect within a few seconds. "Only allow" mode
      with the wrong IPs/CIDRs silently makes the live site unreachable to
      everyone, including the tenant's own real visitors -- there's no
      confirmation step and no automatic recovery. Your own current IP
      (viewing this admin panel) is <code>{{ your_ip }}</code> -- a useful
      reference point, though not necessarily the tenant's own visitors' IPs.</div>
      <div class="card">
        <form method="post">
          <div class="field" style="display:flex;flex-direction:column;gap:0.4rem">
            <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="allow" style="width:auto" {% if mode == "allow" %}checked{% endif %}> Only allow these IPs (block everyone else)</label>
            <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="deny" style="width:auto" {% if mode == "deny" %}checked{% endif %}> Block these IPs (allow everyone else)</label>
            <label style="display:flex;align-items:center;gap:0.5rem;font-weight:400"><input type="radio" name="mode" value="" style="width:auto" {% if not mode %}checked{% endif %}> Disabled -- no restriction</label>
          </div>
          <div class="field"><textarea name="lines" rows="6" placeholder="203.0.113.0/24&#10;198.51.100.7">{{ current }}</textarea></div>
          <button type="submit">Save</button>
        </form>
      </div>
    """, t=t, mode=mode, current=current, your_ip=request.remote_addr)


@app.route("/tenants/<domain>/email", methods=["GET", "POST"])
@require_auth
# Gated for the same reason /tenants/<domain>/reset-mailbox-passwords above
# already is: this page resets individual mailbox passwords (postmaster@
# included), so leaving it open let an operator without a second factor
# reach that route's exact outcome one mailbox at a time, which made the
# gate on the bulk button decorative. Mailboxes are also the recovery
# channel for most other accounts a tenant owns -- the same reasoning that
# put require_2fa on the tenant side's own /email page.
@require_2fa
def tenant_email(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    phpconf_dir = Path(t.phpconf_host_path)
    if request.method == "POST":
        action = request.form.get("action")
        user = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        if action == "add":
            problem = toggles.add_mailbox(phpconf_dir, user, password)
        elif action == "reset":
            problem = toggles.reset_mailbox_password(phpconf_dir, user, password)
        elif action == "delete":
            problem = toggles.delete_mailbox(phpconf_dir, user)
        elif action == "quota":
            quota_mb = request.form.get("quota_mb", "").strip()
            if not quota_mb:
                problem = toggles.set_mailbox_quota(phpconf_dir, user, None)
            else:
                try:
                    problem = toggles.set_mailbox_quota(phpconf_dir, user, int(quota_mb) * 1024 * 1024)
                except ValueError:
                    problem = "Quota must be a whole number of MB."
        else:
            problem = "Unknown action."
        flash(problem, "error") if problem else flash("Saved.", "ok")
        return redirect(url_for("tenant_email", domain=domain))
    boxes = toggles.read_mailboxes(phpconf_dir)
    mailboxes = sorted(boxes, key=lambda u: (u != toggles.POSTMASTER, u))
    return render(TENANT_NAV + """
      <p class="muted">
        Server: <code>mail.{{ t.domain }}</code> &middot;
        IMAP: port 993 (implicit TLS) &middot;
        SMTP (submission): port 465 (implicit TLS) &middot;
        Webmail: <a href="https://webmail.{{ t.domain }}/" target="_blank" rel="noopener noreferrer">https://webmail.{{ t.domain }}/</a>
      </p>
      <div class="warn">Changes take effect within a few seconds
      (postfix/dovecot reload automatically). Per-mailbox quotas are
      independent of the tenant's combined disk quota above, but usage
      still counts toward it either way.</div>
      <div class="card">
        <table>
          <thead><tr><th>Mailbox</th><th>Quota</th><th>Reset password</th><th></th></tr></thead>
          <tbody>
          {% for user in mailboxes %}
          <tr>
            <td><code>{{ user }}@{{ t.domain }}</code>{% if user == postmaster %} <span class="muted">(required)</span>{% endif %}</td>
            <td>
              <form class="inline actions" method="post" autocomplete="off">
                <input type="hidden" name="action" value="quota">
                <input type="hidden" name="user" value="{{ user }}">
                <input type="number" name="quota_mb" min="1" placeholder="unlimited" value="{{ boxes[user].quota_bytes // 1048576 if boxes[user].quota_bytes else '' }}" style="width:8em">
                <span class="muted">MB</span> <button type="submit">Set</button>
              </form>
            </td>
            <td>
              <form class="inline actions" method="post" autocomplete="off">
                <input type="hidden" name="action" value="reset">
                <input type="hidden" name="user" value="{{ user }}">
                <input type="password" name="password" placeholder="new password" required autocomplete="new-password" style="width:11em">
                <button type="submit">Reset</button>
              </form>
            </td>
            <td>
              {% if user != postmaster %}
              <form class="inline" method="post"
                    onsubmit="return confirm('Delete ' + '{{ user }}' + '@{{ t.domain }}? This cannot be undone.');">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="user" value="{{ user }}">
                <button class="danger" type="submit">Delete</button>
              </form>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
      <h3>Add a mailbox</h3>
      <div class="card">
        <form method="post" autocomplete="off">
          <input type="hidden" name="action" value="add">
          <div class="actions">
            <label class="sr-only" for="new-mailbox-user">Mailbox name</label>
            <input id="new-mailbox-user" type="text" name="user" placeholder="sales" autocomplete="off" style="max-width:160px">
            <span class="muted">@{{ t.domain }}</span>
            <label class="sr-only" for="new-mailbox-password">Password</label>
            <input id="new-mailbox-password" type="password" name="password" placeholder="password" autocomplete="new-password" style="max-width:200px">
            <button type="submit">Add</button>
          </div>
        </form>
      </div>
    """, t=t, mailboxes=mailboxes, boxes=boxes, postmaster=toggles.POSTMASTER)


DNS_RECORDS_TABLE = """
{% if records %}
<form method="get" style="margin-bottom:1rem">
  <button type="submit" name="check" value="1">Check records</button>
  {% if checked %}<span class="muted" style="margin-left:0.5rem">Checked against live DNS just now.</span>{% endif %}
</form>
{# No overflow-x on this card, deliberately. Any scroll container between
   a sticky <thead> and the viewport becomes that header's containing
   block, so `thead th { top: var(--topbar-h) }` stopped meaning "sit
   under the topbar" and started meaning "sit --topbar-h down from the
   top of THIS card" -- which rendered an empty band where the header
   belonged and floated the header over the second row. Reported on this
   page; the header is the only thing here that was ever sticky, so the
   card is what had to give. The Value column already wraps
   (word-break:break-all below), so nothing needs to scroll sideways. #}
<div class="card">
  <table>
    <thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
    <tbody>
    {% for r in records %}
    <tr class="{{ 'dns-row-ok' if r.ok }}">
      <td>{{ r.kind }}
        {% if r.ok %} <span class="badge badge-ok">live</span>
        {% elif r.ok is defined %} <span class="badge badge-warn">not live yet</span>
        {% endif %}
      </td>
      <td><code class="copyable" title="Click to copy" tabindex="0" role="button" onclick="vhspCopyDns(this)" onkeydown="vhspCopyDnsKey(event, this)">{{ r.name }}</code></td>
      <td style="word-break:break-all"><code class="copyable" title="Click to copy" tabindex="0" role="button" onclick="vhspCopyDns(this)" onkeydown="vhspCopyDnsKey(event, this)">{{ r.value }}</code>
        {% if r.note %}<div class="muted" style="margin-top:0.25rem">{{ r.note }}</div>{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% elif error %}
<div class="flash error">{{ error }}</div>
{% else %}
<div class="card muted">Not available yet -- the mail server generates its signing key on
first start, which can take a few seconds after this tenant was created.</div>
{% endif %}
"""


@app.route("/tenants/<domain>/dns", methods=["GET"])
@require_auth
def tenant_dns(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    # Reads the same host-written file images/tenant-admin/'s Email page
    # reads (see vhsp_ctl.provisioner._write_dns_records_status) rather
    # than recomputing via dns_records.compute_records itself -- this
    # process already has full docker access and could call it live, but
    # reusing the cached file avoids a redundant docker-exec round trip
    # and guarantees the operator sees exactly what the tenant sees, not
    # a second, possibly-momentarily-different computation.
    records_file = Path(t.phpconf_host_path) / "dns_records.json"
    records = []
    if records_file.exists():
        try:
            records = json.loads(records_file.read_text())
        except json.JSONDecodeError:
            pass
    checked = request.args.get("check") == "1"
    if checked and records:
        records = dns_records.check_records_live(records)
    return render(TENANT_NAV + """
      <p class="muted">Same suggested records this tenant's own Email page shows them --
      nothing here changes DNS for you.</p>
    """ + DNS_RECORDS_TABLE, t=t, records=records, error=None, checked=checked)


@app.route("/tenants/<domain>/backups", methods=["GET"])
@require_auth
@require_2fa
def tenant_backups(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    snapshots = registry.list_backups(domain, destination="operator")
    return render(TENANT_NAV + """
      <div class="card">
        <h3 style="margin-top:0">Operator backups</h3>
        <p class="muted">
          Always on, no opt-out -- every tenant is backed up automatically to the
          operator's own destination regardless of anything configured below.
          Encrypted with the operator's <code>age</code> key and signed; a
          signature check runs before any restore, operator or self-service, so a
          compromised destination can't smuggle tampered content back in.
        </p>
        <form method="post" action="{{ url_for('tenant_set_backup_settings', domain=t.domain) }}">
          <div class="actions">
            <div class="field" style="margin:0">
              <label>Retention (backups kept)</label>
              <input type="number" name="retention_count" min="1" placeholder="{{ default_retention }} (platform default)"
                     value="{{ t.backup_retention_count or '' }}" style="width:12rem">
            </div>
            <div class="field" style="margin:0">
              <label>Interval</label>
              <select name="interval" style="width:12rem">
                <option value="">{{ default_interval }} (platform default)</option>
                {% for choice in interval_choices %}
                <option value="{{ choice }}" {{ 'selected' if t.backup_interval == choice }}>{{ choice }}</option>
                {% endfor %}
              </select>
            </div>
            <button type="submit" style="align-self:flex-end">Save</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Back up now</h3>
        <p class="muted">Runs immediately rather than waiting for the next scheduled sweep.</p>
        <form method="post" action="{{ url_for('tenant_backup_now', domain=t.domain) }}">
          <button type="submit">Back up now</button>
        </form>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Snapshots (operator destination)</h3>
        <table>
          <thead><tr><th>Created</th><th>Size</th><th>Encrypted</th><th>Status</th><th></th></tr></thead>
          <tbody>
          {% for s in snapshots %}
          <tr>
            <td>{{ s.created_at|humanize_ts }}</td>
            <td>{{ format_mb(s.size_bytes) }}</td>
            <td>{{ 'yes' if s.encrypted else 'no' }}</td>
            <td>{{ s.status }}</td>
            <td style="text-align:right">
              <form class="inline" method="post" action="{{ url_for('tenant_backup_restore', domain=t.domain) }}"
                    onsubmit="return confirm('Restore this snapshot into {{ t.domain }}? This overwrites current webroot, mail, phpconf, and database content. WebAuthn keys are left untouched.');">
                <input type="hidden" name="snapshot_name" value="{{ s.dest_path.split('/')[-1] }}">
                <button type="submit">Restore</button>
              </form>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="muted">No backups yet.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, t=t, snapshots=snapshots, default_retention=DEFAULT_BACKUP_RETENTION_COUNT,
        default_interval=DEFAULT_BACKUP_INTERVAL, interval_choices=BACKUP_INTERVAL_CHOICES,
        format_mb=format_mb)


@app.route("/tenants/<domain>/backups/settings", methods=["POST"])
@require_auth
@require_2fa
def tenant_set_backup_settings(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    retention_raw = request.form.get("retention_count", "").strip()
    try:
        retention_count = int(retention_raw) if retention_raw else 0
        if retention_count < 0:
            raise ValueError
    except ValueError:
        flash("Retention must be a positive whole number, or blank for the platform default.", "error")
        return redirect(url_for("tenant_backups", domain=domain))
    interval = request.form.get("interval", "").strip()
    if interval and interval not in BACKUP_INTERVAL_CHOICES:
        flash("Unknown interval.", "error")
        return redirect(url_for("tenant_backups", domain=domain))
    # Only retention/interval are operator-settable here -- destination/key/
    # encryption fields are tenant self-service only (see tenant-admin's own
    # Backups page), so this preserves whatever's already there untouched.
    registry.set_backup_settings(
        domain, retention_count=retention_count, interval=interval,
        dest_host=t.backup_dest_host, dest_port=t.backup_dest_port,
        dest_path=t.backup_dest_path, dest_user=t.backup_dest_user,
        encryption_enabled=t.backup_encryption_enabled,
    )
    flash("Backup settings saved.", "ok")
    return redirect(url_for("tenant_backups", domain=domain))


@app.route("/tenants/<domain>/backups/now", methods=["POST"])
@require_auth
@require_2fa
def tenant_backup_now(domain):
    try:
        backup.create_backup(domain, actor=f"admin-ui:{session['username']}")
        flash("Backup created.", "ok")
    except backup.BackupError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_backups", domain=domain))


@app.route("/tenants/<domain>/backups/restore", methods=["POST"])
@require_auth
@require_2fa
def tenant_backup_restore(domain):
    snapshot_name = request.form.get("snapshot_name", "").strip()
    if not snapshot_name:
        flash("Missing snapshot.", "error")
        return redirect(url_for("tenant_backups", domain=domain))
    try:
        backup.restore_backup(domain, snapshot_name, source="operator", actor=f"admin-ui:{session['username']}")
        flash("Restore complete.", "ok")
    except backup.BackupError as e:
        flash(f"error: {e}", "error")
    return redirect(url_for("tenant_backups", domain=domain))


@app.route("/backups")
@require_auth
@require_2fa
def backups_browse():
    try:
        domains = backup.list_remote_domains(source="operator")
    except backup.BackupError as e:
        return render("<p class='danger'>error: {{ e }}</p>", e=str(e)), 400
    return render("""
      <h2>Backups</h2>
      <p class="muted">
        Every domain that has ever been backed up to the operator's shared
        destination -- including ones destroyed or never provisioned on this
        deployment at all. Restoring one recreates it from scratch here.
      </p>
      <div class="card">
        <table>
          <thead><tr><th>Domain</th><th></th></tr></thead>
          <tbody>
          {% for d in domains %}
          <tr><td>{{ d }}</td><td><a href="{{ url_for('backups_domain', domain=d) }}">View snapshots</a></td></tr>
          {% else %}
          <tr><td colspan="2" class="muted">Nothing on the operator destination yet.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, domains=domains)


@app.route("/dns")
@require_auth
def dns_view():
    try:
        platform_records = [asdict(r) for r in dns_records.platform_records()]
        platform_error = None
    except dns_records.DnsRecordsError as e:
        platform_records = []
        platform_error = str(e)
    checked = request.args.get("check") == "1"
    if checked and platform_records:
        platform_records = dns_records.check_records_live(platform_records)
    tenants = registry.list_tenants()
    return render("""
      <h2>DNS</h2>
      <p class="muted">
        Suggested records only -- nothing here changes DNS for you. No
        platform-hosted zone/API integration exists yet (architecture.md's
        DNS automation section documents that as still undecided), so this
        is what a human pastes into whatever actually hosts each zone.
      </p>
      <h3>Platform-wide</h3>
      <p class="muted">Exists once for the whole platform, not per-tenant -- e.g. the
      shared inbound mail gateway every tenant's MX record points at.</p>
    """ + DNS_RECORDS_TABLE + """
      <h3>Per-tenant</h3>
      <div class="table-filter">
        <label class="sr-only" for="dns-tenant-filter">Filter tenants</label>
        <input type="search" id="dns-tenant-filter" placeholder="Filter by domain&hellip;"
               data-filter-target="dns-tenant-table" data-filter-noun="tenant" autocomplete="off">
        <span class="muted filter-count" data-filter-count="dns-tenant-table" aria-live="polite"></span>
      </div>
      <div class="card">
        <table id="dns-tenant-table">
          <thead><tr><th>Domain</th><th></th></tr></thead>
          <tbody>
          {% for t in tenants %}
          <tr><td>{{ t.domain }}</td><td><a href="{{ url_for('tenant_dns', domain=t.domain) }}">View suggested records</a></td></tr>
          {% else %}
          <tr data-filter-skip><td colspan="2" class="muted">No tenants yet.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, records=platform_records, error=platform_error, tenants=tenants, checked=checked)


@app.route("/backups/<domain>")
@require_auth
@require_2fa
def backups_domain(domain):
    try:
        snapshots = backup.list_remote_snapshots_detailed(domain, source="operator")
    except backup.BackupError as e:
        return render("<p class='danger'>error: {{ e }}</p>", e=str(e)), 400
    existing = registry.get_tenant_any_status(domain)
    total_bytes = sum(s["size_bytes"] or 0 for s in snapshots)
    return render("""
      <h2>{{ domain }}</h2>
      {% if existing %}
      <p class="muted">A tenant for this domain exists here now (status: {{ existing.status }}) --
      restoring will overwrite its current content in place, leaving its WebAuthn keys untouched.
      Use "restore as" to recreate under a different domain instead.</p>
      {% else %}
      <p class="muted">No tenant for this domain exists on this deployment -- restoring recreates it
      from scratch, password-only (WebAuthn is never in a backup).</p>
      {% endif %}
      {% if snapshots %}
      <p class="muted">{{ snapshots|length }} snapshot{{ '' if snapshots|length == 1 else 's' }},
      {{ total_bytes|format_bytes }} total on the backup host. Sizes are the
      encrypted archives as stored remotely.</p>
      {% endif %}
      <div class="card">
        <table>
          <thead><tr><th>Taken</th><th>Size</th><th>Snapshot</th><th></th></tr></thead>
          <tbody>
          {% for s in snapshots %}
          <tr>
            <td style="white-space:nowrap">
              {%- if s.taken_at -%}{{ s.taken_at|humanize_ts }}
              {%- else -%}<span class="muted">unknown</span>{%- endif -%}
            </td>
            <td style="white-space:nowrap">{{ s.size_bytes|format_bytes }}</td>
            <td><code>{{ s.name }}</code></td>
            <td style="text-align:right">
              <form class="inline" method="post" action="{{ url_for('backups_restore', domain=domain) }}"
                    onsubmit="return confirm('Restore ' + '{{ s.name }}' + '? This may overwrite an existing tenant\\'s content, or create a new one.');">
                <input type="hidden" name="snapshot_name" value="{{ s.name }}">
                <input type="text" name="as_domain" placeholder="restore as (optional, default {{ domain }})" style="width:16rem;display:inline-block;margin-right:0.5rem">
                <button type="submit">Restore</button>
              </form>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="4" class="muted">No snapshots for this domain.</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, domain=domain, snapshots=snapshots, existing=existing, total_bytes=total_bytes)


@app.route("/backups/<domain>/restore", methods=["POST"])
@require_auth
@require_2fa
def backups_restore(domain):
    snapshot_name = request.form.get("snapshot_name", "").strip()
    as_domain = request.form.get("as_domain", "").strip() or None
    if not snapshot_name:
        flash("Missing snapshot.", "error")
        return redirect(url_for("backups_domain", domain=domain))
    try:
        t = backup.restore_backup(domain, snapshot_name, source="operator", target_domain=as_domain,
                                   actor=f"admin-ui:{session['username']}")
        flash(f"Restored to {t.domain}.", "ok")
        return redirect(url_for("tenant_detail", domain=t.domain))
    except backup.BackupError as e:
        flash(f"error: {e}", "error")
        return redirect(url_for("backups_domain", domain=domain))


@app.route("/tenants/<domain>/audit")
@require_auth
@require_2fa
def tenant_audit(domain):
    """The tenant's own panel audit log, for incident response.

    @require_2fa because this is somebody else's activity history --
    every login they made, every setting they touched, from which IP.
    That's the same "consequential, read someone else's business" tier
    as the credential-reset levers on the detail page, not the same tier
    as viewing their nginx logs.

    Read off the host, so it still works when the tenant's container is
    stopped or wedged -- which during an incident is the likely state,
    and is exactly when their own /audit page can't be trusted anyway.
    """
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    action_filter = request.args.get("action", "").strip()
    actor_filter = request.args.get("actor", "").strip()
    chain_ok, chain_count = provisioner.tenant_audit_verify(domain)
    entries = provisioner.tenant_audit_entries(
        domain, limit=300, action_filter=action_filter, actor_filter=actor_filter,
    )
    return render(TENANT_NAV + """
      <h3>Panel audit log</h3>
      <p class="muted">
        Everything done in <strong>this tenant's own admin panel</strong> -- their logins
        (including failed ones and the IP they came from), and every setting they changed.
        Written by the tenant's container onto its phpconf volume; read here straight off
        the host, so it still works when that container is stopped or wedged.
        This is <em>their</em> activity -- your own actions against this tenant are in the
        <a href="{{ url_for('audit_view') }}">operator audit log</a> instead.
      </p>
      <div class="card">
        <p style="margin-top:0">
          {% if chain_ok %}<span class="badge badge-ok">Chain intact</span>
          <span class="muted">{{ chain_count }} entries verified.</span>
          {% else %}<span class="badge badge-warn">Chain broken</span>
          <span class="muted">First mismatch at entry #{{ chain_count }} -- entries before it still verify.
          Treat anything at or after that point as untrustworthy.</span>
          {% endif %}
        </p>
        <p class="muted" style="margin-bottom:0">
          Passwords, one-time codes, SQL the tenant ran, and file contents are never
          recorded by the tenant panel -- only that the action happened. Entries are
          hash-chained, so edits or deletions show up as a broken chain above. Root on
          this host could still rewrite the file and recompute the chain; treat this as
          tamper-evident, not tamper-proof.
        </p>
      </div>
      <form method="get" class="table-filter">
        <label class="sr-only" for="f-action">Filter by action</label>
        <input type="search" id="f-action" name="action" value="{{ action_filter }}" placeholder="Filter by action&hellip;" autocomplete="off">
        <label class="sr-only" for="f-actor">Filter by user</label>
        <input type="search" id="f-actor" name="actor" value="{{ actor_filter }}" placeholder="Filter by user&hellip;" autocomplete="off">
        <button type="submit">Filter</button>
        {% if action_filter or actor_filter %}<a href="{{ url_for('tenant_audit', domain=t.domain) }}" class="muted">clear</a>{% endif %}
      </form>
      <div class="card">
        <table>
          <thead><tr><th>When</th><th>User</th><th>Action</th><th>From</th><th>Details</th></tr></thead>
          <tbody>
          {% for e in entries %}
          <tr>
            <td style="white-space:nowrap">{{ e.ts|humanize_ts }}</td>
            <td>{{ e.actor }}</td>
            <td><code>{{ e.action }}</code>{% if e.status and e.status >= 400 %} <span class="badge badge-warn">{{ e.status }}</span>{% endif %}</td>
            <td class="muted">{{ e.ip or '--' }}</td>
            <td style="word-break:break-word">
              {%- if e.detail -%}
                {%- for k, v in e.detail.items() %}<div class="muted"><code>{{ k }}</code>: {{ v }}</div>{% endfor -%}
              {%- else -%}<span class="muted">&mdash;</span>{%- endif -%}
            </td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="muted">
            {% if action_filter or actor_filter %}No matching entries.
            {% else %}Nothing logged yet -- this tenant's panel hasn't been used since audit
            logging was added.{% endif %}
          </td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    """, t=t, entries=entries, chain_ok=chain_ok, chain_count=chain_count,
        action_filter=action_filter, actor_filter=actor_filter)


@app.route("/tenants/<domain>/logs")
@require_auth
def tenant_logs(domain):
    t, err = get_tenant_or_404(domain)
    if err:
        return err
    logs_dir = Path(t.logs_host_path)
    entries = [(fname, label, toggles.tail_log(logs_dir, fname)) for fname, label in toggles.LOG_FILES]
    # Coraza's audit log never reaches logs_dir (no file mount -- it
    # only ever goes to the WAF container's own stdout), so this one
    # entry is fetched via the Docker API instead of a file read, same
    # None-means-"no entries yet" contract as the rest of this list --
    # see provisioner.tail_waf_log's own docstring.
    entries.append(("waf", "WAF (Coraza)", provisioner.tail_waf_log(t.slug, toggles.TAIL_LINES)))
    return render(TENANT_NAV + """
      <p class="muted">Last {{ tail_lines }} lines of each. Reload the page to refresh.</p>
      {% for fname, label, content in logs %}
        <h3>{{ label }}</h3>
        <div class="card" style="padding:0">
        {% if content is none %}
          <p class="muted" style="padding:1.25rem 1.5rem;margin:0">No entries yet.</p>
        {% else %}
          <pre style="margin:0; max-height:400px; overflow-y:auto; font-size:0.8rem; border:none; border-radius:var(--radius);">{{ content }}</pre>
        {% endif %}
        </div>
      {% endfor %}
    """, t=t, logs=entries, tail_lines=toggles.TAIL_LINES)


MANUAL_PAGE = """
<h2>Operator manual</h2>
<p class="muted">Every setting, option, and feature on this admin UI, in one place --
what each one does, when to use it, and what it doesn't do. Not a substitute for
architecture.md or the control-plane README (those cover the *why* and the
verification history); this is the *what*, written for whoever is actually
clicking the buttons.</p>

<div class="card">
  <p class="eyebrow" style="margin-top:0">Jump to</p>
  <ul class="toc">
    <li><a href="#tenants">Tenants list &amp; create</a></li>
    <li><a href="#tenant-overview">Tenant overview &amp; credentials</a></li>
    <li><a href="#quota">Disk quota</a></li>
    <li><a href="#billing">Billing account ID</a></li>
    <li><a href="#ssh-key">SSH/SFTP public key</a></li>
    <li><a href="#reset-admin-password">Reset tenant admin password</a></li>
    <li><a href="#tenant-webauthn">Tenant WebAuthn keys</a></li>
    <li><a href="#incident-response">Incident response</a></li>
    <li><a href="#maintenance">Maintenance mode</a></li>
    <li><a href="#destroy-tenant">Destroy tenant</a></li>
    <li><a href="#php-functions">PHP functions</a></li>
    <li><a href="#fallback">404 handling</a></li>
    <li><a href="#basic-auth">Password protection</a></li>
    <li><a href="#error-pages">Error pages</a></li>
    <li><a href="#redirects">Redirects</a></li>
    <li><a href="#noexec-dirs">No-exec directories</a></li>
    <li><a href="#ip-acl">IP restrictions</a></li>
    <li><a href="#tenant-email">Email (per tenant)</a></li>
    <li><a href="#dns">DNS (per tenant &amp; platform-wide)</a></li>
    <li><a href="#tenant-backups">Backups (per tenant)</a></li>
    <li><a href="#backups-browse">Backups (browse any domain)</a></li>
    <li><a href="#tenant-logs">Logs (per tenant)</a></li>
    <li><a href="#operators">Operators</a></li>
    <li><a href="#audit-log">Audit log</a></li>
    <li><a href="#fail2ban">fail2ban log</a></li>
    <li><a href="#allowlist">fail2ban allowlist (platform-wide)</a></li>
    <li><a href="#my-account">My account</a></li>
    <li><a href="#api-mcp">API tokens, REST API &amp; MCP</a></li>
    <li><a href="#tenant-api-mcp">Allowing tenant API/MCP access</a></li>
    <li><a href="#security-model">How the pieces fit together</a></li>
  </ul>
</div>

<div class="docs">

<h3 id="tenants">Tenants list &amp; create</h3>
<p>The <a href="{{ url_for('index') }}">Tenants</a> page lists every active tenant
(domain, billing account ID if set, status, SSH port, created date). Creating one
needs only a domain -- provisioning is fully automatic: web + database + SFTP +
mail + tenant-admin containers, a private per-tenant DB network, unique generated
credentials, a per-tenant Coraza WAF sidecar, a per-tenant fail2ban SFTP jail, and
Traefik routing, all in one synchronous call that can take 60-90 seconds for a
full stack. <strong>Destroy</strong> (from this list or the tenant's own page,
below) tears down every one of those resources -- containers, volumes, host
directories, DNS/routing entries, the fail2ban jail -- and is not reversible from
here; the only way back is restoring from a backup (see Backups below).</p>

<h3 id="tenant-overview">Tenant overview &amp; credentials</h3>
<p>Clicking a domain opens its detail page: live site link, slug, status,
container names, the private DB network, volume names and host paths, database
name/user/password, SFTP connection details (key-only, no password fallback --
a tenant is locked out of SFTP entirely until a key is set), mail
container/hostname/mailbox/password, and links to the tenant's own admin panel
and shared webmail. Every credential shown here is plaintext, visible to any
authenticated operator -- this is the one page on the platform that shows them
in the clear (the REST API's equivalent endpoint deliberately redacts them by
default; see API tokens below).</p>

<h3 id="quota">Disk quota</h3>
<p>A soft quota only -- nothing currently blocks writes past it. Combined
web + database + mail usage is checked live on every page load and shown as a
progress bar (turns amber at 80%, red at 100%) here and on the tenant's own
overview page. Set a new limit in MB any time; there's no platform-wide default
enforced automatically if left unset.</p>

<h3 id="billing">Billing account ID</h3>
<p>An opaque string tying this tenant to an account in external billing
software (Stripe customer ID, etc.) -- operator-set only, never shown or
editable on the tenant's own admin panel. Purely a label the platform doesn't
interpret; leave it blank to clear it.</p>

<h3 id="ssh-key">SSH/SFTP public key</h3>
<p>Installs (replacing any previous one) the public key a tenant's SFTP client
authenticates with. Validated with <code>ssh-keygen</code> before being
accepted; the SFTP container restarts to pick it up. Without a key installed,
SFTP is entirely inaccessible for that tenant -- there's no password fallback.</p>

<h3 id="reset-admin-password">Reset tenant admin password</h3>
<p>Resets only the original <code>admin</code> login's password on a tenant's
own admin.&lt;domain&gt; panel. If the tenant has added other team logins (see
their own Team page), those are untouched and not shown here. Unlike the
incident-response resets below, nothing is generated here -- type the new
password yourself and pass it to the tenant directly; it's not saved or shown
anywhere else in this UI. Same minimum length as an operator's own account
password. Takes effect immediately, no restart.</p>

<h3 id="tenant-webauthn">Tenant WebAuthn keys</h3>
<p>Shows how many WebAuthn security keys are registered across <em>every</em>
login on a tenant's panel (not just <code>admin</code>). Resetting the admin
password above does not help someone locked out by a lost security key --
WebAuthn has no in-panel fallback once any key exists for that login. Clearing
here wipes every registered key for every login on that tenant's panel at once,
dropping all of them back to password-only immediately.</p>

<h3 id="incident-response">Incident response</h3>
<p>Four coarse, single-click resets for a suspected compromise -- not routine
lockout recovery (use "Reset tenant admin password" above for that, which
leaves everything else alone). Each one rotates <strong>all</strong> of its
category at once, since an operator has no way to tell which specific
credential is the compromised one, and an attacker with panel access could have
planted a backdoor login of their own:</p>
<ul>
  <li><strong>Admin password nuke</strong> -- wipes every admin-panel login down
  to one fresh <code>admin</code> account, and rotates the panel's
  session-signing secret so anyone already logged in is kicked out immediately
  too. No downtime.</li>
  <li><strong>Email password nuke</strong> -- regenerates a fresh random
  password for every mailbox on the tenant at once. Existing mail clients need
  reconfiguring. No downtime.</li>
  <li><strong>Database nuke</strong> -- rotates the app DB password with a live
  <code>ALTER USER</code>, then recreates the web and tenant-admin containers so
  both pick up the new value. The only one with real cost: brief downtime on
  the tenant's live website while those containers restart.</li>
  <li><strong>Nuke all passwords</strong> -- all three above in one action, DB
  last since it's the only one with downtime. Use when the compromised
  credential is unknown, or assume all of them might be.</li>
</ul>
<p>New credentials from any of these are generated and shown once, never saved
in this UI.</p>

<h3 id="maintenance">Maintenance mode</h3>
<p>An operator-only hold -- not a setting the tenant can see or toggle, useful
for e.g. a lapsed bill without it looking like a punishment. While on: site
visitors see a plain "temporarily undergoing maintenance" page instead of the
real site, and the tenant can't log into IMAP or send mail. Inbound email keeps
delivering normally throughout -- nothing bounces or is lost. The tenant's own
admin panel and SFTP access stay fully working, so they can see what's
happening and reach their host.</p>

<h3 id="destroy-tenant">Destroy</h3>
<p>Permanently deletes the tenant and every resource described under "Tenants
list &amp; create" above. No confirmation step beyond the browser's own
"are you sure" dialog. The only recovery path afterward is restoring from a
backup (see Backups, below) -- there's no soft-delete or trash.</p>

<h3 id="php-functions">PHP functions</h3>
<p>Per-tenant toggles for a fixed list of process-execution PHP functions
(<code>exec</code>, <code>shell_exec</code>, <code>system</code>,
<code>proc_open</code>, and others) -- all disabled by default, since
re-enabling any of them lets PHP code on that site run arbitrary programs on
the server. Changes reach the web container within a few seconds (PHP-FPM
reloads automatically); requests already in flight aren't interrupted. This is
the exact same knob the tenant's own panel exposes -- either side can flip it,
last write wins.</p>

<h3 id="fallback">404 handling</h3>
<p>Controls whether a request for a path that isn't a real file falls back to
the site's front controller (<code>index.php</code> if present, else
<code>index.html</code>) -- the mechanism that makes pretty permalinks work for
WordPress/Laravel/etc., equivalent to Apache's <code>.htaccess</code>
rewriting. Off means plain 404 responses for anything that doesn't exist as a
literal file. Takes effect immediately, no reload.</p>

<h3 id="basic-auth">Password protection</h3>
<p>HTTP Basic Auth across the entire site, PHP included -- the same job
Apache's <code>AuthUserFile</code> does. One username/password pair; setting a
new password replaces the old one, and there's a one-click disable. Reaches the
web container within a few seconds.</p>

<h3 id="error-pages">Error pages</h3>
<p>Maps an HTTP status code to a page already in the tenant's webroot, one per
line (<code>CODE /path/to/page.html</code>) -- e.g. a custom 404. Paths must
start with <code>/</code> and point at a real file; anything else is rejected
before saving.</p>

<h3 id="redirects">Redirects</h3>
<p>Permanent (301) redirects for exact paths, one per line
(<code>/old-path https://example.com/new-path</code>, or an absolute path on
the same site). Exact-match only -- no wildcards or pattern matching.</p>

<h3 id="noexec-dirs">No-exec directories</h3>
<p>Denies PHP execution under specific webroot subdirectories regardless of
what ends up in them, one per line, no leading/trailing slash (e.g.
<code>wp-content/uploads</code>). Matters because the web process runs as the
same user the SFTP account does -- a dropped executable anywhere writable is a
full compromise, not a contained one. Recommended for any directory the site or
its visitors can write to (upload folders, cache directories).</p>

<h3 id="ip-acl">IP restrictions</h3>
<p>Restricts the whole site to a specific allowlist of IPs/CIDRs, or blocks a
specific denylist -- one mode active at a time (or disabled entirely). Same job
as <code>.htaccess</code>'s <code>Allow</code>/<code>Deny from</code>
directives. Separate from the fail2ban allowlist below: this is about who can
reach the live site at all, not who's exempt from a login-failure ban.</p>

<h3 id="tenant-email">Email (per tenant)</h3>
<p>A full mailbox console, the same capability as the tenant's own panel's
Email page -- not read-only, and not tenant-self-service-only. An operator can
add a mailbox, reset a mailbox's password, delete one, and set per-mailbox
quotas directly from here, without needing a tenant login. Useful for helping
a tenant who's locked themselves out of their own mailbox management. This is
a separate tab from DNS, below, which is read-only.</p>

<h3 id="dns">DNS</h3>
<p>The platform-wide <a href="{{ url_for('dns_view') }}">DNS</a> page lists
suggested records that exist once for the whole platform (e.g. the shared
inbound mail gateway's MX target), plus a link to each tenant's own suggested
records. All of it is advisory -- there's no platform-hosted DNS zone or
provider API integration; a human copies these into whatever actually hosts
each domain's zone. A "Check records" button verifies each suggested record
against live DNS and marks matches.</p>

<h3 id="tenant-backups">Backups (per tenant)</h3>
<p>Every tenant is backed up automatically to the operator's own destination
with no opt-out -- this tab lets an operator adjust that tenant's retention
count and interval (blank means the platform default), trigger an immediate
backup, and restore any existing snapshot back into that tenant in place
(overwriting current webroot/mail/phpconf/database content; WebAuthn keys are
left untouched). Every restore is signature-verified before anything is
touched -- a tampered or corrupted snapshot is refused outright. This operator
destination is separate from and in addition to whatever backup destination
the tenant may have configured for themselves on their own panel. Deliberately
out of reach from here: neither this page nor the platform-wide Backups pages
below can browse or restore from a tenant's <em>own</em> self-configured
destination -- that stays tenant-controlled, reachable only from their own
panel or, for an operator, the CLI (<code>vhsp backup list-remote --source
tenant</code> / <code>vhsp backup restore --source tenant</code>). If a
tenant needs help with their own destination specifically, that's the path.</p>

<h3 id="backups-browse">Backups (browse any domain)</h3>
<p>The platform-wide <a href="{{ url_for('backups_browse') }}">Backups</a> page
lists every domain that has ever been backed up to the operator's shared
destination -- including domains destroyed or never provisioned on this
deployment at all. Restoring from here can recreate a tenant from scratch
(if it doesn't currently exist) or restore into an existing one; "restore as"
lets you recreate under a different domain than the one it was originally
backed up from, useful for standing up a clone or a disaster-recovery copy
without touching the original.</p>

<h3 id="tenant-logs">Logs (per tenant)</h3>
<p>The last 200 lines of each of a tenant's logs: web access, web error,
PHP-FPM error, mail (Postfix + Dovecot), SFTP, and Coraza WAF (fetched live via
the Docker API rather than a file, since the WAF container's audit trail never
gets written to a mounted file). Reload the page to refresh -- nothing here
auto-updates.</p>

<h3 id="operators">Operators</h3>
<p>Operator accounts are flat and equal-privilege -- every operator can do
everything any other operator can, including managing other operators from
this page. There's no role/permission system yet. Adding an operator generates
a password shown once; resetting one's password does the same. Removing the
last remaining operator is blocked outright (the platform would otherwise lock
itself out). Adding, removing, or resetting a password all require the
<em>acting</em> operator's own account to have a second factor (security key
or authenticator app) registered first.</p>

<h3 id="audit-log">Audit log</h3>
<p>A read-only, reverse-chronological view of every privileged action taken on
this platform -- tenant create/destroy, credential resets, operator changes,
login/logout/failed-login events, and more -- each with a timestamp, action,
domain (if applicable), and actor. The actor string reflects how the action
was taken: <code>admin-ui:&lt;username&gt;</code> for this web UI,
<code>cli</code> for the command-line tool, or <code>api:&lt;username&gt;</code>
/ <code>mcp:&lt;username&gt;</code> for the REST API/MCP surfaces (see API
tokens, below). Every entry is chained by hash to the one before it
(<code>vhsp doctor</code>/<code>vhsp audit verify</code> on the host detect
tampering by broken chain), and shipped off-host every minute so the trail
survives even a full compromise of this host.</p>

<h3 id="fail2ban">fail2ban log</h3>
<p>The last 200 lines of <code>/var/log/fail2ban.log</code>, every jail mixed
together in one stream -- host SSH, this admin UI's own login jail, the shared
tenant-admin-login jail every tenant's panel funnels through, and every
tenant's individual SFTP jail. Read-only; reload to refresh.</p>

<h3 id="allowlist">fail2ban allowlist (platform-wide)</h3>
<p>IPs/CIDRs entered here are never banned by any jail on the platform --
SSH, this admin UI's own login, or any tenant's SFTP/admin-panel login.
Checked live on every ban decision, no restart needed. Separate from (and
additive to) each tenant's own login allowlist on their panel, which only
covers failures against that one tenant's own login page. Gated behind a
second factor on the acting operator's account, since misuse here could exempt
an attacker's IP from ever being banned anywhere on the platform.</p>

<h3 id="my-account">My account</h3>
<p>The logged-in operator's own settings, at <a href="{{ url_for('account') }}">My account</a>:</p>
<ul>
  <li><strong>Password</strong> -- change the operator's own login password.</li>
  <li><strong>Security keys (WebAuthn)</strong> -- register/remove hardware or
  platform security keys as a second factor. Only works over the real public
  hostname (WebAuthn ties a key to the exact origin it was registered on).
  With only one key registered, there's no self-service recovery if it's lost
  (unlike a tenant's, which an operator can clear from that tenant's own page)
  -- only direct server access. A second backup key is strongly recommended.</li>
  <li><strong>Authenticator app (TOTP)</strong> -- an alternative second
  factor to a security key (Google Authenticator, Authy, 1Password, anything
  reading a standard <code>otpauth://</code> QR code). Either this or a
  security key satisfies login's second-factor requirement; no need for both.</li>
  <li><strong>API access</strong> -- link to API tokens, shown once a second
  factor is registered (see below).</li>
</ul>
<p>Most destructive or credential-revealing actions elsewhere in this UI
require the acting operator to have <em>some</em> second factor registered
here first -- a password alone isn't enough for those. On a tenant's own
Overview page: setting an SSH key or admin password, clearing WebAuthn keys,
maintenance mode, every incident-response button, and Destroy (that page's
own banner lists these exactly). Platform-wide: adding, removing, or
resetting another operator's password (Operators); the platform allowlist;
minting or revoking an API token; and every backup action, browsing included
(a tenant's own Backups tab, and the platform-wide Backups pages) -- backups
are gated as a whole page, not just the destructive actions on it, since a
snapshot's contents are as sensitive as the credentials in it. Tenant disk
quota, by contrast, only needs a plain login -- it's operator-visible
metadata, not a credential or a destructive action.</p>

<h3 id="api-mcp">API tokens, REST API &amp; MCP</h3>
<p>Both off by default platform-wide, and independently toggleable from
<a href="{{ url_for('api_tokens_view') }}">My account -&gt; API &amp; MCP
access</a> (needs a second factor registered first, same as every other
consequential action here) -- no shell access to the host required for
either. Currently on this deployment: REST API
<strong>{{ 'on' if api_enabled else 'off' }}</strong>, MCP server
<strong>{{ 'on' if mcp_enabled else 'off' }}</strong>.</p>
<p><a href="{{ url_for('api_tokens_view') }}">API tokens</a> mints bearer
tokens -- shown once, never recoverable afterward -- that authenticate every
call to either surface below, regardless of which one is currently on. A
token can do everything the minting operator's own account can, scoped to
the same read/lifecycle/backup operation set: list/get/create/destroy
tenants, usage, backups, audit verify, fail2ban log tail. Deliberately
excluded from both surfaces: the secret-revealing incident-response resets
above (admin/email/database nukes) -- those stay web-UI/CLI-only for now.
<code>GET /tenants/&lt;domain&gt;</code> redacts every credential field by
default, stricter than this web UI's own tenant page (which always shows
them) -- treat a token like a password, not a bookmark: anyone holding it
can act as the operator who minted it. Revoking a token takes effect
immediately, independent of either toggle below.</p>

<h4>Turning the REST API on or off</h4>
<p>Restarts this admin UI to apply it (the Flask Blueprint that serves
<code>/api/v1/*</code> is only registered at process startup) -- the toggle
button itself explains this, and the page needs a manual reload a few
seconds after clicking it. Once on, base URL is
<code>https://{{ rp_id }}/api/v1</code>, every request carrying
<code>Authorization: Bearer &lt;token&gt;</code>:</p>
<pre>curl -H "Authorization: Bearer &lt;token&gt;" https://{{ rp_id }}/api/v1/tenants</pre>
<p>Or drive it interactively from <a href="{{ url_for('api_tokens_view') }}">the
API &amp; MCP access page</a>'s link to Swagger UI docs -- its "Authorize"
button accepts the same token and lets you try any endpoint from the
browser.</p>

<h4>Turning MCP on or off</h4>
<p>A genuinely separate process from the REST API above (not just a
different path on the same one), so its toggle does more than the REST
API's: installs and starts its own <code>vhsp-mcp.service</code> systemd
unit, opens a firewall rule scoped to the internal Traefik network only
(never the public interface), and adds its Traefik routing entry -- turning
it off reverses all three, not just stopping the process. Once on, point an
MCP client (Streamable HTTP transport) at:</p>
<pre>https://{{ rp_id }}/mcp</pre>
<p>authenticated with the same <code>Authorization: Bearer &lt;token&gt;</code>
header as the REST API -- one token, both surfaces, and MCP doesn't need the
REST API also turned on (each toggle is independent). A working client
exposes the same operation set as the REST API as callable tools
(<code>list_tenants</code>, <code>create_tenant</code>,
<code>get_fail2ban_log</code>, and so on) rather than HTTP routes; which
specific config format a given MCP client wants (a JSON block naming the
URL and header, typically) depends on that client, not on this platform.</p>

<h3 id="tenant-api-mcp">Allowing tenant API/MCP access</h3>
<p>Separate from everything above -- this section is about tenants using
API/MCP for <em>their own</em> self-service operations (mailboxes, PHP
function toggles, redirects, backups, and the rest of what their own
panel exposes), not about operator access. Off by default, and gated by
two independent layers of consent: an operator-side allow (this
section), and a tenant-side enable that tenant must set themselves --
allowing here does not turn anything on by itself.</p>
<p>Each tenant's own detail page has an "API &amp; MCP access" card with
Allow/Disallow buttons for REST API and MCP independently. Allowing
takes effect immediately -- there's no restart involved, unlike the
platform-wide toggle above, since a tenant's own routes/tools are always
present in the shared process and check both layers live on every call.
Disallowing here immediately blocks that tenant's calls too, even if
their own enable toggle is still on. <strong>Allowing a tenant here
requires this deployment's own REST API/MCP to also be turned on</strong>
(the section above) -- tenant traffic reaches the same shared
`/api/v1/self/*` routes and MCP tools this platform's operator surface
does, just scoped to a narrower token and operation set, so if this
platform's own REST API or MCP is off, allowing a tenant here has no
effect until it's on.</p>
<p>Tenants mint their own tokens from their own panel's "API &amp; MCP
access" page (owner-only, second factor required, same tier as their
Files/Database pages) -- operators never see or handle a tenant's
token. A tenant token can only ever reach that one tenant's own
`/self/*` operations; it's rejected outright for anything else,
including every operator-only route and every other tenant's data.</p>

<h3 id="security-model">How the pieces fit together</h3>
<p>A few things that show up across multiple pages above, in one place:</p>
<ul>
  <li><strong>Two-factor authentication</strong> is opt-in per operator
  account (no forced enrollment on creation), but every destructive or
  credential-revealing action checks that the <em>acting</em> operator
  specifically has one registered -- not just that 2FA exists somewhere on
  the platform.</li>
  <li><strong>The audit log</strong> (above) is the platform's tamper-evident
  record of who did what; every action from every surface (this UI, the CLI,
  the API, MCP) lands in the same chain.</li>
  <li><strong>fail2ban</strong> (log + allowlist, above) bans by source IP
  after repeated failures -- login pages and SFTP. <strong>Coraza (WAF)</strong>,
  visible per-tenant on the Logs tab, inspects individual request content
  regardless of source IP. The two are complementary, not overlapping.</li>
  <li><strong>Credentials</strong> at rest (tenant DB/mail passwords, operator
  TOTP secrets, backup transport keys) are encrypted with a locally-held
  master key (<code>vhsp secrets</code> on the CLI) -- a leaked database file
  or backup alone doesn't hand over plaintext.</li>
</ul>
</div>
"""


@app.route("/manual")
@require_auth
def manual_view():
    return render(MANUAL_PAGE, api_enabled=current_api_enabled(), mcp_enabled=current_mcp_enabled(), rp_id=webauthn.RP_ID)


def main():
    """Local/dev convenience only (`vhsp-admin` console script) -- real
    deployments run under gunicorn instead (see deploy/vhsp-admin.service),
    since Flask's own dev server says so itself on every startup: single
    request at a time, not hardened for anything actually reachable.
    ADMIN_BIND_HOST/PORT still apply either way -- gunicorn's own --bind
    reads the identical env vars, just via the systemd unit's shell
    wrapper rather than this function."""
    print(f"VHSP admin UI (dev server) on http://{ADMIN_BIND_HOST}:{ADMIN_BIND_PORT}")
    app.run(host=ADMIN_BIND_HOST, port=ADMIN_BIND_PORT)


if __name__ == "__main__":
    main()
