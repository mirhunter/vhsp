# vhsp UX/Accessibility Review (2026-07-25)

Scope: read-only UX/accessibility review of the two hand-rolled Flask admin
UIs -- `vhsp_ctl/web.py` (operator UI, ~2680 lines, 55 routes) and
`images/tenant-admin/app.py` (tenant UI, ~3300 lines, 29 routes) -- plus a
feature-coverage cross-check against every function/command in
`vhsp_ctl/provisioner.py`, `backup.py`, `registry.py`, `toggles.py`,
`dns_records.py`, `fail2ban_allowlist.py`, `auth.py`, and `cli.py` (roughly
150 functions/commands total). This is a UX review, not a security review
(see `SECURITY_REVIEW_2.md` for that; its format is mirrored here). No
infrastructure was touched -- read-only source review plus read-only
Flask-test-client renders against the live vhsp2 deployment
(`astjohn@vhsp2.dvce.us`, both the operator process and the
`vhsp-testing-bigchimp-org-tenant-admin` / `vhsp-smoketest-vhsp2-dvce-us-tenant-admin`
containers), used to confirm several findings against real rendered HTML
rather than template source alone.

Both apps' new "Manual" tabs (`MANUAL_PAGE` + `/manual` in each file, added
in the immediately preceding session) got a full section-by-section
line-by-line cross-check against the routes/decorators they describe --
this is where the two highest-value findings came from.

---

## Summary

| Category | Findings |
|---|---|
| 1. Feature coverage (CLI-only / orphaned) | 2 |
| 2. Usability friction | 4 |
| 3. Visual cleanliness / accessibility | 5 |
| 4. Documentation accuracy (Manual) | 3 |
| **Total** | **14** |

By confidence: 12 are directly confirmed against source and/or live
rendered HTML; 2 are flagged as lower-confidence/more-subjective and
marked as such below.

**Overall verdict:** feature coverage is genuinely strong -- every
operator-facing library function in `provisioner.py`/`toggles.py`/`auth.py`
that isn't a one-time bootstrap or cron-timer entry point has a working UI
route, and every route in both apps is reachable from its nav (no orphans
found, confirmed programmatically). The real problems are concentrated in
two places: the brand-new Manual tabs contain two flat, checkable factual
errors (the kind that actively misleads an operator into wrong expectations
rather than just being incomplete), and neither app has a `<meta
viewport>` tag, which undermines a genuinely competent, consistent CSS
design system the moment either UI is opened on a phone. Underneath that,
destructive-action confirmation is *almost* perfectly consistent across
both apps except for one specific, identical gap in both (mailbox delete),
which is the kind of narrow, easy-to-fix bug that's more concerning for
what it implies about test coverage than for its own blast radius.

---

## Findings

### 1. [HIGH -- documentation] Operator manual claims tenant admin-password resets are system-generated; they are actually operator-typed, with no minimum-length check

**Status: FIXED.** Manual text corrected to describe the real behavior, and
`tenant_set_admin_password` (`web.py`) now enforces the same
`MIN_PASSWORD_LENGTH` the operator's own account password does -- closing the
actual gap the manual's wrong text had been papering over, not just fixing
the words. Deployed and verified live on vhsp2.

`vhsp_ctl/web.py:2399-2404` (`id="reset-admin-password"`):

> "Resets only the original `admin` login's password... **The new password
> is generated and displayed exactly once** -- pass it to the tenant
> directly, it's not saved anywhere else in this UI."

This is false. The actual card two clicks away, on the tenant's own
Overview page (`web.py:1227-1236`), is a plain password **input** the
operator types into themselves:

```html
<input type="password" name="new_password" placeholder="new password" required autocomplete="new-password" ...>
<button type="submit">Set password</button>
```

...and the handler (`web.py:1369-1382`, `tenant_set_admin_password`) uses
`request.form.get("new_password", "")` verbatim -- nothing is generated
server-side, and there's nothing to "display" since the operator already
typed the value. The Overview card's own text even gets this right ("pick
one and pass it to the tenant directly," `web.py:1229`) -- the Manual's
copy appears to have been adapted from the neighboring "Admin password
nuke" incident-response action (`provisioner.reset_tenant_panel_access`),
which genuinely *does* generate and show a password once, and the two got
conflated.

**Why it matters:** an operator reading the manual before using this
feature for the first time will look for a generated password to copy and
won't find one, or worse, will assume the system enforces some minimum
password strength here the way it does on the operator's own account
(`MIN_PASSWORD_LENGTH = 12`, `web.py:63`, checked at `web.py:651-652` for
`/account` but never referenced in `tenant_set_admin_password` or its
route handler) -- there is currently no length/strength check at all on
this field, so a 1-character password is accepted silently.

**Fix:** rewrite the manual section to match reality ("type a new password
for the tenant and pass it to them directly -- nothing is generated or
shown by the system here"), and separately consider adding the same
`MIN_PASSWORD_LENGTH` check this route already enforces for the operator's
own account.

### 2. [HIGH -- documentation] Operator manual claims mailbox management "isn't duplicated into the operator UI" -- it is, and it's linked from every tenant's nav

**Status: FIXED.** Manual section rewritten to accurately describe the
operator Email tab as a full mailbox console, and split from the DNS
description it had been incorrectly merged into. Verified live on vhsp2.

`vhsp_ctl/web.py:2505-2510` (`id="tenant-email"`):

> "The per-tenant DNS and email tab shows the same suggested DNS records...
> read-only here, nothing on this page changes DNS. **Mailbox management
> itself (add/reset/delete, quotas) is tenant self-service only, on their
> own panel's Email page -- not duplicated into the operator UI.**"

This is false on two counts. First, "DNS and email" isn't one tab --
`TENANT_NAV` (`web.py:1073-1074`) has two separate entries, "Email" and
"DNS." Second, and more importantly, the operator-side "Email" tab
(`/tenants/<domain>/email`, `web.py:1839-1931`) is a full mailbox
add/reset/delete/quota console -- the exact functionality the manual says
doesn't exist on the operator side. Verified live against vhsp2: the real
rendered `/manual` page still contains this exact claim, and
`/tenants/testing.bigchimp.org/email` renders a working add/reset/delete
table with three real mailboxes.

**Why it matters:** this is the kind of error that actively misleads --
an operator trying to help a tenant with a stuck mailbox, who trusts the
manual, will go looking for a way to reach into the tenant's own panel
(which they can't do without knowing a tenant login) instead of just using
the tab they're already on.

**Fix:** rewrite the "Email (per tenant)" section to describe what it
actually does: full mailbox management (add/reset/delete/quota, same
capability as the tenant's own panel) plus the read-only suggested-DNS
view, and split it back into an accurate description of the two separate
tabs.

### 3. [HIGH -- visual/mobile] No `<meta name="viewport">` anywhere in either app

**Status: FIXED.** Added to both `LAYOUT` and the pre-session
`AUTH_PAGE`-equivalent shell in both files (4 spots total). Verified live --
`/login` on both apps now serves the tag.

Confirmed by `grep -rn viewport` across both files: zero matches. Also
confirmed live -- fetched the real rendered `/email` page from both the
operator process and the `vhsp-testing-bigchimp-org-tenant-admin`
container on vhsp2; neither response contains a viewport meta tag.

**Why it matters:** without this tag, mobile browsers render the page at
their default desktop-assumption width (~980px) and scale the whole thing
down to fit, regardless of how well the underlying CSS actually adapts.
Both apps' CSS is otherwise reasonably disciplined (dark-mode-aware via
`prefers-color-scheme`, flexible `.card`/`.actions` layouts, sensible
`max-width` on the content shell) -- none of that matters on a phone
without this tag, because the browser never gives the CSS a mobile-sized
viewport to respond to in the first place. This affects every single page
of both apps, on the first visit from a phone, 100% of the time -- an
operator SSHing in isn't the only audience; a tenant checking whether their
mailbox update went through from their phone is exactly the kind of user
this breaks. It's also the cheapest fix in this whole report: one line, no
behavior change, no risk.

**Fix:** add `<meta name="viewport" content="width=device-width, initial-scale=1">`
to both `LAYOUT` and `AUTH_PAGE`-equivalent shells in both files.

### 4. [HIGH -- usability] Mailbox "Delete" is the one destructive button in either app with no confirmation dialog

**Status: FIXED.** Added the same `confirm()` pattern used everywhere else
in both apps, with a specific message naming the mailbox and domain being
deleted. Verified live -- both apps' rendered `/email` pages now include the
`onsubmit` guard.

`vhsp_ctl/web.py:1905-1911` (operator side, `/tenants/<domain>/email`) and
`images/tenant-admin/app.py:1815-1821` (tenant side, `/email`):

```html
<form class="inline" method="post">
  <input type="hidden" name="action" value="delete">
  <input type="hidden" name="user" value="{{ user }}">
  <button class="danger" type="submit">Delete</button>
</form>
```

No `onsubmit="return confirm(...)"`. This was checked systematically: every
other `class="danger"` button in both files -- security-key remove, TOTP
remove, operator remove, team-member remove, tenant destroy, all four
incident-response nuke buttons, and file delete in the tenant's own Files
manager -- has a confirm dialog with specific, well-written warning text
(often better than a generic "are you sure?", e.g. the file-delete one
warns specifically about recursive directory deletion). Mailbox delete is
the sole exception, in **both** apps, at the same conceptual spot.
Verified live: fetched `/tenants/testing.bigchimp.org/email` (operator)
and the tenant-admin container's own `/email` (has 3 real mailboxes, so a
real Delete button renders) and confirmed zero `onsubmit` on that specific
form in the actual served HTML.

**Why it matters:** a misclick (fat-finger on a touch device, a stray
click while scrolling a long mailbox list) permanently deletes a mailbox
with no undo -- worse than most of the *other* danger buttons here, since
those at least ask "are you sure" first. `postmaster@` is protected from
deletion server-side, but any other mailbox isn't.

**Fix:** add the same confirm pattern used everywhere else, e.g.
`onsubmit="return confirm('Delete {{ user }}@{{ domain }}? This cannot be undone.');"`,
to both forms.

### 5. [MEDIUM -- documentation] Both Manuals' "which pages need 2FA" summaries are incomplete, and contradict their own apps' route decorators

**Status: FIXED.** Both summaries rewritten from a fresh read of every
`@require_2fa` decorator in each file (checked programmatically, not by
re-reading the old prose). Operator side now lists all 5 previously-omitted
items plus the platform-wide ones. Tenant side now lists Email and Backups
(previously omitted), clarifies Team needs no 2FA at all, and the
per-section "needs 2FA to change" phrasing on redirects/no-exec-dirs/ip-acl/
allowlist/PHP-functions/Email/Backups was corrected to make clear the whole
page (GET included) is gated, not just the save action.

**Operator side** (`web.py:2604-2607`, under "My account"): lists
"incident response, operator management, the platform allowlist, API
tokens, tenant backups" as needing the acting operator's account to have
2FA enrolled. This omits five things that actually carry `@require_2fa`
in their route decorators: Destroy tenant (`web.py:1498`), Maintenance
mode (`web.py:1485`), the single-login "Reset tenant admin password"
(`web.py:1370`), Tenant WebAuthn key clearing (`web.py:1386`), and
SSH/SFTP key install (`web.py:1355`). All five are already correctly and
*completely* listed elsewhere in the same app -- the Tenant Overview page's
own warning banner (`web.py:1149-1157`) says exactly: "setting an SSH key
or admin password, clearing WebAuthn keys, maintenance mode, every
incident-response button, and Destroy." The Manual, written later, just
doesn't match a list the app already gets right two clicks away.

**Tenant side** (`images/tenant-admin/app.py:3256-3258`, under "My
account"): lists "PHP functions, redirects, no-exec directories, IP
restrictions, the login allowlist, Files, Database, and team-owner
actions" as needing 2FA. Omits Email (`/email` has `@require_2fa`,
`app.py:2694`) and Backups (`/backups` has `@require_2fa` on the *entire*
route -- including just viewing the page or clicking "Back up now,"
`app.py:3014`). The Backups section's own text (`app.py:3225-3242`)
explicitly says "any team member can trigger an immediate backup," which
is only true if that member *also* has 2FA enrolled -- something the
manual never mentions, so a member without 2FA who follows that sentence
hits an unexplained 403.

Secondary/smaller: the tenant manual's per-page phrasing for
redirects/no-exec-dirs/ip-acl/the login allowlist ("Needs a second factor
registered **to change**," e.g. `app.py:3171`, `3179`, `3187`, `3197`)
implies read-only viewing is available without 2FA. It isn't --
`require_2fa` (`app.py:946-953`) wraps the whole view function, GET
included, so a non-2FA member can't even load these pages to look, not
just edit them.

**Why it matters:** less severe than #1/#2 since it's omission rather than
active misdirection, but it means an operator or tenant member reading the
manual to predict what will 403 on them gets an incomplete answer, and the
two apps' own in-UI signals (the Overview warning banner, the subnav's
inline "(2FA required)" tags) are more trustworthy than the manual meant
to summarize them.

**Fix:** regenerate both "which pages need 2FA" lists directly from the
route decorators (or better, derive the manual's claims from a single
source of truth -- e.g. have `require_2fa` register the endpoint name in a
list the manual template iterates over, so this can't drift again).

### 6. [MEDIUM -- accessibility] "Click to copy" DNS record cells are mouse-only; zero keyboard accessibility anywhere in either app

**Status: FIXED.** Added `tabindex="0" role="button"` plus an `onkeydown`
handler firing the same copy function on Enter/Space, to both `<code>`
cells in both apps, plus a `:focus-visible` style so the now-focusable
element has a visible focus ring. Verified live via rendered HTML.

`vhsp_ctl/web.py:1947-1948` and `2013` region, `images/tenant-admin/app.py:1862-1863`:

```html
<code class="copyable" title="Click to copy" onclick="vhspCopyDns(this)">{{ r.name }}</code>
```

`grep -c "tabindex\|onkeydown\|role=\"button\""` across both entire files
returns zero. The DNS-record copy-to-clipboard control is a `<code>`
element with only a mouse `onclick` handler -- no `tabindex` to make it
focusable, no `role="button"` to announce it as interactive, no
`onkeydown` to fire on Enter/Space. A keyboard-only user tabbing through
the page skips right over it; there is no way to trigger the copy action
without a mouse.

**Why it matters:** this is a real, not theoretical, feature gap for
keyboard-only users (motor-impairment assistive tech, or just someone who
prefers not to reach for a mouse) -- not a broken page, since the DNS
values are still visible/selectable text, but the specific
click-to-copy convenience this UI was clearly designed to offer (there's a
whole `vhspCopyDns` JS helper with a "Copied!" visual confirmation) is
entirely unavailable to that population.

**Fix:** either make these real `<button>` elements styled to look like
the current `<code>` tags, or add `tabindex="0" role="button"` plus an
`onkeydown` handler that fires the same copy function on Enter/Space.

### 7. [MEDIUM -- usability/accessibility] Inconsistent form labeling: "quick add" rows lack accessible labels that settings forms consistently have

**Status: FIXED.** Added a new `.sr-only` utility class (visually hidden,
still announced by screen readers) to both apps' CSS, and a matching
`<label>` to every field called out: create tenant, add operator, add
mailbox (both apps), and add team member (plus its previously-unlabeled
role `<select>`, found while fixing this). Verified live.

Settings-style forms are properly labeled throughout both apps: login
(`web.py:516-517`), account password change (`web.py:1230-1234` region /
`app.py:2183-2185`), backup destination settings (`app.py:2084-2087`).
But several "add a row" forms rely on placeholder text alone, with no
`<label>` or `aria-label`:

- Create tenant: `<input name="domain" placeholder="example.com" required ...>` (`web.py:1118`)
- Add operator: `<input type="text" name="username" placeholder="username" required ...>` (`web.py:999`)
- Add mailbox (both apps): user/password fields with `placeholder="sales"` / `placeholder="password"` only (`web.py:1924,1926`; `app.py:1835,1837`)
- Add team member: `<input type="text" name="target" placeholder="username" required ...>` (`app.py:2367`)

**Why it matters:** a placeholder is not a substitute for a programmatic
label -- it disappears the moment the field has focus/content, and screen
readers announce these fields as unnamed "edit text" controls. This isn't
a hypothetical edge case: these are exactly the highest-stakes text
inputs in either app (the ones that create a tenant, an operator account,
or a mailbox), and they're the ones most likely to be filled in from
memory/a support ticket rather than by someone who has the whole page
layout memorized already.

**Fix:** add `<label>` (visually hidden via a `.sr-only`-style class if the
compact `.actions` row layout is worth preserving) to each of these, same
pattern already used on every settings form in both apps.

### 8. [MEDIUM, lower confidence -- feature coverage] Operator UI can't browse or restore from a tenant's *own* configured backup destination -- CLI-only

**Status: FIXED (documented, not built).** Took the finding's own suggested
fallback rather than the UI-toggle option: this report's own framing
correctly flagged that adding operator reach into a tenant's own destination
is a trust-boundary product decision, not a pure bug fix, so it shouldn't be
made silently as part of a UX-polish pass. Added an explicit paragraph to
the manual's "Backups (per tenant)" section stating the gap plainly and
pointing at the CLI (`vhsp backup list-remote`/`restore --source tenant`)
as the current path, rather than leaving it undocumented. Whether to build a
UI path for this is a separate decision for the user to make.

`backup.list_remote_domains`/`list_remote_snapshots`/`restore_backup` all
take a `source: "operator" | "tenant"` parameter, and the CLI exposes both
(`vhsp backup list-remote --source tenant`, `vhsp backup restore --source
tenant`). But every web UI call site -- `tenant_backups`, `backups_browse`,
`backups_domain`, `backups_restore` (`web.py:2012-2282`) -- hardcodes
`source="operator"` (or omits the parameter, defaulting to it). There is
no way, from either admin UI, for an operator to see or restore from
snapshots sitting at a tenant's own self-configured SFTP destination; that
requires dropping to the CLI on the host.

**Why it matters:** a plausible real support scenario -- a tenant asks the
operator for help because their *own* backup destination looks broken, or
they want to restore from it but locked themselves out of their own
panel -- currently has no UI path, only a CLI one, on a platform whose
explicit design goal (per the manual, per `architecture.md`) is that
routine operator actions live in the UI. This is flagged as lower
confidence than the others above because it may be a deliberate
trust-boundary choice (the tenant's own destination/keys are meant to stay
tenant-controlled, and an operator reaching into it without being asked
could itself be a UX/trust problem) -- but if so, that's worth stating
explicitly rather than leaving as a silent gap.

**Fix:** either add a `source` toggle to the operator's tenant-backups
page (gated the same way the rest of that page already is, behind
`@require_2fa`), or, if the omission is deliberate, say so in the manual's
"Backups (per tenant)" section instead of leaving it unaddressed.

### 9. [LOW -- feature coverage] `backup.preview_snapshot()` is dead code -- unreachable from any CLI command or UI route

**Status: FIXED (removed).** Deleted the unused function per this
codebase's own stated convention (no backwards-compat shims for confirmed-
unused code); `_fetch_and_verify`, which it shared with `restore_backup`,
is untouched and still has a real caller.

`vhsp_ctl/backup.py:892` defines `preview_snapshot(domain, snapshot_name,
source="operator", tenant=None)`, clearly intended to let a caller inspect
a snapshot's manifest before committing to a restore. `grep -rn
preview_snapshot` across `cli.py` and both UI files turns up nothing
besides the function's own definition and a docstring cross-reference in
`_fetch_and_verify`. Every restore path (CLI `backup restore`, both web UI
restore buttons) goes straight from a snapshot's filename/timestamp to a
full overwrite, with no intermediate "here's what's actually in this
snapshot" step.

**Why it matters:** low severity because the existing restore
confirmations already show enough context to make an informed choice
(timestamp, size, encrypted-or-not, and for the global Backups page, an
explicit warning about what gets overwritten) -- this is a missing
nice-to-have, not a broken workflow. Worth noting mainly because it's a
half-built feature: the backend function exists and is documented, but
nothing calls it.

**Fix:** either wire it into the restore confirmation flow (e.g. an
expandable "preview manifest" link before the Restore button) or remove
the unused function if it's not planned.

### 10. [LOW -- visual] Table overflow handling is inconsistent -- only 2 of the many `<card><table>` combinations opt into `overflow-x:auto`

**Status: FIXED.** Moved `overflow-x: auto` onto the global `.card table`
rule in both apps, so every table gets it by default rather than opting in
per-table. The two existing per-table inline `overflow-x:auto` wrappers
(DNS table, SQL console results) were left in place -- now redundant but
harmless, not worth the extra diff to remove.

`vhsp_ctl/web.py:296-309` shows `.card`/`table` get no `overflow-x`
treatment by default; only the DNS records table (`web.py:1940`) and the
SQL console results table (`images/tenant-admin/app.py:2032`) add an
inline `style="overflow-x:auto"`. Every other table -- tenants list,
operators list, mailboxes, audit log, snapshot lists, the fail2ban
allowlist -- has no such wrapper, and `.shell` itself
(`web.py:266`) sets no `overflow-x` constraint either, so a table wider
than the viewport would drag the whole page into horizontal scroll rather
than scrolling just the table.

**Why it matters:** secondary to #3 (the viewport-meta gap is the bigger
mobile problem) -- most of these tables are narrow enough (3-6 short
columns) that this rarely bites in practice today. Flagged as a
consistency gap: two tables got the fix, the rest didn't, for no apparent
reason related to their actual width.

**Fix:** move `overflow-x: auto` onto `.card table`'s wrapping rule
globally rather than opting in per-table.

### 11. [LOW -- accessibility] WebAuthn "2FA enabled" badge relies on a title-only tooltip with an `aria-hidden` SVG

**Status: FIXED.** Added `aria-label="Two-factor authentication enabled"`
to the wrapping span in both apps, alongside the existing `title`.

`vhsp_ctl/web.py:404`, `images/tenant-admin/app.py:1525` (identical
pattern in both):

```html
<span title="Two-factor authentication enabled" ...><svg ... aria-hidden="true">...</svg></span>
```

The SVG is correctly marked decorative (`aria-hidden="true"`), but the
wrapping `<span>` isn't interactive/focusable and carries no `aria-label`
-- only a `title` attribute, which is inconsistently exposed by screen
readers and never reachable via keyboard-only navigation (no hover, no
focus stop). A sighted mouse user gets a tooltip; everyone else gets
nothing indicating 2FA is on for that account.

**Why it matters:** low severity -- this is supplementary status
information next to the username, not a control that blocks any action --
but it's exactly the kind of icon-only indicator the task called out to
check, and it fails the same way in both apps identically.

**Fix:** add `aria-label="Two-factor authentication enabled"` to the
wrapping span (in addition to, not instead of, the existing `title`).

### 12. [LOW -- visual, minor] "Maintenance mode" badge styling is duplicated inline instead of a reusable class

**Status: FIXED.** Added `.badge-warn` next to `.badge-ok`; both call sites
now use `class="badge badge-warn"` with only their layout-specific inline
styles (`vertical-align`/`margin-left`) left inline.

`vhsp_ctl/web.py:1064` and `1326` both repeat the identical 3-property
inline style (`background:var(--warn-bg);color:var(--warn-text);border:1px
solid var(--warn-border)`) for a warning-colored badge, rather than adding
a `.badge-warn` class alongside the existing `.badge-ok`
(`web.py:319-323`). Purely a maintenance/consistency nit -- no rendering
bug, both instances look identical and correct.

**Fix:** add `.badge-warn { background: var(--warn-bg); color:
var(--warn-text); border: 1px solid var(--warn-border); }` next to
`.badge-ok` and use it at both call sites.

### 13. [LOW -- usability, minor] Tenant quota-limit action isn't 2FA-gated while the similarly low-risk maintenance-mode toggle is

**Status: NOT CHANGED -- deliberately.** Checked further before acting on
this one: `/tenants/<domain>/quota` isn't the only same-tier setting left
ungated -- `tenant_auth` (password-protection on/off), `tenant_fallback`
(404 handling), and `tenant_error_pages` are equally ungated, while
`tenant_php`/`tenant_redirects`/`tenant_noexec_dirs`/`tenant_ip_acl` are
gated. Adding `@require_2fa` to just the one route this finding happened to
compare against maintenance mode would trade one inconsistency for a
narrower, equally arbitrary one, without a real security gap being closed
(quota is operator-visible metadata, not a credential). Fixing this
properly means auditing all ~8 tenant-setting routes' 2FA gating in one
pass and either justifying or correcting each -- a real but separate task
from this UX-polish pass, not a one-line change. Flagging for the user
rather than silently picking a route boundary on their behalf.

`/tenants/<domain>/quota` (`web.py:1457`) has only `@require_auth`, while
`/tenants/<domain>/maintenance` (`web.py:1484`) right next to it on the
same Overview page has `@require_2fa`. Neither is credential-revealing or
destructive in the way the incident-response buttons are, so this is a
minor inconsistency in where the line was drawn, not a real exposure --
included for completeness since the task asked specifically about
cross-page consistency of similar actions.

### 14. [LOW, lower confidence -- usability] Cosmetically different treatment of "generated password, shown once" between the two apps

**Status: FIXED.** Operator-side flash message now wraps username and
password in `<code>`, matching the tenant-side pattern. Required switching
that one `flash()` call to a `Markup(...)` value with both interpolated
values passed through `markupsafe.escape()` by hand first (LAYOUT's flash
loop relies on Jinja's default autoescaping for every other message; opting
this one out needed the same protection reimplemented explicitly, since
`username` is operator-chosen input, not generated).

Operator "Add operator" (`web.py:1020`) delivers the new password through
a plain-text `flash()` banner (`flash(f"Operator {username!r} created.
Password (shown once): {password}", "ok")`), rendered by the shared
`{{ message }}` loop in `LAYOUT` (`web.py:411-413`) with no monospace
formatting. Tenant "Add a team member" (`images/tenant-admin/app.py:2306`)
renders the password inline as `<div class="flash">Password for
<code>{{ generated_username }}</code> (shown once): <code>{{
generated_password }}</code></div>` -- styled in `<code>`, easier to
read/select precisely. Both are otherwise functionally equivalent (shown
once, not persisted, clear "shown once" language). Flagged as lower
confidence/severity since it's a cosmetic difference between two
otherwise-consistent flows, not a functional gap.

**Fix:** wrap the password in `<code>` in the operator-side flash message
too, for easier copy-selection.

---

## What held up well

- **No orphaned routes.** Checked programmatically (every `@app.route`
  endpoint cross-referenced against every `url_for(...)` call, plus manual
  review of `TENANT_NAV` and the tenant-admin subnav tuple list) -- every
  route in both apps is reachable through normal navigation. The
  login/WebAuthn ceremony endpoints that don't show up in that check are
  correctly invoked via `fetch()` from inline `<script>` blocks, not
  orphaned.
- **Feature coverage from the library layer is comprehensive.** Every
  function in `provisioner.py`, `toggles.py`, and `auth.py` that isn't a
  one-time bootstrap (`vhsp admin init`, `vhsp secrets init`) or a
  systemd-timer entry point (`backup run-all`, `backup process-requests`,
  `backup ship-audit-log`) has a working UI route. `vhsp doctor` and
  `vhsp secrets rotate` are correctly left CLI-only per the task's own
  judgment call on bootstrap/maintenance commands.
- **Destructive-action confirmation is consistent except for finding #4.**
  Checked every `class="danger"` button in both files against its
  `onsubmit`; the mailbox-delete gap is a genuine, narrow outlier, not
  part of a wider pattern.
- **Manual TOC anchors and `url_for()` references all resolve correctly**
  (checked programmatically) -- the errors found are in prose content, not
  in the page's own internal structure or link targets.
- **Dark-mode CSS is genuinely handled** via `prefers-color-scheme` in
  both files, consistently.

---

## Closing note

The two Manual-accuracy findings (#1, #2) are the standout results here --
both are flat, checkable factual reversals rather than vague staleness,
and both are exactly the kind of error a first read-through by someone who
already knows the codebase would gloss over (the prose reads fluently and
matches the *shape* of the neighboring accurate sections). The missing
viewport tag (#3) is the cheapest, highest-leverage fix in the whole
report -- one line, applies platform-wide, no functional risk. The
mailbox-delete confirm gap (#4) is worth fixing not just for its own sake
but as a prompt to add a lint-style check (grep for `class="danger"`
without a matching `onsubmit`) given how easy the pattern was to miss by
eye in a ~3000-line template string. None of this should block adoption;
all fourteen are polish/accuracy issues on top of an already-comprehensive
and mostly-well-executed feature set, not gaps in what the platform can
actually do.
