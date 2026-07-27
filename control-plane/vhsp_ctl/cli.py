import os
import re
import secrets
import sys
from pathlib import Path

import click
from cryptography.fernet import Fernet

from vhsp_ctl import __version__, audit, auth, backup, config, dns_records, platform_settings, provisioner, registry, secretbox, totp, update_check, webauthn


@click.group()
@click.version_option(__version__, "-V", "--version", prog_name="vhsp")
def cli():
    """VHSP control plane -- tenant provisioning."""


@cli.group()
def tenant():
    """Manage tenant containers."""


@tenant.command("create")
@click.argument("domain")
def tenant_create(domain: str):
    """Provision a new tenant for DOMAIN."""
    try:
        t = provisioner.create_tenant(domain)
    except provisioner.ProvisioningError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"created tenant {t.slug!r}")
    click.echo(f"  domain:          {t.domain}")
    click.echo(f"  web container:   {t.web_container}")
    click.echo(f"  db container:    {t.db_container}")
    click.echo(f"  db network:      {t.db_network} (internal, web-only)")
    click.echo(f"  webroot volume:  {t.webroot_volume} ({t.webroot_host_path})")
    click.echo(f"  db volume:       {t.db_volume} ({t.db_host_path})")
    click.echo(f"  db name/user:    {t.db_name} / {t.db_user}")
    click.echo(f"  db password:     {t.db_password}")
    click.echo(f"  db root password:{t.db_root_password}")
    click.echo(f"  sftp container:  {t.sftp_container}")
    click.echo(f"  sftp user:       {t.sftp_user}")
    click.echo("  sftp auth:       key-only, password login disabled -- no access until a key is set")
    click.echo(f"  sftp connect:    sftp -P {t.ssh_port} {t.sftp_user}@<this-host>  (uploads land in ~/www, served live)")
    click.echo(f"                   vhsp tenant set-ssh-key {t.domain} <path-to-key.pub>")
    click.echo(f"  mail container:  {t.mail_container}")
    click.echo(f"  mail hostname:   {t.mail_hostname}  (IMAPS 993 / SMTPS 465, SNI-routed via Traefik)")
    click.echo(f"  mailbox:         {t.mail_user}@{t.domain}")
    click.echo(f"  mail password:   {t.mail_password}")
    if config.TENANT_ADMIN_MGMTWEB_EXISTS:
        click.echo(f"  tenant admin:    https://{t.admin_hostname}/  (PHP toggle + web/mail/sftp logs; also reachable mgmt-network-only at http://{t.admin_hostname}:8090/)")
    else:
        click.echo(f"  tenant admin:    https://{t.admin_hostname}/  (PHP toggle + web/mail/sftp logs)")
    click.echo(f"  tenant admin login: admin / {t.tenant_admin_password}")
    click.echo("  (credentials are also retrievable later via `vhsp tenant show`)")


@tenant.command("show")
@click.argument("domain")
def tenant_show(domain: str):
    """Show full detail, including DB credentials, for DOMAIN."""
    t = registry.get_tenant(domain)
    if not t:
        click.echo(f"error: no active tenant for domain {domain!r}", err=True)
        sys.exit(1)
    for field in (
        "slug", "domain", "status", "created_at", "ssh_port",
        "web_container", "db_container", "sftp_container", "mail_container",
        "tenant_admin_container", "admin_hostname",
        "db_network", "webroot_volume", "webroot_host_path", "db_volume",
        "db_host_path", "db_name", "db_user", "db_password",
        "db_root_password", "sftp_user",
        "ssh_key_fingerprint", "mail_hostname", "mail_user", "mail_password",
        "logs_volume", "logs_host_path", "tenant_admin_password",
        "billing_account_id",
    ):
        click.echo(f"  {field:20} {getattr(t, field)}")
    if not t.ssh_key_fingerprint:
        click.echo("  (sftp is key-only, no password fallback -- no SSH key set yet, SFTP is inaccessible)")


@tenant.command("set-ssh-key")
@click.argument("domain")
@click.argument("public_key_file", type=click.File("r"))
def tenant_set_ssh_key(domain: str, public_key_file):
    """Install an SSH public key for DOMAIN's SFTP access (use '-' for stdin)."""
    try:
        fingerprint = provisioner.set_ssh_public_key(domain, public_key_file.read())
    except provisioner.ProvisioningError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"key installed for {domain}")
    click.echo(f"  fingerprint: {fingerprint}")


@tenant.command("set-billing-account-id")
@click.argument("domain")
@click.argument("billing_account_id")
def tenant_set_billing_account_id(domain: str, billing_account_id: str):
    """Set (or clear, with '') DOMAIN's billing account ID -- ties this
    tenant to an account in external billing software. Operator-set only;
    never shown or editable on the tenant's own admin page."""
    provisioner.set_tenant_billing_account_id(domain, billing_account_id)
    click.echo(f"billing account id for {domain} set to {billing_account_id!r}" if billing_account_id
               else f"billing account id for {domain} cleared")


@tenant.command("reissue-cert")
@click.argument("domain")
def tenant_reissue_cert(domain: str):
    """Ask Let's Encrypt again for DOMAIN's certificates.

    For a tenant created before its DNS pointed here: that first
    certificate order failed and nothing retries it. Recreates the
    containers carrying the tenant's HTTP routers, which is what makes
    Traefik request again. Briefly interrupts the tenant's site.
    """
    try:
        result = provisioner.reissue_tenant_certificates(domain, actor="cli")
    except provisioner.CertReissueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"reissue requested for: {', '.join(result['hostnames'])}")
    click.echo("Traefik orders asynchronously -- check in ~30s with `vhsp tenant show` or the DNS page.")


@tenant.command("reconcile-certs")
def tenant_reconcile_certs():
    """Issue real certificates for tenants whose DNS has caught up.

    Run on a timer by vhsp-cert-reconcile.timer. A tenant created before
    its A records pointed here comes up on Traefik's self-signed cert and
    orders nothing; this notices once DNS resolves and requests for real.
    No-op for tenants that already hold a certificate.
    """
    flipped = provisioner.reconcile_tenant_certificates()
    if not flipped:
        click.echo("nothing to do")
        return
    for result in flipped:
        click.echo(f"requested certificates for {result['domain']}: {', '.join(result['hostnames'])}")


@tenant.command("destroy")
@click.argument("domain")
def tenant_destroy(domain: str):
    """Tear down the tenant for DOMAIN and free its resources."""
    try:
        provisioner.destroy_tenant(domain)
    except provisioner.ProvisioningError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"destroyed tenant for {domain}")


@tenant.command("list")
@click.option("--all", "include_destroyed", is_flag=True, help="Include destroyed tenants.")
def tenant_list(include_destroyed: bool):
    """List tenants."""
    tenants = registry.list_tenants(include_destroyed=include_destroyed)
    if not tenants:
        click.echo("no tenants")
        return
    for t in tenants:
        click.echo(f"{t.domain:30} slug={t.slug:20} ssh_port={t.ssh_port} status={t.status}")


@cli.group()
def admin():
    """Manage the admin web UI's operators."""


@admin.command("init")
def admin_init():
    """Bootstrap the first operator (username "admin") if none exist yet."""
    if auth.list_operators():
        click.echo("operators already exist -- use `vhsp admin add-operator <username>` to add "
                    "another, or `vhsp admin reset-password <username>` to reset one", err=True)
        sys.exit(1)
    password = auth.create_operator("admin")
    click.echo("admin username: admin")
    click.echo(f"admin password: {password}")
    click.echo("(shown once -- single-use; you'll be asked to choose your own at first login)")


@admin.command("add-operator")
@click.argument("username")
def admin_add_operator(username: str):
    """Add another operator (generates a password, shown once)."""
    try:
        password = auth.create_operator(username)
    except auth.AuthError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"operator username: {username}")
    click.echo(f"operator password: {password}")
    click.echo("(shown once -- single-use; they'll be asked to choose their own at first login)")


@admin.command("list-operators")
def admin_list_operators():
    """List every operator and how many security keys they've registered."""
    for o in auth.list_operators():
        key_count = len(webauthn.list_credentials(o["username"]))
        click.echo(f"  {o['username']:20} created={o['created_at']} keys={key_count}")


@admin.command("remove-operator")
@click.argument("username")
def admin_remove_operator(username: str):
    """Remove an operator (refuses if it's the last remaining one)."""
    try:
        auth.remove_operator(username)
    except auth.AuthError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"removed operator {username!r}")


@admin.command("reset-password")
@click.argument("username")
def admin_reset_password(username: str):
    """Regenerate one operator's password."""
    if not auth.operator_exists(username):
        click.echo(f"error: no such operator {username!r}", err=True)
        sys.exit(1)
    password = secrets.token_urlsafe(18)
    # Single-use: this password reaches the operator via a terminal and
    # whatever channel it gets relayed over, so it's held by more than the
    # person who will log in with it until they replace it.
    auth.set_password(username, password, must_change=True)
    click.echo(f"operator username: {username}")
    click.echo(f"operator password: {password}")
    click.echo("(shown once -- single-use; they'll be asked to choose their own at next login)")


@click.group()
def backup_group():
    """Backup / restore."""


cli.add_command(backup_group, name="backup")


@backup_group.command("init")
@click.option("--force", is_flag=True, help="Regenerate keys even if some already exist (invalidates old backups).")
def backup_init(force: bool):
    """Generate the operator's transport/signing/encryption keypairs."""
    try:
        keys = backup.init_operator_keys(force=force)
    except backup.BackupError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo("operator backup keys generated -- COPY THESE NOW, they are never shown again:")
    click.echo()
    click.echo(f"  ssh (transport) public key:  {keys['ssh_public_key']}")
    click.echo(f"  ssh (transport) private key:\n{keys['ssh_private_key']}")
    click.echo(f"  signing public key:          {keys['signing_public_key']}")
    click.echo(f"  signing private key:\n{keys['signing_private_key']}")
    click.echo(f"  age (encryption) public key: {keys['age_public_key']}")
    click.echo(f"  age (encryption) private key:\n{keys['age_private_key']}")
    click.echo("(store all three private keys somewhere safe outside this host -- losing them "
                "makes existing backups unverifiable/undecryptable; they are not re-displayable)")


@backup_group.command("create")
@click.argument("domain")
def backup_create(domain: str):
    """Create a backup now for DOMAIN (operator destination, plus the tenant's own if configured)."""
    try:
        records = backup.create_backup(domain)
    except backup.BackupError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    for r in records:
        click.echo(f"  {r.destination:8} {r.dest_path}  ({r.size_bytes} bytes, encrypted={r.encrypted})")


@backup_group.command("run-all")
def backup_run_all():
    """Back up every tenant whose backup interval is due (systemd timer entry point)."""
    results = backup.run_all_due_backups()
    if not results:
        click.echo("no tenants due")
        return
    for domain, status in results.items():
        click.echo(f"{domain:30} {status}")
    if any(status != "ok" for status in results.values()):
        sys.exit(1)


@backup_group.command("list")
@click.argument("domain")
def backup_list(domain: str):
    """List known backup records for DOMAIN (from this deployment's own registry)."""
    records = registry.list_backups(domain)
    if not records:
        click.echo("no backups recorded")
        return
    for r in records:
        click.echo(f"{r.created_at}  {r.destination:8} {r.dest_path}  ({r.size_bytes} bytes, encrypted={r.encrypted}, status={r.status})")


@backup_group.command("list-remote")
@click.option("--domain", "domain", default=None, help="List snapshots for this domain instead of listing domains.")
@click.option("--source", type=click.Choice(["operator", "tenant"]), default="operator")
def backup_list_remote(domain: str | None, source: str):
    """Browse a destination directly over SFTP -- works even for domains with no local registry rows."""
    tenant = registry.get_tenant_any_status(domain) if (domain and source == "tenant") else None
    try:
        if domain:
            names = backup.list_remote_snapshots(domain, source=source, tenant=tenant)
        else:
            names = backup.list_remote_domains(source=source, tenant=tenant)
    except backup.BackupError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    for name in names:
        click.echo(name)


@backup_group.command("restore")
@click.argument("domain")
@click.argument("snapshot_name")
@click.option("--source", type=click.Choice(["operator", "tenant"]), default="operator")
@click.option("--as-domain", "as_domain", default=None, help="Restore under a different domain than the snapshot's own.")
def backup_restore(domain: str, snapshot_name: str, source: str, as_domain: str | None):
    """Restore SNAPSHOT_NAME for DOMAIN -- recreates the tenant if it doesn't exist here, otherwise restores content in place."""
    try:
        tenant = backup.restore_backup(domain, snapshot_name, source=source, target_domain=as_domain)
    except backup.BackupError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"restored {tenant.domain} from {domain}/{snapshot_name}")
    click.echo("(WebAuthn is never in a backup -- if this recreated the tenant, login is password-only; "
                "if it restored into an existing tenant, that tenant's own WebAuthn keys were left untouched)")


@backup_group.command("process-requests")
def backup_process_requests():
    """Reconcile tenant-configured backup settings/keys/on-demand triggers (reconciler timer entry point)."""
    backup.process_requests()


@backup_group.command("ship-audit-log")
def backup_ship_audit_log():
    """Ship any new audit.log entries to the operator's SFTP destination (the audit-ship timer's own entry point)."""
    # Mirror first, then ship: anything an operator did inside a tenant's
    # panel since the last run becomes an operator-log entry here, so the
    # same run that ships the log off-host also carries those. Doing it
    # in the timer rather than in the admin UI is deliberate -- an
    # operator must not be able to keep their own actions out of their
    # own log by simply never reloading a page.
    try:
        mirrored = provisioner.mirror_all_tenant_operator_actions()
        if mirrored:
            click.echo(f"mirrored {mirrored} operator action(s) from tenant panels")
    except Exception as e:  # noqa: BLE001 -- must never block shipping
        click.echo(f"warning: mirroring tenant operator actions failed: {e!r}", err=True)
    try:
        n = backup.ship_audit_log()
    except backup.BackupError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"shipped {n} new byte(s)" if n else "nothing new to ship")


@cli.group()
def dns():
    """Suggested DNS records (never pushed anywhere -- see architecture.md's DNS automation section)."""


cli.add_command(dns, name="dns")


@dns.command("records")
@click.argument("domain")
def dns_show_records(domain: str):
    """Print the full suggested record set for DOMAIN -- A/www/mail A, MX, SPF, DKIM, DMARC."""
    try:
        records = dns_records.suggested_records(domain)
    except dns_records.DnsRecordsError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"Suggested DNS records for {domain} -- review before applying, nothing here touches live DNS:\n")
    for r in records:
        click.echo(f"{r.kind:<4} {r.name:<40} {r.value}")
        if r.note:
            click.echo(f"     ^ {r.note}")
        click.echo()


@cli.group()
def secrets_group():
    """Envelope encryption for credentials at rest (registry.py/totp.py)."""


cli.add_command(secrets_group, name="secrets")


@secrets_group.command("init")
@click.option("--force", is_flag=True, help="Regenerate the master key even if one already exists (orphans everything encrypted under the old one).")
def secrets_init(force: bool):
    """Generate the master key used to encrypt tenant credentials and TOTP secrets at rest."""
    try:
        secretbox.init_master_key(force=force)
    except secretbox.SecretBoxError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(1)
    click.echo(f"master key generated at {secretbox.MASTER_KEY_PATH}")
    click.echo("run `vhsp secrets migrate` next to encrypt any credentials already on disk.")


@secrets_group.command("migrate")
def secrets_migrate():
    """Re-encrypt any tenant credentials / TOTP secrets / backup private keys still in plaintext (e.g. written before `vhsp secrets init` ran, or before backup-key encryption existed). Safe to re-run -- already-encrypted values are left untouched."""
    if not secretbox.is_initialized():
        click.echo("error: no master key yet -- run `vhsp secrets init` first", err=True)
        sys.exit(1)
    tenants_updated = registry.reencrypt_all_credentials()
    totp_updated = totp.reencrypt_all()
    backup_keys_updated = backup.migrate_operator_keys()
    click.echo(f"re-encrypted {tenants_updated} tenant row(s), {totp_updated} TOTP secret(s), {backup_keys_updated} backup key file(s)")


@secrets_group.command("rotate")
def secrets_rotate():
    """Generate a fresh master key and re-encrypt every tenant credential
    and TOTP secret under it, replacing the old key -- for when the
    current key is known or suspected to have leaked (`vhsp secrets
    migrate` doesn't help with that: it only touches still-plaintext
    rows, not ones already encrypted under a compromised key).

    IMPORTANT: stop vhsp-admin.service and any vhsp-backup*.service/
    timers before running this. A process still reading with the old key
    while this runs would fail to decrypt rows this command has already
    rewritten under the new one -- there's no cross-process coordination
    here, just a documented precondition, matching this deployment's
    single-operator scale. Restart those services once this finishes."""
    if not secretbox.is_initialized():
        click.echo("error: no master key yet -- run `vhsp secrets init` first", err=True)
        sys.exit(1)
    old_fernet = Fernet(secretbox.MASTER_KEY_PATH.read_bytes())
    new_key_bytes = Fernet.generate_key()
    new_fernet = Fernet(new_key_bytes)

    tenants_rotated = registry.rotate_credentials(old_fernet, new_fernet)
    totp_rotated = totp.rotate_secrets(new_fernet)

    # Swap the key file only after both stores are fully rewritten under
    # the new key -- write-then-rename so a crash mid-write never leaves
    # a truncated key file in place of a good one.
    tmp_path = secretbox.MASTER_KEY_PATH.with_name(secretbox.MASTER_KEY_PATH.name + ".new")
    tmp_path.write_bytes(new_key_bytes)
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(secretbox.MASTER_KEY_PATH)

    click.echo(f"rotated {tenants_rotated} tenant row(s), {totp_rotated} TOTP secret(s) to a new master key")
    click.echo("restart vhsp-admin.service and any vhsp-backup*.service/timers now if you stopped them")


@cli.group()
def audit_group():
    """The local audit trail (audit.py) -- tamper-evidence checks."""


cli.add_command(audit_group, name="audit")


@audit_group.command("verify")
def audit_verify():
    """Walk the local audit log and confirm its hash chain is intact.
    A break means some past entry was edited or deleted -- report where.
    Entries written before chaining existed can't be verified
    retroactively (see audit.verify_chain's own docstring) and don't
    count as a break on their own."""
    intact, count = audit.verify_chain()
    if intact:
        click.echo(f"chain intact -- {count} entr{'y' if count == 1 else 'ies'} checked")
    else:
        click.echo(f"error: chain broken at entry {count} -- {count} entries before it verified correctly", err=True)
        sys.exit(1)


# Root-owned, self-validating wrapper scripts installed once to
# /usr/local/sbin (see deploy/vhsp-sudoers's own header comment for why
# this pattern exists at all). The two fail2ban ones each hardcode a
# copy of a path config.py also derives from STATE_DIR/VHSP_STATE_DIR,
# rather than reading it from config.py directly -- they run outside
# this process entirely (fail2ban's own root service, or sudo), so
# there's no live import boundary to share the value through. A follow-
# up security review flagged that nothing actually enforces the two
# copies stay in sync (only a "must match config.py's X" comment in
# each script) -- if a deployment ever overrides VHSP_STATE_DIR after
# these scripts were installed, the allowlist/tenant-jail machinery
# would silently stop finding the right files. Fails *safe* (over-bans
# rather than skipping real bans) but silently, which is exactly the
# kind of drift `doctor` exists to catch instead of leaving to be
# noticed the hard way.
_FAIL2BAN_PATH_CHECKS = [
    ("/usr/local/sbin/vhsp-fail2ban-allowlist-check", "OPERATOR_LIST", lambda: str(config.FAIL2BAN_OPERATOR_ALLOWLIST_PATH)),
    ("/usr/local/sbin/vhsp-fail2ban-allowlist-check", "TENANTS_DIR", lambda: str(config.TENANTS_DIR)),
    ("/usr/local/sbin/vhsp-fail2ban-tenant-jail", "TENANTS_DIR", lambda: str(config.TENANTS_DIR)),
]


@cli.command("doctor")
def doctor():
    """Sanity-check that deployment-time assumptions this process can't
    verify on its own (paths hardcoded into root-owned scripts installed
    outside this codebase's own import graph) still match config.py's
    current values. Exits non-zero if any check fails or can't run, so
    it's safe to wire into a deploy pipeline, not just for humans."""
    problems = 0
    for script_path, var_name, expected_fn in _FAIL2BAN_PATH_CHECKS:
        path = Path(script_path)
        if not path.exists():
            click.echo(f"skip: {script_path} not installed on this host yet")
            continue
        match = re.search(rf'^{re.escape(var_name)}="([^"]*)"', path.read_text(), re.MULTILINE)
        if not match:
            click.echo(f"error: couldn't find a {var_name}=\"...\" line in {script_path} -- script format changed?", err=True)
            problems += 1
            continue
        actual, expected = match.group(1), expected_fn()
        if actual != expected:
            click.echo(
                f"error: {script_path}'s {var_name} is {actual!r}, but config.py currently "
                f"says {expected!r} -- this script was installed before VHSP_STATE_DIR changed, "
                f"or the script is stale. Reinstall it (see DEPLOYMENT.md's fail2ban section).",
                err=True,
            )
            problems += 1
        else:
            click.echo(f"ok: {script_path}'s {var_name} matches config.py ({actual!r})")

    if problems:
        click.echo(f"\n{problems} problem(s) found", err=True)
        sys.exit(1)
    click.echo("\nall checks passed")


if __name__ == "__main__":
    cli()


@cli.group()
def update():
    """Check whether a newer vhsp release is available.

    Notification only -- nothing here downloads or applies anything. See
    UPDATING.md for the actual update procedure, and update_check.py's
    module docstring for why applying updates automatically is
    deliberately not a feature.
    """


@update.command("check")
def update_check_cmd():
    """Ask GitHub for the latest release now (also run daily by
    vhsp-update-check.timer). Works regardless of the opt-in toggle --
    running this by hand IS the operator choosing to make the request;
    the toggle governs the unattended timer and the UI banner."""
    state = update_check.run_check()
    if state.get("last_error"):
        raise click.ClickException(state["last_error"])
    latest = state.get("latest_tag", "?")
    if state.get("update_available"):
        click.echo(f"update available: {latest} (running {__version__})")
        click.echo(f"  release notes: {state.get('latest_url', '')}")
        click.echo(f"  how to update: {update_check.UPDATING_DOC_URL}")
    else:
        click.echo(f"up to date: running {__version__}, latest release is {latest}")


@update.command("status")
def update_status_cmd():
    """Show the last cached result without contacting GitHub."""
    st = update_check.status()
    click.echo(f"running version:  {st['current_version']}")
    click.echo(f"latest release:   {st.get('latest_tag') or '(never checked)'}")
    click.echo(f"last checked:     {st.get('last_checked_at') or '(never)'}")
    if st.get("last_error"):
        click.echo(f"last error:       {st['last_error']}")
    click.echo(f"update available: {'yes' if st['update_available'] else 'no'}")
    click.echo(f"checks enabled:   {'yes' if config.current_update_check_enabled() else 'no (opt-in)'}")


@update.command("enable")
def update_enable_cmd():
    """Allow the daily unattended check and the admin-UI banner."""
    platform_settings.set_update_check_enabled(True, actor="cli")
    click.echo("update checks enabled")


@update.command("disable")
def update_disable_cmd():
    """Stop the unattended check and hide the banner."""
    platform_settings.set_update_check_enabled(False, actor="cli")
    click.echo("update checks disabled")
