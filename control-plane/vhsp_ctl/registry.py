"""SQLite-backed tenant registry.

This is the control plane's source of truth: domain -> container/network/
volume/port assignments. The Docker objects themselves are derived from
this state at provisioning time; the registry is what survives a control
plane restart.
"""

import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from vhsp_ctl import secretbox
from vhsp_ctl.config import DB_PATH

# Columns holding tenant credentials, encrypted at rest via secretbox --
# see that module's docstring for why. add_tenant()/set_tenant_db_password()/
# set_tenant_admin_password() are the only writers, _row_to_tenant() the
# only reader; every other call site (provisioner.py, web.py, backup.py,
# cli.py) only ever sees a plaintext Tenant object, unaware this exists.
_ENCRYPTED_FIELDS = ("db_password", "db_root_password", "mail_password", "tenant_admin_password")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL,
    domain TEXT NOT NULL,
    ssh_port INTEGER NOT NULL,
    web_container TEXT NOT NULL,
    -- Coraza WAF reverse-proxy sidecar -- owns the public Traefik router
    -- web_container used to hold directly (see provisioner.py's
    -- _create_waf_container). DEFAULT '' so CREATE TABLE IF NOT EXISTS
    -- deployments and the _MIGRATIONS path below agree on new-column
    -- shape, even though this is always populated at creation time now
    -- (existing tenants from before this feature get '' until backfilled
    -- via recreate_waf.py).
    waf_container TEXT NOT NULL DEFAULT '',
    db_network TEXT NOT NULL,
    webroot_volume TEXT NOT NULL,
    webroot_host_path TEXT NOT NULL,
    db_container TEXT NOT NULL,
    db_volume TEXT NOT NULL,
    db_host_path TEXT NOT NULL,
    db_name TEXT NOT NULL,
    db_user TEXT NOT NULL,
    db_password TEXT NOT NULL,
    db_root_password TEXT NOT NULL,
    sftp_container TEXT NOT NULL,
    sftp_user TEXT NOT NULL,
    ssh_keys_volume TEXT NOT NULL,
    ssh_keys_host_path TEXT NOT NULL,
    ssh_public_key TEXT NOT NULL DEFAULT '',
    ssh_key_fingerprint TEXT NOT NULL DEFAULT '',
    mail_container TEXT NOT NULL,
    mail_volume TEXT NOT NULL,
    mail_host_path TEXT NOT NULL,
    mail_hostname TEXT NOT NULL,
    mail_user TEXT NOT NULL,
    mail_password TEXT NOT NULL,
    tenant_admin_container TEXT NOT NULL,
    phpconf_volume TEXT NOT NULL,
    phpconf_host_path TEXT NOT NULL,
    admin_hostname TEXT NOT NULL,
    logs_volume TEXT NOT NULL,
    logs_host_path TEXT NOT NULL,
    tenant_admin_password TEXT NOT NULL DEFAULT '',
    -- Operator-set only (see set_tenant_billing_account_id -- no
    -- writer anywhere in images/tenant-admin/app.py, deliberately, this
    -- ties a tenant to an account in external billing software, not a
    -- tenant-facing concept). Optional, never required at creation time,
    -- same as backup_dest_host etc. below.
    billing_account_id TEXT NOT NULL DEFAULT '',
    -- Whether plain http://<domain> gets redirected to https, or falls
    -- through to Traefik's own bare 404 (see provisioner.py's
    -- _create_waf_container -- this is a pair of `traefik.*` labels on
    -- the tenant's WAF sidecar, not a nginx/PHP-level setting). DEFAULT 1
    -- so every tenant, new or pre-existing, redirects unless an operator
    -- explicitly turns it off via set_tenant_https_redirect.
    https_redirect INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

-- Uniqueness only matters among *active* tenants -- a destroyed tenant's
-- row is kept for history but must not block its domain/slug/port from
-- being reused.
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_slug_active
    ON tenants(slug) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_domain_active
    ON tenants(domain) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_ssh_port_active
    ON tenants(ssh_port) WHERE status = 'active';

-- One row per pushed snapshot (see backup.py's create_backup). The first
-- second table this registry has ever needed -- a pure addition via
-- CREATE TABLE IF NOT EXISTS, same as tenants' own original creation, so
-- it needs no _MIGRATIONS entry despite being new. Kept even after a
-- tenant is destroyed (never deleted alongside mark_destroyed) since an
-- operator-destination backup must stay restorable regardless of what
-- happens to the tenant's row on THIS deployment.
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_domain TEXT NOT NULL,
    tenant_slug TEXT NOT NULL,
    created_at TEXT NOT NULL,
    destination TEXT NOT NULL,
    dest_host TEXT NOT NULL,
    dest_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    encrypted INTEGER NOT NULL DEFAULT 0,
    manifest_sha256 TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS ix_backups_domain_dest
    ON backups(tenant_domain, destination, created_at);
"""


@dataclass
class Tenant:
    slug: str
    domain: str
    ssh_port: int
    web_container: str
    db_network: str
    webroot_volume: str
    webroot_host_path: str
    db_container: str
    db_volume: str
    db_host_path: str
    db_name: str
    db_user: str
    db_password: str
    db_root_password: str
    sftp_container: str
    sftp_user: str
    ssh_keys_volume: str
    ssh_keys_host_path: str
    mail_container: str
    mail_volume: str
    mail_host_path: str
    mail_hostname: str
    mail_user: str
    mail_password: str
    tenant_admin_container: str
    phpconf_volume: str
    phpconf_host_path: str
    admin_hostname: str
    logs_volume: str
    logs_host_path: str
    status: str
    created_at: str
    ssh_public_key: str = ""
    ssh_key_fingerprint: str = ""
    tenant_admin_password: str = ""
    # 0/"" mean "use the platform-wide default" (see config.py's
    # DEFAULT_BACKUP_RETENTION_COUNT/DEFAULT_BACKUP_INTERVAL) -- not a
    # tenant-set 0 or a genuinely empty interval, since neither of those
    # would be a sensible tenant choice on their own.
    backup_retention_count: int = 0
    backup_interval: str = ""
    # A tenant's own ADDITIONAL destination -- always in addition to,
    # never instead of, the operator's own unconditional backup below.
    # Empty dest_host means the tenant hasn't configured one.
    backup_dest_host: str = ""
    backup_dest_port: int = 22
    backup_dest_path: str = ""
    backup_dest_user: str = ""
    backup_encryption_enabled: bool = False
    backup_age_key_path: str = ""
    backup_age_public_key: str = ""
    backup_ssh_key_path: str = ""
    backup_ssh_public_key: str = ""
    billing_account_id: str = ""
    # Populated at creation time (see provisioner.create_tenant), same as
    # web_container -- declared with a default anyway, not as a new
    # required positional field near web_container, since Python
    # dataclasses require every non-default field to precede every
    # default one and web_container sits early in this list. Same
    # precedent as tenant_admin_password above: also creation-time-set,
    # also defaulted for low-risk evolution.
    waf_container: str = ""
    # Defaults True so a fresh create_tenant() call redirects out of the
    # box (see #20 -- a tenant typing a bare http://<domain> into a
    # browser used to get a 404 instead of landing on their site).
    https_redirect: bool = True
    id: int | None = None


# The four fields above that are genuinely plaintext secrets at the
# Python level (decrypted transparently by _row_to_tenant -- every
# caller of get_tenant/list_tenants just sees a plaintext Tenant, same
# as the CLI/web UI already do). Named explicitly here, not derived by
# convention (e.g. "ends in _password"), so this list can't silently
# drift out of sync with the dataclass without a human noticing it in a
# diff.
SECRET_FIELDS = ("db_password", "db_root_password", "mail_password", "tenant_admin_password")


def tenant_to_dict(tenant: Tenant, include_secrets: bool = False) -> dict:
    """For vhsp_ctl/api.py and vhsp_ctl/mcp_server.py -- the CLI's `tenant
    show` and the web UI's tenant_detail page both already display
    SECRET_FIELDS directly to an authenticated operator, which is fine
    for a live browser session, but a bearer token is a meaningfully
    different risk profile (easier to leak into a script/log/shell
    history than a session cookie tied to one browser). Redacts by
    default; include_secrets=True exists for a future, deliberate
    "reveal" action, not exposed by any endpoint yet."""
    d = asdict(tenant)
    if not include_secrets:
        for field in SECRET_FIELDS:
            d.pop(field, None)
    return d


# Columns added after the table's first release -- CREATE TABLE IF NOT
# EXISTS (below) only creates the table when it's missing entirely, it
# doesn't retrofit new columns onto an already-populated one (verified:
# the three tenants already provisioned before tenant_admin_password
# existed would otherwise make every Tenant(**dict(row)) call fail with
# a missing keyword argument). Each entry here is applied with ALTER
# TABLE, guarded by PRAGMA table_info, exactly once.
_MIGRATIONS = [
    ("tenant_admin_password", "TEXT NOT NULL DEFAULT ''"),
    ("backup_retention_count", "INTEGER NOT NULL DEFAULT 0"),
    ("backup_interval", "TEXT NOT NULL DEFAULT ''"),
    ("backup_dest_host", "TEXT NOT NULL DEFAULT ''"),
    ("backup_dest_port", "INTEGER NOT NULL DEFAULT 22"),
    ("backup_dest_path", "TEXT NOT NULL DEFAULT ''"),
    ("backup_dest_user", "TEXT NOT NULL DEFAULT ''"),
    ("backup_encryption_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("backup_age_key_path", "TEXT NOT NULL DEFAULT ''"),
    ("backup_age_public_key", "TEXT NOT NULL DEFAULT ''"),
    ("backup_ssh_key_path", "TEXT NOT NULL DEFAULT ''"),
    ("backup_ssh_public_key", "TEXT NOT NULL DEFAULT ''"),
    ("billing_account_id", "TEXT NOT NULL DEFAULT ''"),
    ("waf_container", "TEXT NOT NULL DEFAULT ''"),
    ("https_redirect", "INTEGER NOT NULL DEFAULT 1"),
]


def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(tenants)")}
    for column, decl in _MIGRATIONS:
        if column not in existing:
            conn.execute(f"ALTER TABLE tenants ADD COLUMN {column} {decl}")


@contextmanager
def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        # Tenant credentials (db_password, db_root_password, mail_password,
        # tenant_admin_password) are encrypted at rest via secretbox.py --
        # see _ENCRYPTED_FIELDS above and that module's docstring. The
        # 0600 permission below is still real defense in depth (limits who
        # can even attempt to read the ciphertext), just no longer the
        # *only* thing standing between this file and plaintext secrets.
        os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
        yield conn
        conn.commit()
    finally:
        conn.close()


def add_tenant(tenant: Tenant) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO tenants
                (slug, domain, ssh_port, web_container, waf_container, db_network,
                 webroot_volume, webroot_host_path, db_container, db_volume,
                 db_host_path, db_name, db_user, db_password,
                 db_root_password, sftp_container, sftp_user,
                 ssh_keys_volume, ssh_keys_host_path, mail_container,
                 mail_volume, mail_host_path, mail_hostname, mail_user,
                 mail_password, tenant_admin_container, phpconf_volume,
                 phpconf_host_path, admin_hostname, logs_volume,
                 logs_host_path, tenant_admin_password, https_redirect, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant.slug,
                tenant.domain,
                tenant.ssh_port,
                tenant.web_container,
                tenant.waf_container,
                tenant.db_network,
                tenant.webroot_volume,
                tenant.webroot_host_path,
                tenant.db_container,
                tenant.db_volume,
                tenant.db_host_path,
                tenant.db_name,
                tenant.db_user,
                secretbox.encrypt(tenant.db_password),
                secretbox.encrypt(tenant.db_root_password),
                tenant.sftp_container,
                tenant.sftp_user,
                tenant.ssh_keys_volume,
                tenant.ssh_keys_host_path,
                tenant.mail_container,
                tenant.mail_volume,
                tenant.mail_host_path,
                tenant.mail_hostname,
                tenant.mail_user,
                secretbox.encrypt(tenant.mail_password),
                tenant.tenant_admin_container,
                tenant.phpconf_volume,
                tenant.phpconf_host_path,
                tenant.admin_hostname,
                tenant.logs_volume,
                tenant.logs_host_path,
                secretbox.encrypt(tenant.tenant_admin_password),
                int(tenant.https_redirect),
                tenant.status,
                tenant.created_at,
            ),
        )


def _row_to_tenant(row: sqlite3.Row) -> Tenant:
    # SQLite has no real boolean type -- backup_encryption_enabled comes
    # back as a plain 0/1 int, which Python's dataclass happily accepts
    # without coercing to bool (dataclasses don't enforce field types at
    # runtime). Truthy/falsy behavior would work either way, but coercing
    # here keeps the field actually bool-typed for anything that does a
    # stricter check later.
    d = dict(row)
    d["backup_encryption_enabled"] = bool(d["backup_encryption_enabled"])
    d["https_redirect"] = bool(d["https_redirect"])
    for field in _ENCRYPTED_FIELDS:
        d[field] = secretbox.decrypt(d[field])
    return Tenant(**d)


def get_tenant(domain: str) -> Tenant | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM tenants WHERE domain = ? AND status = 'active'",
            (domain,),
        ).fetchone()
        return _row_to_tenant(row) if row else None


def get_tenant_by_slug(slug: str) -> Tenant | None:
    """Same active-only shape as get_tenant, keyed by slug instead of
    domain -- needed by tenant_api_auth.py, which resolves a tenant
    token's identity from the slug prefix baked into the token itself
    (see that module's own docstring), not a caller-supplied domain."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM tenants WHERE slug = ? AND status = 'active'",
            (slug,),
        ).fetchone()
        return _row_to_tenant(row) if row else None


def get_tenant_any_status(domain: str) -> Tenant | None:
    """Like get_tenant, but doesn't filter on status -- used by restore's
    "does this domain have a tenant here AT ALL, active or destroyed"
    check, which is a genuinely different question than get_tenant's own
    active-only lookup. If multiple rows exist for the same domain
    (destroyed, then recreated, then destroyed again...), the most
    recent one is what matters here."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM tenants WHERE domain = ? ORDER BY id DESC LIMIT 1",
            (domain,),
        ).fetchone()
        return _row_to_tenant(row) if row else None


def list_tenants(include_destroyed: bool = False) -> list[Tenant]:
    """ORDER BY domain, not insertion order: SQLite makes no promise about
    the order of an unordered SELECT (today's de-facto rowid order can
    shift after a VACUUM or a query-plan change), and every caller here
    renders this straight into a list a human then scans for one specific
    domain. Alphabetical is the only order that makes that scan -- or the
    admin UI's filter box on top of it -- predictable.
    """
    with _connect() as conn:
        if include_destroyed:
            rows = conn.execute("SELECT * FROM tenants ORDER BY domain").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tenants WHERE status = 'active' ORDER BY domain"
            ).fetchall()
        return [_row_to_tenant(r) for r in rows]


def set_ssh_key(domain: str, public_key: str, fingerprint: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET ssh_public_key = ?, ssh_key_fingerprint = ? "
            "WHERE domain = ? AND status = 'active'",
            (public_key, fingerprint, domain),
        )


def set_tenant_waf_container(domain: str, waf_container: str) -> None:
    """Not a credential -- a plain container name, same as web_container
    etc. Used by recreate_waf.py to record the WAF sidecar's name for a
    tenant that's getting one created/recreated outside create_tenant()'s
    own registry.add_tenant() call, which already sets this at INSERT
    time for new tenants."""
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET waf_container = ? WHERE domain = ? AND status = 'active'",
            (waf_container, domain),
        )


def set_tenant_https_redirect(domain: str, enabled: bool) -> None:
    """Not a credential -- a plain flag, same as billing_account_id below.
    provisioner.set_tenant_https_redirect is the real entry point (it
    also recreates the WAF container so the new `traefik.*` labels
    actually take effect); this just persists the choice."""
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET https_redirect = ? WHERE domain = ? AND status = 'active'",
            (int(enabled), domain),
        )


def set_tenant_billing_account_id(domain: str, billing_account_id: str) -> None:
    """Not a credential -- no secretbox encryption, same as every other
    plain identifier column here (slug, db_name, etc.). Empty string is
    a valid value (clears it), matching every other optional field in
    this table."""
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET billing_account_id = ? WHERE domain = ? AND status = 'active'",
            (billing_account_id, domain),
        )


def set_tenant_admin_password(domain: str, password: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET tenant_admin_password = ? WHERE domain = ? AND status = 'active'",
            (secretbox.encrypt(password), domain),
        )


def set_tenant_db_password(domain: str, password: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET db_password = ? WHERE domain = ? AND status = 'active'",
            (secretbox.encrypt(password), domain),
        )


def set_backup_settings(
    domain: str, *, retention_count: int, interval: str,
    dest_host: str, dest_port: int, dest_path: str, dest_user: str,
    encryption_enabled: bool,
) -> None:
    """Operator- or (via backup.py's reconciler) tenant-set backup
    config -- mirrors set_tenant_quota_limit's own "one UPDATE, no
    validation here, the caller already validated" shape. Deliberately
    NOT status = 'active'-scoped like most setters here: a destroyed
    tenant's row can still legitimately have its backup settings read
    (e.g. to know where its last backups went), even though nothing
    will act on them again."""
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET backup_retention_count = ?, backup_interval = ?, "
            "backup_dest_host = ?, backup_dest_port = ?, backup_dest_path = ?, "
            "backup_dest_user = ?, backup_encryption_enabled = ? WHERE domain = ?",
            (retention_count, interval, dest_host, dest_port, dest_path,
             dest_user, int(encryption_enabled), domain),
        )


def set_backup_tenant_keys(
    domain: str, *, age_key_path: str, age_public_key: str,
    ssh_key_path: str, ssh_public_key: str,
) -> None:
    """Written by backup.py's process_requests reconciler once a
    tenant's own transport/encryption keypairs have been generated --
    never called from web.py or tenant-admin's app.py directly, since
    neither of those processes is where key generation happens (see
    backup.py's key-management functions)."""
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET backup_age_key_path = ?, backup_age_public_key = ?, "
            "backup_ssh_key_path = ?, backup_ssh_public_key = ? WHERE domain = ?",
            (age_key_path, age_public_key, ssh_key_path, ssh_public_key, domain),
        )


@dataclass
class Backup:
    tenant_domain: str
    tenant_slug: str
    created_at: str
    destination: str  # "operator" | "tenant"
    dest_host: str
    dest_path: str
    size_bytes: int
    encrypted: bool
    manifest_sha256: str
    status: str = "ok"
    id: int | None = None


def _row_to_backup(row: sqlite3.Row) -> Backup:
    d = dict(row)
    d["encrypted"] = bool(d["encrypted"])
    return Backup(**d)


def add_backup_record(b: Backup) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO backups
                (tenant_domain, tenant_slug, created_at, destination,
                 dest_host, dest_path, size_bytes, encrypted,
                 manifest_sha256, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (b.tenant_domain, b.tenant_slug, b.created_at, b.destination,
             b.dest_host, b.dest_path, b.size_bytes, int(b.encrypted),
             b.manifest_sha256, b.status),
        )
        return cur.lastrowid


def list_backups(domain: str, destination: str | None = None) -> list[Backup]:
    with _connect() as conn:
        if destination:
            rows = conn.execute(
                "SELECT * FROM backups WHERE tenant_domain = ? AND destination = ? "
                "ORDER BY created_at DESC",
                (domain, destination),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM backups WHERE tenant_domain = ? ORDER BY created_at DESC",
                (domain,),
            ).fetchall()
        return [_row_to_backup(r) for r in rows]


def latest_backup_times(destination: str = "operator") -> dict[str, str]:
    """{tenant_domain: newest successful backup's created_at} for EVERY
    tenant, as one aggregate query -- the admin UI's tenant list needs
    this per row, and list_backups() above is per-domain, so calling that
    in the render loop would add a query per tenant to a page that
    otherwise costs exactly one.

    Only status='ok' rows count. A failed backup must never present as a
    recent one: "last backup: today" next to a tenant whose backup
    actually errored is worse than showing nothing, since it's precisely
    the case an operator needs to notice.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT tenant_domain, MAX(created_at) AS latest FROM backups "
            "WHERE status = 'ok' AND destination = ? GROUP BY tenant_domain",
            (destination,),
        ).fetchall()
        return {r["tenant_domain"]: r["latest"] for r in rows}


def prune_old_backups(domain: str, destination: str, keep_n: int) -> list[Backup]:
    """Deletes registry rows for every backup beyond the newest keep_n
    for this domain/destination and returns exactly those pruned rows.
    Only touches this table -- deleting the corresponding remote file is
    backup.py's job (registry.py never touches Docker/SSH/host state
    itself anywhere else in this module, same separation of concerns
    kept throughout)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM backups WHERE tenant_domain = ? AND destination = ? "
            "ORDER BY created_at DESC",
            (domain, destination),
        ).fetchall()
        stale = rows[keep_n:]
        if stale:
            conn.executemany(
                "DELETE FROM backups WHERE id = ?", [(r["id"],) for r in stale]
            )
        return [_row_to_backup(r) for r in stale]


def reencrypt_all_credentials() -> int:
    """One-time migration for `vhsp secrets migrate`: re-writes every
    tenant's credential columns through secretbox.encrypt(), for rows
    written before `vhsp secrets init` ever ran. The writers above only
    encrypt going forward and _row_to_tenant() already transparently
    decrypts old plaintext, so nothing is actually broken without this --
    it just closes the gap so old rows don't stay unencrypted forever.

    Operates on every row regardless of status (including destroyed
    tenants, which get_tenant() would otherwise skip) -- a destroyed
    tenant's old credentials sitting in the database in plaintext are
    just as real a leak as an active one's. Idempotent: an already-
    encrypted value is left untouched rather than re-wrapped, so re-
    running finds nothing to do and returns 0.
    """
    updated = 0
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, db_password, db_root_password, mail_password, tenant_admin_password FROM tenants"
        ).fetchall()
        for row in rows:
            values = {}
            changed = False
            for field in _ENCRYPTED_FIELDS:
                raw = row[field]
                if secretbox.is_encrypted(raw):
                    values[field] = raw
                else:
                    values[field] = secretbox.encrypt(raw)
                    changed = True
            if changed:
                conn.execute(
                    "UPDATE tenants SET db_password = ?, db_root_password = ?, "
                    "mail_password = ?, tenant_admin_password = ? WHERE id = ?",
                    (values["db_password"], values["db_root_password"],
                     values["mail_password"], values["tenant_admin_password"], row["id"]),
                )
                updated += 1
    return updated


def rotate_credentials(old_fernet, new_fernet) -> int:
    """Re-encrypts every tenant row's credential columns under a new
    master key, for `vhsp secrets rotate` (cli.py) -- when the current
    master key is known or suspected to be compromised, `vhsp secrets
    migrate` (above) doesn't help, since it only touches still-plaintext
    rows. Caller passes explicit Fernet instances for the old and new
    keys (from secretbox.MASTER_KEY_PATH's current contents and a freshly
    generated key, respectively) rather than this function reading
    secretbox.MASTER_KEY_PATH itself -- the whole point of rotation is
    that the on-disk key hasn't been swapped yet when this runs, so
    secretbox.encrypt()/decrypt() (which always use whatever's currently
    on disk) would be wrong here; secretbox.encrypt_with()/decrypt_with()
    take an explicit key instead.

    Every row is decrypted-then-re-encrypted inside a single SQLite
    transaction (one `with _connect()` block, same as
    reencrypt_all_credentials above) so a failure partway rolls back
    cleanly rather than leaving some rows under the old key and others
    under the new one. Also implicitly finishes migrating any row that
    was still plaintext (decrypt_with's pass-through hands the same value
    back, which then gets freshly encrypted under the new key) -- no
    separate is_encrypted() branch needed here, unlike
    reencrypt_all_credentials, since every row gets rewritten regardless.
    """
    updated = 0
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, db_password, db_root_password, mail_password, tenant_admin_password FROM tenants"
        ).fetchall()
        for row in rows:
            values = {}
            for field in _ENCRYPTED_FIELDS:
                plaintext = secretbox.decrypt_with(old_fernet, row[field])
                values[field] = secretbox.encrypt_with(new_fernet, plaintext)
            conn.execute(
                "UPDATE tenants SET db_password = ?, db_root_password = ?, "
                "mail_password = ?, tenant_admin_password = ? WHERE id = ?",
                (values["db_password"], values["db_root_password"],
                 values["mail_password"], values["tenant_admin_password"], row["id"]),
            )
            updated += 1
    return updated


def mark_destroyed(domain: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE tenants SET status = 'destroyed' WHERE domain = ?",
            (domain,),
        )


def used_ssh_ports() -> set[int]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ssh_port FROM tenants WHERE status = 'active'"
        ).fetchall()
        return {r["ssh_port"] for r in rows}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()
