"""Tenant backup and restore.

Two tiers, both built on the same snapshot format:
  - Operator-level: every active tenant is backed up unconditionally to
    ONE operator-configured SFTP destination, no tenant opt-out. Must
    survive the tenant/domain being deleted -- restoring re-provisions
    the tenant from scratch, even onto a completely different vhsp
    deployment, reusing the SSH port only if it's still free there.
  - Tenant-level: a tenant can ADDITIONALLY configure their own SFTP
    destination (never a replacement for the operator's copy), with
    optional client-side encryption.

A snapshot bundles four pre-compressed components (webroot.tar.gz,
db.sql.gz, mail.tar.gz, phpconf.tar.gz) plus a manifest.json (enough to
reconstruct a registry.Tenant row from nothing else) and its detached
signature into one outer, uncompressed tar -- which is what gets
age-encrypted as a single unit when encryption applies. WebAuthn
credentials are never collected into any component; their absence is
what makes a freshly-restored tenant come back password-only.

Three purpose-specific operator keypairs (see init_operator_keys) --
SSH transport, age encryption, Ed25519 signing (via ssh-keygen -Y
sign/verify, OpenSSH's own signature format -- no extra signing tool
needed beyond what's already ambient) -- are plain 600 host files,
deliberately not Docker Swarm secrets (only mountable into Swarm
*services*, and tied to that swarm's raft state -- a recoverability
trap if this host is lost) and not systemd-creds (TPM/host-key bound,
same trap). Each is shown exactly once at generation time.

Signature verification is MANDATORY before any restore proceeds --
operator-triggered or tenant self-service, no bypass exists in this
module's own API on purpose. This is the actual defense against a
compromised backup destination smuggling tampered content back in.
"""

import gzip
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from docker.errors import NotFound

from vhsp_ctl import audit, provisioner, registry, secretbox
from vhsp_ctl.config import (
    AUDIT_SHIP_STATE_PATH,
    BACKUP_INTERVAL_DAYS,
    BACKUP_KEYS_DIR,
    BACKUP_MANIFEST_FORMAT_VERSION,
    BACKUP_OPERATOR_AGE_KEY_PATH,
    BACKUP_OPERATOR_SFTP_HOST,
    BACKUP_OPERATOR_SFTP_PATH,
    BACKUP_OPERATOR_SFTP_PORT,
    BACKUP_OPERATOR_SFTP_USER,
    BACKUP_OPERATOR_SIGNING_KEY_PATH,
    BACKUP_OPERATOR_SSH_KEY_PATH,
    BACKUP_TENANT_KEYS_DIR,
    BACKUP_WORKDIR,
    DB_INTERNAL_PORT,
    DEFAULT_BACKUP_INTERVAL,
    DEFAULT_BACKUP_RETENTION_COUNT,
    DEFAULT_WEB_IMAGE,
    GATEWAY_NETWORK,
    WEB_DOCUMENT_ROOT,
    WEB_TRUSTED_PROXY_CIDRS,
)


class BackupError(Exception):
    pass


# --- shell-out helpers -------------------------------------------------

def _run(args: list[str], input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """Thin wrapper so every shelled-out failure in this module (ssh/scp
    unreachable, wrong key, age/ssh-keygen rejecting bad input, etc.)
    surfaces as a BackupError the CLI/web/tenant-admin layers already
    know how to catch and display, instead of a raw CalledProcessError
    with no handler anywhere in those layers."""
    try:
        return subprocess.run(args, input=input_bytes, capture_output=True, check=check)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="replace").strip() if e.stderr else ""
        raise BackupError(f"{args[0]} failed: {stderr or e}") from e


def _chmod600(path: Path) -> None:
    path.chmod(0o600)


# --- key management ------------------------------------------------------

@contextmanager
def _decrypted_key_file(encrypted_path: Path):
    """Stages a plaintext copy of an at-rest-encrypted private key file
    (secretbox-wrapped text -- see _write_encrypted_key below) into a
    private 0600 temp file for exactly the duration of one subprocess
    call that needs a real path on disk. ssh/scp/age/ssh-keygen all
    require an actual file path, not stdin, for their key argument --
    there's no way to hand them key material without SOME file existing
    on disk, so this keeps that existence window as short as a single
    `with` block instead of the key's entire lifetime on disk. Deletion
    happens in a finally so it runs even if the wrapped subprocess call
    raises (a failed ssh/age invocation must not leave plaintext behind
    any more than a successful one does).

    Placed under BACKUP_WORKDIR (this module's existing scratch-space
    convention, already cleaned up per-operation elsewhere in this file)
    rather than the system default temp dir -- keeps every transient
    file this module ever creates in one place."""
    plaintext = secretbox.decrypt(encrypted_path.read_text())
    BACKUP_WORKDIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=BACKUP_WORKDIR, prefix=".vhsp-key-")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(plaintext)
        _chmod600(tmp_path)
        yield tmp_path
    finally:
        tmp_path.unlink(missing_ok=True)


def _write_encrypted_key(path: Path, plaintext: str) -> None:
    path.write_text(secretbox.encrypt(plaintext))
    _chmod600(path)


def _generate_ssh_keypair(path: Path, comment: str) -> str:
    """Writes path (private, encrypted at rest -- see _write_encrypted_key)
    + path.with_suffix additive '.pub' (public, never sensitive, stays
    plaintext). Returns the public key text. -N "" -> no passphrase: this
    key is used unattended by a systemd timer, not typed in interactively.

    ssh-keygen itself unavoidably writes the private key to disk in
    plaintext -- there's no way to have it emit ciphertext directly --
    so the encrypt-in-place happens immediately after, before this
    function returns to any caller."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    Path(f"{path}.pub").unlink(missing_ok=True)
    _run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)])
    _write_encrypted_key(path, path.read_text())
    return Path(f"{path}.pub").read_text().strip()


def _generate_age_keypair(path: Path) -> str:
    """Writes the AGE-SECRET-KEY-1... identity to path (encrypted at rest
    once this returns), returns the corresponding age1... recipient
    (public) string.

    Same "external binary unavoidably writes plaintext first" reasoning
    as _generate_ssh_keypair -- the pubkey derivation below (age-keygen's
    own authority on deriving one from the other, not hand-rolled) has to
    run against the real plaintext identity file BEFORE it gets
    overwritten with ciphertext, not after."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _run(["age-keygen", "-o", str(path)])
    plaintext = path.read_text()
    result = _run(["age-keygen", "-y", str(path)])
    _write_encrypted_key(path, plaintext)
    return result.stdout.decode().strip()


def init_operator_keys(force: bool = False) -> dict:
    """`vhsp backup init`. Generates all three operator keypairs if
    missing. Refuses to silently overwrite existing ones unless
    force=True: regenerating the signing key invalidates every existing
    backup's verifiability (old backups were signed with the old key),
    and regenerating the age key makes every existing operator-
    destination backup permanently undecryptable. Returns everything the
    CLI needs to print ONCE -- same "generated, shown once, never
    persisted anywhere re-displayable" UX this codebase already uses for
    operator/tenant admin passwords (see auth.create_operator).
    """
    existing = [
        p for p in (BACKUP_OPERATOR_SSH_KEY_PATH, BACKUP_OPERATOR_AGE_KEY_PATH, BACKUP_OPERATOR_SIGNING_KEY_PATH)
        if p.exists()
    ]
    if existing and not force:
        raise BackupError(
            f"operator backup keys already exist ({', '.join(str(p) for p in existing)}) -- "
            "pass --force to regenerate (this invalidates every existing backup's "
            "signature/decryptability, only do this if you understand that)"
        )

    ssh_pub = _generate_ssh_keypair(BACKUP_OPERATOR_SSH_KEY_PATH, "vhsp-backup-transport")
    signing_pub = _generate_ssh_keypair(BACKUP_OPERATOR_SIGNING_KEY_PATH, "vhsp-backup-manifest-signing")
    age_pub = _generate_age_keypair(BACKUP_OPERATOR_AGE_KEY_PATH)

    return {
        "ssh_private_key": secretbox.decrypt(BACKUP_OPERATOR_SSH_KEY_PATH.read_text()),
        "ssh_public_key": ssh_pub,
        "signing_private_key": secretbox.decrypt(BACKUP_OPERATOR_SIGNING_KEY_PATH.read_text()),
        "signing_public_key": signing_pub,
        "age_private_key": secretbox.decrypt(BACKUP_OPERATOR_AGE_KEY_PATH.read_text()),
        "age_public_key": age_pub,
    }


def migrate_operator_keys() -> int:
    """One-time migration for `vhsp secrets migrate`: operator and
    tenant backup private keys generated before this encryption-at-rest
    pass existed are still plaintext on disk. Same idempotent
    "is_encrypted() per file, skip if already done" shape as
    registry.reencrypt_all_credentials/totp.reencrypt_all. Returns the
    number of files touched."""
    paths = [BACKUP_OPERATOR_SSH_KEY_PATH, BACKUP_OPERATOR_AGE_KEY_PATH, BACKUP_OPERATOR_SIGNING_KEY_PATH]
    if BACKUP_TENANT_KEYS_DIR.exists():
        paths += sorted(BACKUP_TENANT_KEYS_DIR.glob("*/ssh_ed25519"))
        paths += sorted(BACKUP_TENANT_KEYS_DIR.glob("*/age.key"))
    updated = 0
    for path in paths:
        if not path.exists():
            continue
        content = path.read_text()
        if not secretbox.is_encrypted(content):
            _write_encrypted_key(path, content)
            updated += 1
    return updated


def _tenant_key_dir(slug: str) -> Path:
    return BACKUP_TENANT_KEYS_DIR / slug


def ensure_tenant_ssh_key(slug: str) -> tuple[Path, str]:
    """Generates a tenant's own backup-transport keypair if it doesn't
    exist yet; returns (private_key_path, public_key_text). The public
    half is safe to show/redisplay in tenant-admin at any time -- unlike
    the age encryption key below, it's not sensitive."""
    key_path = _tenant_key_dir(slug) / "ssh_ed25519"
    pub_path = Path(f"{key_path}.pub")
    if key_path.exists() and pub_path.exists():
        return key_path, pub_path.read_text().strip()
    pub = _generate_ssh_keypair(key_path, f"vhsp-backup-transport-{slug}")
    return key_path, pub


def ensure_tenant_age_key(slug: str, own_private_key: str | None = None) -> tuple[Path, str, str | None]:
    """Returns (key_path, public_recipient, first_reveal_or_None).
    first_reveal is the raw private key text, present ONLY on the call
    that actually generates it (or ingests one the tenant pasted in) --
    every subsequent call for the same tenant returns None there, so the
    caller (process_requests) can write it into backup_status.json's
    one-time-reveal field exactly once and never again.

    key_path holds ciphertext at rest (see _write_encrypted_key) in
    every branch below -- age-keygen itself only ever runs against a
    real plaintext file (staged via _decrypted_key_file when reading an
    existing key back), never the ciphertext directly."""
    key_path = _tenant_key_dir(slug) / "age.key"
    if key_path.exists():
        with _decrypted_key_file(key_path) as tmp:
            pub = _run(["age-keygen", "-y", str(tmp)]).stdout.decode().strip()
        return key_path, pub, None

    key_path.parent.mkdir(parents=True, exist_ok=True)
    if own_private_key:
        plaintext = own_private_key.strip() + "\n"
        _write_encrypted_key(key_path, plaintext)
        with _decrypted_key_file(key_path) as tmp:
            pub = _run(["age-keygen", "-y", str(tmp)]).stdout.decode().strip()
        return key_path, pub, plaintext
    else:
        pub = _generate_age_keypair(key_path)
        return key_path, pub, secretbox.decrypt(key_path.read_text())


# --- hashing / manifest --------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_manifest(tenant: registry.Tenant, component_files: dict[str, Path]) -> dict:
    """Everything _restore_as_new_tenant needs to reconstruct a
    registry.Tenant row from nothing but this file -- including every
    credential EXACTLY as it was at backup time (reused verbatim on
    restore, never regenerated, by explicit choice). Deliberately never
    reads or references webauthn_credentials.json at all -- that file
    isn't collected into phpconf.tar.gz's manifest hash either, it's
    just absent from the whole snapshot."""
    return {
        "format_version": BACKUP_MANIFEST_FORMAT_VERSION,
        "created_at": registry.now(),
        "domain": tenant.domain,
        "slug": tenant.slug,
        "sftp_port": tenant.ssh_port,
        "sftp_user": tenant.sftp_user,
        "ssh_public_key": tenant.ssh_public_key,
        "ssh_key_fingerprint": tenant.ssh_key_fingerprint,
        "mail_hostname": tenant.mail_hostname,
        "mail_user": tenant.mail_user,
        "mail_password": tenant.mail_password,
        "admin_hostname": tenant.admin_hostname,
        "db_name": tenant.db_name,
        "db_user": tenant.db_user,
        "db_password": tenant.db_password,
        "db_root_password": tenant.db_root_password,
        "tenant_admin_password": tenant.tenant_admin_password,
        "components": [
            {"name": name, "sha256": _sha256_file(p), "size_bytes": p.stat().st_size}
            for name, p in component_files.items()
        ],
    }


# --- signing / encryption -------------------------------------------------

def _sign_manifest(manifest_path: Path, signing_key_path: Path) -> Path:
    sig_path = Path(f"{manifest_path}.sig")
    sig_path.unlink(missing_ok=True)
    _run(["ssh-keygen", "-Y", "sign", "-f", str(signing_key_path), "-n", "vhsp-backup", str(manifest_path)])
    # ssh-keygen -Y sign writes <file>.sig itself; nothing further to move.
    return sig_path


def _verify_manifest_signature(manifest_path: Path, sig_path: Path, signing_public_key: str) -> None:
    """Mandatory, no-bypass check -- every restore path in this module
    calls this before extracting a single byte of tenant data from a
    fetched snapshot. A destination compromise alone can't forge a valid
    signature without the operator's (or tenant's own) private signing
    key, which never leaves this host."""
    if not sig_path.exists():
        raise BackupError("backup has no signature file -- refusing to restore")
    with tempfile.TemporaryDirectory() as td:
        allowed_signers = Path(td) / "allowed_signers"
        allowed_signers.write_text(f"backup-signer {signing_public_key}\n")
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers),
             "-I", "backup-signer", "-n", "vhsp-backup", "-s", str(sig_path)],
            input=manifest_path.read_bytes(), capture_output=True,
        )
    if result.returncode != 0:
        raise BackupError(
            f"backup signature verification FAILED -- refusing to restore "
            f"(possible tampering): {result.stderr.decode(errors='replace').strip()}"
        )


def _encrypt(src: Path, dest: Path, recipient_public_key: str) -> None:
    _run(["age", "-r", recipient_public_key, "-o", str(dest), str(src)])


def _decrypt(src: Path, dest: Path, identity_key_path: Path) -> None:
    result = subprocess.run(
        ["age", "-d", "-i", str(identity_key_path), "-o", str(dest), str(src)],
        capture_output=True,
    )
    if result.returncode != 0:
        raise BackupError(
            "decryption failed -- wrong key, or the file is corrupt/tampered "
            f"(age's own authenticated encryption rejected it): {result.stderr.decode(errors='replace').strip()}"
        )


# --- SFTP transport (shell out to ssh/scp, not a new Python SSH library) -
#
# IMPORTANT: ssh joins every trailing argv element you give it with a
# single space and sends that ONE string to the remote host, which then
# parses it exactly once through the login shell. Passing a remote
# command as several separate argv elements (e.g. ["sh", "-c", "find ..."])
# means ssh's own join-with-spaces reconstructs something like
# `sh -c find /path -mindepth 1 ...` as ONE string, which the remote shell
# then parses as "run sh with -c as its ONLY -c argument and everything
# else as sh's own positional parameters" -- not "run find scoped to
# /path" -- silently losing all the quoting and dropping find's path
# argument entirely (verified directly: it defaulted to searching the
# login shell's cwd, $HOME, recursively). The fix is to build exactly ONE
# shell-quoted command string locally and hand ssh that single string as
# its one trailing argument, so there is only one shell parse, not two.

def _ssh_opts(identity_key: Path, port: int) -> list[str]:
    return [
        "-i", str(identity_key), "-p", str(port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
    ]


def _remote_mkdir_p(host: str, port: int, user: str, identity_key: Path, remote_dir: str) -> None:
    cmd = f"mkdir -p {shlex.quote(remote_dir)}"
    _run(["ssh", *_ssh_opts(identity_key, port), f"{user}@{host}", cmd])


def _push_file(host: str, port: int, user: str, identity_key: Path, local_file: Path, remote_dir: str) -> None:
    _remote_mkdir_p(host, port, user, identity_key, remote_dir)
    _run(["scp", "-i", str(identity_key), "-P", str(port),
          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
          str(local_file), f"{user}@{host}:{remote_dir}/{local_file.name}"])


def _list_remote_dirs(host: str, port: int, user: str, identity_key: Path, base_dir: str) -> list[str]:
    cmd = f"find {shlex.quote(base_dir)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>/dev/null || true"
    result = _run(["ssh", *_ssh_opts(identity_key, port), f"{user}@{host}", cmd], check=False)
    return sorted(line for line in result.stdout.decode().splitlines() if line)


def _list_remote_files(host: str, port: int, user: str, identity_key: Path, remote_dir: str) -> list[str]:
    cmd = f"find {shlex.quote(remote_dir)} -mindepth 1 -maxdepth 1 -type f -printf '%f\\n' 2>/dev/null || true"
    result = _run(["ssh", *_ssh_opts(identity_key, port), f"{user}@{host}", cmd], check=False)
    return sorted((line for line in result.stdout.decode().splitlines() if line), reverse=True)


def _list_remote_files_detailed(
    host: str, port: int, user: str, identity_key: Path, remote_dir: str,
) -> list[dict]:
    """Same listing as _list_remote_files, plus each file's real size --
    one extra printf field, still exactly one SSH round trip. Sizes come
    from the backup host itself rather than the registry's recorded
    size_bytes deliberately: the remote file is what a restore would
    actually pull, and a snapshot can exist there with no registry row at
    all (restored onto a fresh deployment, registry rebuilt, pruned rows).
    """
    cmd = (
        f"find {shlex.quote(remote_dir)} -mindepth 1 -maxdepth 1 -type f "
        "-printf '%f\\t%s\\n' 2>/dev/null || true"
    )
    result = _run(["ssh", *_ssh_opts(identity_key, port), f"{user}@{host}", cmd], check=False)
    out = []
    for line in result.stdout.decode().splitlines():
        if not line.strip():
            continue
        name, _, raw_size = line.partition("\t")
        try:
            size_bytes = int(raw_size)
        except ValueError:
            size_bytes = None  # unreadable size must not drop the snapshot itself
        out.append({"name": name, "size_bytes": size_bytes})
    return sorted(out, key=lambda d: d["name"], reverse=True)


def _fetch_file(host: str, port: int, user: str, identity_key: Path, remote_path: str, local_file: Path) -> None:
    _run(["scp", "-i", str(identity_key), "-P", str(port),
          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
          f"{user}@{host}:{remote_path}", str(local_file)])


def _remote_rm(host: str, port: int, user: str, identity_key: Path, remote_path: str) -> None:
    cmd = f"rm -f {shlex.quote(remote_path)}"
    _run(["ssh", *_ssh_opts(identity_key, port), f"{user}@{host}", cmd], check=False)


# --- gathering components -------------------------------------------------

def _tar_directory(src_dir: Path, dest_file: Path) -> None:
    """sudo tar, not Python's tarfile module reading as this process's own
    uid: mail's entrypoint chowns its maildir tree to an internal vmail uid
    on every start, and Dovecot's own default mailbox mode (0700) leaves
    per-mailbox subdirectories unreadable to this unprivileged process --
    verified directly, tarfile.add raised PermissionError partway through a
    real tenant's mail directory. sudo is already an established dependency
    for this exact class of problem (see _restore_into_existing_tenant's own
    sudo find/chown). Root-owned tar output stays readable by this process
    afterward under sudo's default umask (0022), no extra chown needed.

    Goes through deploy/vhsp-backup-tar, a root-owned wrapper script that
    validates its own arguments, rather than a raw `sudo tar` call -- the
    astjohn user's sudoers grant is scoped (see the control-plane
    README's "Sudo scoping" section), and can't safely wildcard an
    arbitrary tenant directory into a Cmnd_Alias directly (modern sudo
    refuses wildcards in command arguments). _split_tenant_host_path
    recovers the (slug, purpose) the script needs from src_dir, which is
    always TENANTS_DIR/slug/purpose (see _create_hardened_volume)."""
    slug, purpose = provisioner._split_tenant_host_path(str(src_dir))
    result = subprocess.run(
        ["sudo", "/usr/local/sbin/vhsp-backup-tar", slug, purpose, str(dest_file)],
        capture_output=True,
    )
    if result.returncode != 0:
        raise BackupError(f"tar failed for {src_dir}: {result.stderr.decode(errors='replace').strip()}")


def _extract_component(component_file: Path, dest_dir: Path) -> None:
    with tarfile.open(component_file, "r:gz") as tf:
        tf.extractall(dest_dir, filter="data")


def _relocate_mail_domain_dir(mail_host_path: Path, old_domain: str, new_domain: str) -> None:
    """images/mail/entrypoint.sh's dovecot config keys every mailbox by
    `%d` = its own MAIL_DOMAIN env var (mail_location =
    maildir:/var/mail/vhosts/%d/%n) and postfix's virtual_mailbox_domains
    is set to that exact same domain -- so mail extracted under the
    backed-up tenant's OLD domain name is invisible to both once the
    container comes up as `new_domain`, not silently readable some other
    way. A no-op when restoring back onto the same domain it was backed
    up from (the common case); only restoring under a different
    domain -- a fresh target_domain, or an existing tenant with a
    different live domain than the snapshot -- needs the rename."""
    if old_domain == new_domain:
        return
    old_dir = mail_host_path / old_domain
    if not old_dir.exists():
        return
    new_dir = mail_host_path / new_domain
    if new_dir.exists():
        shutil.rmtree(new_dir)
    old_dir.rename(new_dir)


def _dump_database(client, tenant: registry.Tenant, dest_file: Path) -> None:
    """A LOGICAL dump (mariadb-dump --single-transaction), not a raw
    datadir copy -- a live datadir snapshot isn't guaranteed consistent,
    a transactional dump is. Streamed via the low-level exec API with
    demux=True (stdout/stderr properly separated) straight into a local
    gzip file, rather than buffering the whole dump in process memory
    the way the high-level Container.exec_run does by default."""
    exec_id = client.api.exec_create(
        tenant.db_container,
        ["mariadb-dump", "-uroot", f"-p{tenant.db_root_password}",
         "--single-transaction", tenant.db_name],
    )["Id"]
    stream = client.api.exec_start(exec_id, stream=True, demux=True)
    with gzip.open(dest_file, "wb") as f:
        for stdout_chunk, _stderr_chunk in stream:
            if stdout_chunk:
                f.write(stdout_chunk)
    exit_code = client.api.exec_inspect(exec_id)["ExitCode"]
    if exit_code != 0:
        raise BackupError(f"mariadb-dump failed for {tenant.domain} (exit {exit_code})")


def _wait_for_db(client, container_name: str, root_password: str, timeout: int = 60) -> None:
    """A single successful ping isn't enough: the official MariaDB image
    runs a temporary, bootstrap-only mysqld instance to apply init
    scripts, then shuts it down and starts the real one. This function
    used to require just two consecutive successful pings, one second
    apart, on the theory that the bootstrap instance would be gone by
    the second check -- verified directly (real backup/restore run, not
    just reading the code) that this ISN'T reliable: the bootstrap
    instance's own window turned out to be ~2 seconds end to end in
    practice, easily long enough to produce two consecutive pings within
    it, and there's also a further multi-second gap between the
    bootstrap instance shutting down and the real one becoming ready
    where NEITHER answers -- landing the caller's restore import inside
    that gap raises a much more confusing "can't connect to socket" (or,
    seen in a separate run, a TLS-flavored broken-pipe from the client
    library giving up mid-handshake) instead of a clean, obvious
    connection-refused. Now requires three consecutive successes, two
    seconds apart -- a ~4-6 second continuous-uptime requirement that
    comfortably exceeds the observed bootstrap window while adding
    little latency to the common case (the real server, once up, stays
    up and answers every check)."""
    deadline = time.time() + timeout
    consecutive_ok = 0
    while time.time() < deadline:
        try:
            container = client.containers.get(container_name)
            exit_code, _ = container.exec_run(["mariadb-admin", "ping", "-uroot", f"-p{root_password}"])
            if exit_code == 0:
                consecutive_ok += 1
                if consecutive_ok >= 3:
                    return
            else:
                consecutive_ok = 0
        except NotFound:
            consecutive_ok = 0
        time.sleep(2)
    raise BackupError(f"timed out waiting for {container_name} to accept connections")


def _restore_database(client, db_container: str, db_name: str, db_root_password: str, dump_gz_path: Path) -> None:
    with gzip.open(dump_gz_path, "rb") as f:
        sql_bytes = f.read()
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo(name="restore.sql")
        info.size = len(sql_bytes)
        tf.addfile(info, io.BytesIO(sql_bytes))
    tar_buf.seek(0)
    container = client.containers.get(db_container)
    container.put_archive("/tmp", tar_buf.read())
    exit_code, output = container.exec_run(
        ["sh", "-c", f"mariadb -uroot -p{db_root_password} {db_name} < /tmp/restore.sql && rm -f /tmp/restore.sql"]
    )
    if exit_code != 0:
        raise BackupError(f"database restore failed: {output.decode(errors='replace')}")


# --- building & pushing a snapshot -----------------------------------------

def _build_snapshot_tar(tenant: registry.Tenant, workdir: Path) -> Path:
    """webroot/mail/phpconf tarred directly off their already-host-side
    *_host_path (no docker exec needed for these three); db via
    _dump_database. Bundles manifest + signature + all four pre-
    compressed components into ONE outer, uncompressed snapshot.tar --
    this is what gets age-encrypted as a unit when encryption applies,
    reconciling "compress each component before encrypting" with "one
    file per snapshot on the destination"."""
    client = provisioner._client()
    components = {}

    webroot_tgz = workdir / "webroot.tar.gz"
    _tar_directory(Path(tenant.webroot_host_path), webroot_tgz)
    components["webroot.tar.gz"] = webroot_tgz

    mail_tgz = workdir / "mail.tar.gz"
    _tar_directory(Path(tenant.mail_host_path), mail_tgz)
    components["mail.tar.gz"] = mail_tgz

    phpconf_tgz = workdir / "phpconf.tar.gz"
    _tar_directory(Path(tenant.phpconf_host_path), phpconf_tgz)
    components["phpconf.tar.gz"] = phpconf_tgz

    db_gz = workdir / "db.sql.gz"
    _dump_database(client, tenant, db_gz)
    components["db.sql.gz"] = db_gz

    manifest = _build_manifest(tenant, components)
    manifest_path = workdir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    with _decrypted_key_file(BACKUP_OPERATOR_SIGNING_KEY_PATH) as tmp_signing_key:
        sig_path = _sign_manifest(manifest_path, tmp_signing_key)

    snapshot_path = workdir / "snapshot.tar"
    with tarfile.open(snapshot_path, "w") as tf:
        tf.add(manifest_path, arcname="manifest.json")
        tf.add(sig_path, arcname="manifest.json.sig")
        for name, path in components.items():
            tf.add(path, arcname=name)
    return snapshot_path


def create_backup(domain: str, actor: str = "cli") -> list[registry.Backup]:
    """Builds one snapshot, always pushes an operator-encrypted copy to
    the shared operator destination (no opt-out), and -- independently,
    IN ADDITION to that, never instead of it -- pushes a second copy to
    the tenant's own destination if tenant.backup_dest_host is set
    (encrypted only if tenant.backup_encryption_enabled). Prunes each
    destination against its own retention count. Returns 1 or 2 rows."""
    tenant = registry.get_tenant(domain)
    if not tenant:
        raise BackupError(f"no active tenant for domain {domain!r}")
    if not BACKUP_OPERATOR_SFTP_HOST:
        raise BackupError(
            "operator backup destination isn't configured "
            "(VHSP_BACKUP_SFTP_HOST) -- refusing to run"
        )
    if not BACKUP_OPERATOR_SIGNING_KEY_PATH.exists():
        raise BackupError("operator backup keys aren't initialized -- run `vhsp backup init` first")

    workdir = BACKUP_WORKDIR / f"{tenant.slug}-{int(time.time())}"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_path = _build_snapshot_tar(tenant, workdir)
        manifest_sha = _sha256_file(workdir / "manifest.json")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results: list[registry.Backup] = []

        # Operator's shared destination -- ALWAYS, ALWAYS encrypted, no opt-out.
        op_encrypted = workdir / f"{timestamp}.tar.age"
        with _decrypted_key_file(BACKUP_OPERATOR_AGE_KEY_PATH) as tmp_age_key:
            op_recipient = _run(["age-keygen", "-y", str(tmp_age_key)]).stdout.decode().strip()
        _encrypt(snapshot_path, op_encrypted, op_recipient)
        op_remote_dir = f"{BACKUP_OPERATOR_SFTP_PATH.rstrip('/')}/{tenant.domain}"
        with _decrypted_key_file(BACKUP_OPERATOR_SSH_KEY_PATH) as tmp_ssh_key:
            _push_file(BACKUP_OPERATOR_SFTP_HOST, BACKUP_OPERATOR_SFTP_PORT, BACKUP_OPERATOR_SFTP_USER,
                       tmp_ssh_key, op_encrypted, op_remote_dir)
        op_record = registry.Backup(
            tenant_domain=tenant.domain, tenant_slug=tenant.slug, created_at=registry.now(),
            destination="operator", dest_host=BACKUP_OPERATOR_SFTP_HOST,
            dest_path=f"{op_remote_dir}/{op_encrypted.name}",
            size_bytes=op_encrypted.stat().st_size, encrypted=True, manifest_sha256=manifest_sha,
        )
        registry.add_backup_record(op_record)
        results.append(op_record)

        retention = tenant.backup_retention_count or DEFAULT_BACKUP_RETENTION_COUNT
        stale_operator = registry.prune_old_backups(tenant.domain, "operator", retention)
        if stale_operator:
            with _decrypted_key_file(BACKUP_OPERATOR_SSH_KEY_PATH) as tmp_ssh_key:
                for stale in stale_operator:
                    _remote_rm(BACKUP_OPERATOR_SFTP_HOST, BACKUP_OPERATOR_SFTP_PORT, BACKUP_OPERATOR_SFTP_USER,
                              tmp_ssh_key, stale.dest_path)

        # Tenant's own additional destination, if configured.
        if tenant.backup_dest_host:
            if tenant.backup_encryption_enabled and tenant.backup_age_key_path:
                with _decrypted_key_file(Path(tenant.backup_age_key_path)) as tmp_age_key:
                    tenant_pub = _run(["age-keygen", "-y", str(tmp_age_key)]).stdout.decode().strip()
                tenant_file = workdir / f"{timestamp}-tenant.tar.age"
                _encrypt(snapshot_path, tenant_file, tenant_pub)
                tenant_encrypted = True
            else:
                tenant_file = workdir / f"{timestamp}-tenant.tar"
                shutil.copyfile(snapshot_path, tenant_file)
                tenant_encrypted = False

            t_remote_dir = f"{tenant.backup_dest_path.rstrip('/') or '/backup'}/{tenant.domain}"
            with _decrypted_key_file(Path(tenant.backup_ssh_key_path)) as tmp_ssh_key:
                _push_file(tenant.backup_dest_host, tenant.backup_dest_port, tenant.backup_dest_user,
                          tmp_ssh_key, tenant_file, t_remote_dir)
            t_record = registry.Backup(
                tenant_domain=tenant.domain, tenant_slug=tenant.slug, created_at=registry.now(),
                destination="tenant", dest_host=tenant.backup_dest_host,
                dest_path=f"{t_remote_dir}/{tenant_file.name}",
                size_bytes=tenant_file.stat().st_size, encrypted=tenant_encrypted,
                manifest_sha256=manifest_sha,
            )
            registry.add_backup_record(t_record)
            results.append(t_record)

            t_retention = tenant.backup_retention_count or DEFAULT_BACKUP_RETENTION_COUNT
            stale_tenant = registry.prune_old_backups(tenant.domain, "tenant", t_retention)
            if stale_tenant:
                with _decrypted_key_file(Path(tenant.backup_ssh_key_path)) as tmp_ssh_key:
                    for stale in stale_tenant:
                        _remote_rm(tenant.backup_dest_host, tenant.backup_dest_port, tenant.backup_dest_user,
                                  tmp_ssh_key, stale.dest_path)

        audit.log_action("backup.create", domain, actor)
        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def is_backup_due(tenant: registry.Tenant) -> bool:
    interval = tenant.backup_interval or DEFAULT_BACKUP_INTERVAL
    existing = registry.list_backups(tenant.domain, destination="operator")
    if not existing:
        return True
    last = datetime.fromisoformat(existing[0].created_at)
    return datetime.now(timezone.utc) - last >= timedelta(days=BACKUP_INTERVAL_DAYS[interval])


def run_all_due_backups(actor: str = "scheduler") -> dict[str, str]:
    """`vhsp backup run-all`, the daily systemd timer's entry point. One
    tenant's failure (DB container down, etc.) must not abort the sweep
    for everyone else -- each domain gets its own try/except."""
    results: dict[str, str] = {}
    for tenant in registry.list_tenants():
        if not is_backup_due(tenant):
            continue
        try:
            create_backup(tenant.domain, actor=actor)
            results[tenant.domain] = "ok"
        except Exception as e:
            # Not just BackupError: a stopped DB container surfaces as a raw
            # docker.errors.APIError out of _dump_database (exec_create
            # against a non-running container), not something this module
            # wraps itself -- verified directly, this used to escape here
            # and abort the whole sweep after the first such tenant, which
            # is exactly the failure mode this function exists to prevent.
            results[tenant.domain] = f"error: {e}"
    return results


def ship_audit_log(actor: str = "scheduler") -> int:
    """Ships whatever's new in audit.py's local, append-only log
    (`audit.AUDIT_LOG_PATH`) to the SAME operator SFTP destination
    tenant backups already use, rather than standing up a second one --
    that destination already exists specifically to survive this host
    being compromised, which is the exact threat model architecture.md's
    control-plane-auth section calls out for the audit trail too ("the
    trail needs to survive even if the control plane itself is later
    compromised"). audit.py's own docstring used to note this half
    wasn't built; this closes that gap.

    Host-wide, not per-tenant -- one shot, not a loop over registry.list_tenants()
    like run_all_due_backups. Each run pushes only the bytes appended
    since the last successful ship, as a new small timestamped file under
    a dedicated `_operator-audit/` remote directory (leading underscore
    so it can't collide with an actual tenant domain) -- not a
    continuously-appended remote file, which would need remote-side
    locking this module has no other reason to implement. Many small
    files replay in filename order just as well as one big one.

    Progress is tracked in AUDIT_SHIP_STATE_PATH (a byte offset into the
    local log, not a registry row -- host-wide single value, same shape
    as auth.py's own SECRET_KEY_PATH). The offset only advances on a
    *successful* push, so a failed run retries the same range next time
    rather than silently dropping it; at worst that means the exact same
    bytes get shipped twice across two remote files, which is a
    harmless, easily-deduplicated-on-read overlap, not data loss.

    Deliberately does NOT sign each chunk the way backup snapshots are
    signed -- that defends against a *destination* compromise (someone
    with SFTP access forging history), a real but different concern from
    this function's actual job (surviving a *source*/host compromise).
    Off-host storage alone already solves the job this was built for;
    remote-tamper-detection for the audit trail specifically is a
    separate, not-yet-built increment, not silently assumed to be covered.

    Deliberately does not call audit.log_action on itself -- a log entry
    that exists only to record its own prior shipment doesn't carry
    information forward, it just grows the log as a side effect of
    shrinking the unshipped backlog.
    """
    if not BACKUP_OPERATOR_SFTP_HOST:
        raise BackupError(
            "operator backup destination isn't configured "
            "(VHSP_BACKUP_SFTP_HOST) -- refusing to run"
        )
    if not BACKUP_OPERATOR_SIGNING_KEY_PATH.exists():
        raise BackupError("operator backup keys aren't initialized -- run `vhsp backup init` first")

    if not audit.AUDIT_LOG_PATH.exists():
        return 0

    shipped_bytes = 0
    if AUDIT_SHIP_STATE_PATH.exists():
        shipped_bytes = json.loads(AUDIT_SHIP_STATE_PATH.read_text()).get("shipped_bytes", 0)

    current_size = audit.AUDIT_LOG_PATH.stat().st_size
    if current_size < shipped_bytes:
        # The local log is SMALLER than what we thought we'd already
        # shipped -- it was rotated/truncated out from under us (not
        # something this codebase does today, but cheap to not assume
        # away). Ship the whole current file fresh rather than silently
        # going quiet forever because the offset no longer makes sense.
        shipped_bytes = 0
    if current_size <= shipped_bytes:
        return 0

    with open(audit.AUDIT_LOG_PATH, "rb") as f:
        f.seek(shipped_bytes)
        new_bytes = f.read()

    workdir = BACKUP_WORKDIR / f"audit-ship-{int(time.time())}"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        chunk_path = workdir / f"{timestamp}.log"
        chunk_path.write_bytes(new_bytes)
        remote_dir = f"{BACKUP_OPERATOR_SFTP_PATH.rstrip('/')}/_operator-audit"
        with _decrypted_key_file(BACKUP_OPERATOR_SSH_KEY_PATH) as tmp_ssh_key:
            _push_file(BACKUP_OPERATOR_SFTP_HOST, BACKUP_OPERATOR_SFTP_PORT, BACKUP_OPERATOR_SFTP_USER,
                       tmp_ssh_key, chunk_path, remote_dir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    AUDIT_SHIP_STATE_PATH.write_text(json.dumps({"shipped_bytes": current_size}))
    return len(new_bytes)


# --- restore ---------------------------------------------------------------

@contextmanager
def _dest_identity(source: str, tenant: registry.Tenant | None):
    """Yields (host, port, user, decrypted_tmp_key_path) -- a context
    manager rather than a plain lookup because every one of this
    function's three callers immediately uses the returned key for
    exactly one ssh/scp subprocess call, so staging its plaintext for
    just that scope (see _decrypted_key_file) belongs here once instead
    of being duplicated at each call site."""
    if source == "operator":
        host, port, user = BACKUP_OPERATOR_SFTP_HOST, BACKUP_OPERATOR_SFTP_PORT, BACKUP_OPERATOR_SFTP_USER
        key_path = BACKUP_OPERATOR_SSH_KEY_PATH
    else:
        if not tenant or not tenant.backup_dest_host:
            raise BackupError("no tenant-configured backup destination for this domain")
        host, port, user = tenant.backup_dest_host, tenant.backup_dest_port, tenant.backup_dest_user
        key_path = Path(tenant.backup_ssh_key_path)
    with _decrypted_key_file(key_path) as tmp_key:
        yield host, port, user, tmp_key


def list_remote_domains(source: str = "operator", tenant: registry.Tenant | None = None) -> list[str]:
    with _dest_identity(source, tenant) as (host, port, user, key):
        base = BACKUP_OPERATOR_SFTP_PATH if source == "operator" else (tenant.backup_dest_path or "/backup")
        return _list_remote_dirs(host, port, user, key, base)


def list_remote_snapshots(domain: str, source: str = "operator", tenant: registry.Tenant | None = None) -> list[str]:
    with _dest_identity(source, tenant) as (host, port, user, key):
        base = BACKUP_OPERATOR_SFTP_PATH if source == "operator" else (tenant.backup_dest_path or "/backup")
        return _list_remote_files(host, port, user, key, f"{base.rstrip('/')}/{domain}")


def snapshot_taken_at(snapshot_name: str) -> str | None:
    """The UTC timestamp encoded in a snapshot's own filename
    (20260724T184505Z.tar.age -> ISO 8601), or None if it doesn't parse.

    Read from the name rather than the file's remote mtime or the
    registry's created_at: the name is assigned at capture time by
    _build_snapshot_tar and travels with the file, so it stays correct
    for a snapshot copied between hosts (which resets mtime) or one with
    no registry row at all.
    """
    stem = snapshot_name.split(".")[0]
    try:
        return datetime.strptime(stem, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def list_remote_snapshots_detailed(
    domain: str, source: str = "operator", tenant: registry.Tenant | None = None,
) -> list[dict]:
    """[{name, size_bytes, taken_at}] newest first -- the name-only
    listing above plus real remote size and the capture time decoded from
    each name. Same single SSH round trip as list_remote_snapshots().
    """
    with _dest_identity(source, tenant) as (host, port, user, key):
        base = BACKUP_OPERATOR_SFTP_PATH if source == "operator" else (tenant.backup_dest_path or "/backup")
        rows = _list_remote_files_detailed(host, port, user, key, f"{base.rstrip('/')}/{domain}")
    for r in rows:
        r["taken_at"] = snapshot_taken_at(r["name"])
    return rows


def _fetch_and_verify(
    domain: str, snapshot_name: str, source: str, tenant: registry.Tenant | None, workdir: Path,
) -> tuple[dict, Path]:
    """Shared fetch/verify step for restore_backup: fetch, decrypt if the
    name ends .age, extract, verify signature (hard fail, no bypass flag
    exists in this function's own signature on purpose). Returns
    (manifest_dict, extract_dir)."""
    fetched = workdir / snapshot_name
    with _dest_identity(source, tenant) as (host, port, user, key):
        base = BACKUP_OPERATOR_SFTP_PATH if source == "operator" else (tenant.backup_dest_path or "/backup")
        remote_path = f"{base.rstrip('/')}/{domain}/{snapshot_name}"
        _fetch_file(host, port, user, key, remote_path, fetched)

    if fetched.suffix == ".age":
        age_key_path = BACKUP_OPERATOR_AGE_KEY_PATH if source == "operator" else Path(tenant.backup_age_key_path)
        if source == "tenant" and not tenant.backup_age_key_path:
            raise BackupError("this backup is encrypted but no decryption key is on file for this tenant")
        snapshot_tar = workdir / "snapshot.tar"
        with _decrypted_key_file(age_key_path) as tmp_age_key:
            _decrypt(fetched, snapshot_tar, tmp_age_key)
    else:
        snapshot_tar = fetched

    extract_dir = workdir / "extracted"
    extract_dir.mkdir()
    with tarfile.open(snapshot_tar, "r") as tf:
        tf.extractall(extract_dir, filter="data")

    with _decrypted_key_file(BACKUP_OPERATOR_SIGNING_KEY_PATH) as tmp_signing_key:
        signing_public_key = _run(["ssh-keygen", "-y", "-f", str(tmp_signing_key)]).stdout.decode().strip()
    _verify_manifest_signature(extract_dir / "manifest.json", extract_dir / "manifest.json.sig", signing_public_key)

    manifest = json.loads((extract_dir / "manifest.json").read_text())
    return manifest, extract_dir


def restore_backup(
    domain: str, snapshot_name: str, *, source: str = "operator",
    target_domain: str | None = None, actor: str = "cli",
) -> registry.Tenant:
    """source="operator": always uses the operator's own shared
    destination/keys, callable by an operator for ANY domain regardless
    of whether it currently exists here. source="tenant": uses
    registry.get_tenant(domain)'s OWN backup_dest_*/backup_age_key_path
    -- self-service restore, gated by the exact same mandatory
    signature check as the operator path, no separate/weaker route.

    target_domain defaults to `domain` (restore in place). If no tenant
    currently exists for target_domain (destroyed here, or a fresh/
    different deployment entirely), recreates it from scratch. If one
    does, restores content into it in place, leaving its current
    WebAuthn credentials (if any) completely untouched.
    """
    target_domain = target_domain or domain
    calling_tenant = registry.get_tenant(domain) if source == "tenant" else None
    if source == "tenant" and not calling_tenant:
        raise BackupError(f"no active tenant for domain {domain!r} to restore from")

    workdir = BACKUP_WORKDIR / f"restore-{int(time.time())}"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        manifest, extract_dir = _fetch_and_verify(domain, snapshot_name, source, calling_tenant, workdir)

        existing = registry.get_tenant(target_domain)
        if existing:
            _restore_into_existing_tenant(existing, manifest, extract_dir)
            result = existing
        else:
            result = _restore_as_new_tenant(target_domain, manifest, extract_dir)

        audit.log_action("backup.restore", target_domain, actor)
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _restore_as_new_tenant(target_domain: str, manifest: dict, extract_dir: Path) -> registry.Tenant:
    """Re-provisions a tenant from a backup's manifest + extracted
    components, reusing provisioner.py's own private helpers directly --
    same "same package, same trust level" reasoning web.py already
    applies importing toggles.py's internals. WebAuthn is never written
    here at all (it was never collected into the backup in the first
    place) -- that absence alone is what makes the restored tenant
    password-only; nothing further needs to enforce it.
    """
    if registry.get_tenant_any_status(target_domain) and registry.get_tenant(target_domain):
        raise BackupError(f"tenant for domain {target_domain!r} already exists -- restore in place instead")

    slug = provisioner.slugify(target_domain)
    client = provisioner._client()
    provisioner._ensure_gateway_network(client)

    ssh_port = manifest["sftp_port"]
    if ssh_port in registry.used_ssh_ports():
        ssh_port = provisioner._allocate_ssh_port()

    volume_name, host_path = provisioner._create_hardened_volume(client, slug, "webroot")
    _extract_component(extract_dir / "webroot.tar.gz", Path(host_path))

    db_network = provisioner._create_db_network(client, slug)
    db_container_name, db_volume_name, db_host_path = provisioner._create_db_container(
        client, slug, db_network, manifest["db_name"], manifest["db_user"],
        manifest["db_password"], manifest["db_root_password"],
    )

    phpconf_volume, phpconf_host_path = provisioner._create_hardened_volume(client, slug, "phpconf")
    _extract_component(extract_dir / "phpconf.tar.gz", Path(phpconf_host_path))
    logs_volume, logs_host_path = provisioner._create_hardened_volume(client, slug, "logs")

    _wait_for_db(client, db_container_name, manifest["db_root_password"])
    _restore_database(client, db_container_name, manifest["db_name"], manifest["db_root_password"], extract_dir / "db.sql.gz")

    container_name = f"vhsp-{slug}-web"
    router_id = f"vhsp-{slug}"
    web_container = client.containers.run(
        DEFAULT_WEB_IMAGE, name=container_name, detach=True,
        restart_policy={"Name": "unless-stopped"}, network=GATEWAY_NETWORK,
        volumes={
            volume_name: {"bind": WEB_DOCUMENT_ROOT, "mode": "ro"},
            phpconf_volume: {"bind": "/data", "mode": "ro"},
            logs_volume: {"bind": "/var/log/vhsp", "mode": "rw"},
        },
        environment={
            "DB_HOST": db_container_name, "DB_PORT": str(DB_INTERNAL_PORT),
            "DB_NAME": manifest["db_name"], "DB_USER": manifest["db_user"], "DB_PASSWORD": manifest["db_password"],
            "VHSP_TRUSTED_PROXY_CIDRS": WEB_TRUSTED_PROXY_CIDRS,
        },
        labels={
            "traefik.enable": "true",
            f"traefik.http.routers.{router_id}.rule": f"Host(`{target_domain}`)",
            f"traefik.http.routers.{router_id}.entrypoints": "web",
            f"traefik.http.services.{router_id}.loadbalancer.server.port": "80",
            "vhsp.tenant.slug": slug, "vhsp.tenant.domain": target_domain,
        },
    )
    client.networks.get(db_network).connect(web_container)

    sftp_container_name, ssh_keys_volume, ssh_keys_host_path = provisioner._create_sftp_container(
        client, slug, ssh_port, volume_name, manifest["sftp_user"], logs_volume,
    )
    if manifest.get("ssh_public_key"):
        (Path(ssh_keys_host_path) / "admin.pub").write_text(manifest["ssh_public_key"].strip() + "\n")
        client.containers.get(sftp_container_name).remove(force=True)
        provisioner._create_sftp_container(
            client, slug, ssh_port, volume_name, manifest["sftp_user"], logs_volume, ssh_keys_volume,
        )

    # Extracted into the volume's host path BEFORE the mail container
    # exists, not after -- see _create_mail_container's own docstring on
    # why (its entrypoint chowns everything under /var/mail/vhosts to its
    # internal vmail uid on first start, which would otherwise lock this
    # unprivileged process out of writing there afterward).
    mail_volume, mail_host_path = provisioner._create_hardened_volume(client, slug, "mail")
    _extract_component(extract_dir / "mail.tar.gz", Path(mail_host_path))
    _relocate_mail_domain_dir(Path(mail_host_path), manifest["domain"], target_domain)
    mail_container_name, mail_volume, mail_host_path, mail_hostname = provisioner._create_mail_container(
        client, slug, target_domain, manifest["mail_user"], manifest["mail_password"],
        logs_volume, phpconf_volume, phpconf_host_path,
        mail_volume=mail_volume, mail_host_path=mail_host_path,
    )

    tenant_admin_container, admin_hostname, _generated_password = provisioner._create_tenant_admin_container(
        client, slug, target_domain, phpconf_volume, phpconf_host_path, logs_volume, volume_name,
        db_network, db_container_name, manifest["db_name"], manifest["db_user"], manifest["db_password"], mail_volume,
        ssh_port, manifest["sftp_user"],
    )

    tenant = registry.Tenant(
        slug=slug, domain=target_domain, ssh_port=ssh_port, web_container=container_name,
        db_network=db_network, webroot_volume=volume_name, webroot_host_path=host_path,
        db_container=db_container_name, db_volume=db_volume_name, db_host_path=db_host_path,
        db_name=manifest["db_name"], db_user=manifest["db_user"], db_password=manifest["db_password"],
        db_root_password=manifest["db_root_password"], sftp_container=sftp_container_name,
        sftp_user=manifest["sftp_user"], ssh_keys_volume=ssh_keys_volume, ssh_keys_host_path=ssh_keys_host_path,
        mail_container=mail_container_name, mail_volume=mail_volume, mail_host_path=mail_host_path,
        mail_hostname=mail_hostname, mail_user=manifest["mail_user"], mail_password=manifest["mail_password"],
        tenant_admin_container=tenant_admin_container, phpconf_volume=phpconf_volume,
        phpconf_host_path=phpconf_host_path, admin_hostname=admin_hostname, logs_volume=logs_volume,
        logs_host_path=logs_host_path, tenant_admin_password=manifest["tenant_admin_password"],
        status="active", created_at=registry.now(),
        ssh_public_key=manifest.get("ssh_public_key", ""), ssh_key_fingerprint=manifest.get("ssh_key_fingerprint", ""),
    )
    registry.add_tenant(tenant)
    provisioner._export_routing_table()
    provisioner._ensure_mail_gateway(client)
    provisioner._regenerate_mail_gateway_maps(client)
    provisioner._regenerate_roundcube_routes(client)
    return tenant


def _restore_into_existing_tenant(tenant: registry.Tenant, manifest: dict, extract_dir: Path) -> None:
    """Overwrites webroot/mail/phpconf/db IN PLACE; the tenant's own
    registry row (credentials, container/volume names, ports) is
    untouched -- only data changes. webauthn_credentials.json is saved
    before phpconf gets wiped and written back verbatim afterward (or
    left absent if it wasn't there before) -- an existing tenant's
    current security keys must survive a content-only restore exactly
    as required; the backup itself never contains that file at all.
    """
    live_webauthn = Path(tenant.phpconf_host_path) / "webauthn_credentials.json"
    saved = live_webauthn.read_bytes() if live_webauthn.exists() else None

    for host_path, component in (
        (tenant.webroot_host_path, "webroot.tar.gz"),
        (tenant.mail_host_path, "mail.tar.gz"),
        (tenant.phpconf_host_path, "phpconf.tar.gz"),
    ):
        # sudo find -delete + chown, not shutil.rmtree/rm -rf on host_path
        # itself: by the time an EXISTING tenant is being restored into,
        # its running containers have already chowned parts of these
        # directories to their own internal uids (mail's entrypoint
        # chowns the whole maildir to vmail; an SFTP upload lands owned
        # by atmoz/sftp's internal per-tenant user) -- this unprivileged
        # process can't clear those itself, same "sudo is the pragmatic
        # stand-in for host-level privileged cleanup" reasoning
        # _remove_host_dir already established. Crucially, though,
        # host_path itself is a noexec/nosuid/nodev-hardened bind mount
        # (verified directly: `rm -rf` on the mountpoint itself fails
        # with "Device or resource busy") -- only its *contents* can be
        # removed this way, the mount has to stay intact. A container's
        # chown -R (mail's entrypoint is the known case) walks into
        # host_path itself, not just what's under it, so clearing the
        # contents alone leaves the directory *inode* still owned by
        # that container's internal uid -- reclaiming ownership of the
        # directory itself is needed too, before extracting into it;
        # whichever container needs its own uid back on the contents
        # re-chowns on restart (done for mail below).
        #
        # Goes through deploy/vhsp-restore-clean, a root-owned wrapper
        # script that validates its own arguments and does both steps
        # internally, rather than two raw `sudo find`/`sudo chown` calls
        # -- same "scoped sudoers, no wildcarded Cmnd_Alias" reasoning as
        # _tar_directory's own vhsp-backup-tar wrapper above.
        slug, purpose = provisioner._split_tenant_host_path(host_path)
        provisioner._run("sudo", "/usr/local/sbin/vhsp-restore-clean", slug, purpose)
        _extract_component(extract_dir / component, Path(host_path))
        if component == "mail.tar.gz":
            _relocate_mail_domain_dir(Path(host_path), manifest["domain"], tenant.domain)

    if saved is not None:
        live_webauthn.write_bytes(saved)
    else:
        live_webauthn.unlink(missing_ok=True)

    client = provisioner._client()
    _restore_database(client, tenant.db_container, tenant.db_name, tenant.db_root_password, extract_dir / "db.sql.gz")

    # The mail container's entrypoint unconditionally chowns the whole
    # maildir to its internal vmail uid on every start (not just first
    # boot) -- restarting it re-applies that ownership to the just-
    # extracted files (which land owned by this process's own uid
    # otherwise, since the extraction above isn't running as vmail).
    try:
        client.containers.get(tenant.mail_container).restart(timeout=10)
    except NotFound:
        pass
    # No restart needed for web/phpconf: the web container's own 3-second
    # phpconf poll loop (images/web/entrypoint.sh) picks up restored
    # toggles/mailboxes automatically, and webroot is a live bind mount.
    # and webroot is a live bind mount.


# --- tenant self-service reconciliation (host-side timer, ~2 min) ---------

def _tenant_backup_request_file(tenant: registry.Tenant) -> Path:
    return Path(tenant.phpconf_host_path) / "backup_request.json"


def _tenant_backup_status_file(tenant: registry.Tenant) -> Path:
    return Path(tenant.phpconf_host_path) / "backup_status.json"


def _tenant_backup_now_marker(tenant: registry.Tenant) -> Path:
    return Path(tenant.phpconf_host_path) / ".vhsp-backup-now"


def _reconcile_tenant_backup_config(tenant: registry.Tenant, req: dict) -> None:
    encryption = req.get("encryption", "none")
    age_key_path = tenant.backup_age_key_path
    age_public_key = tenant.backup_age_public_key
    if encryption == "generate" and not age_key_path:
        path, pub, _first_reveal = ensure_tenant_age_key(tenant.slug)
        age_key_path, age_public_key = str(path), pub
    elif encryption == "own" and req.get("own_age_private_key"):
        path, pub, _first_reveal = ensure_tenant_age_key(tenant.slug, own_private_key=req["own_age_private_key"])
        age_key_path, age_public_key = str(path), pub

    ssh_key_path = tenant.backup_ssh_key_path
    ssh_public_key = tenant.backup_ssh_public_key
    if req.get("dest_host") and not ssh_key_path:
        path, pub = ensure_tenant_ssh_key(tenant.slug)
        ssh_key_path, ssh_public_key = str(path), pub

    registry.set_backup_settings(
        tenant.domain,
        retention_count=tenant.backup_retention_count, interval=tenant.backup_interval,
        dest_host=req.get("dest_host", ""), dest_port=int(req.get("dest_port") or 22),
        dest_path=req.get("dest_path", ""), dest_user=req.get("dest_user", ""),
        encryption_enabled=(encryption != "none"),
    )
    registry.set_backup_tenant_keys(
        tenant.domain, age_key_path=age_key_path, age_public_key=age_public_key,
        ssh_key_path=ssh_key_path, ssh_public_key=ssh_public_key,
    )

    # Scrub any private key material the tenant pasted in back out of the
    # shared-volume request file immediately -- it's already relocated to
    # a host-only file by ensure_tenant_age_key above, it shouldn't also
    # keep lingering in phpconf's plaintext request file any longer than
    # this one reconciliation pass needs it.
    if req.get("own_age_private_key"):
        req = {**req, "own_age_private_key": ""}
        _tenant_backup_request_file(tenant).write_text(json.dumps(req))


def _write_backup_status(tenant: registry.Tenant, age_first_reveal: str | None = None) -> None:
    recent = registry.list_backups(tenant.domain, destination="tenant")[:10]
    status = {
        "ssh_public_key": tenant.backup_ssh_public_key,
        "encryption_enabled": tenant.backup_encryption_enabled,
        # Mirrors the tenant's own current destination settings back --
        # tenant-admin has no registry access of its own (see this module's
        # docstring / architecture.md), so this file is the only way its
        # settings form can pre-fill current values or preserve them across
        # an unrelated submission (e.g. a restore request) without
        # clobbering them the next time _reconcile_tenant_backup_config runs.
        "dest_host": tenant.backup_dest_host,
        "dest_port": tenant.backup_dest_port,
        "dest_path": tenant.backup_dest_path,
        "dest_user": tenant.backup_dest_user,
        "recent_backups": [
            {"created_at": b.created_at, "size_bytes": b.size_bytes, "encrypted": b.encrypted,
             "snapshot_name": b.dest_path.split("/")[-1]}
            for b in recent
        ],
    }
    if age_first_reveal:
        status["age_private_key_once"] = age_first_reveal
    _tenant_backup_status_file(tenant).write_text(json.dumps(status))


def process_requests(actor: str = "reconciler") -> None:
    """`vhsp backup process-requests`, the ~2-minute reconciler timer's
    entry point. Reads each active tenant's own backup_request.json (a
    file on the shared phpconf volume tenant-admin writes to -- that
    container has no docker/host access of its own, so it can never call
    anything in this module directly), applies config/key-generation
    changes, handles on-demand triggers, and refreshes backup_status.json
    for tenant-admin's own Backups page to display."""
    for tenant in registry.list_tenants():
        req_file = _tenant_backup_request_file(tenant)
        age_first_reveal = None
        if req_file.exists():
            req = json.loads(req_file.read_text())
            had_key = bool(tenant.backup_age_key_path)
            _reconcile_tenant_backup_config(tenant, req)
            tenant = registry.get_tenant(tenant.domain)
            if not had_key and tenant.backup_age_key_path:
                # Only the reconciliation pass that JUST generated the key
                # gets to reveal it -- every later pass's tenant.backup_age_key_path
                # is already non-empty, so this branch won't fire again.
                # secretbox.decrypt(): the file holds ciphertext at rest
                # now (see _write_encrypted_key) -- a raw .read_text()
                # here would return the enc1:... wrapper instead of the
                # real key text, silently breaking the "AGE-SECRET-KEY-"
                # substring check below on every run.
                key_text = secretbox.decrypt(Path(tenant.backup_age_key_path).read_text())
                # Not .startswith(): age-keygen -o always writes a couple of
                # leading `# created:`/`# public key:` comment lines before
                # the actual AGE-SECRET-KEY-1... line -- verified directly,
                # a startswith check here never matches a freshly-generated
                # key's file at all, silently skipping the one-time reveal
                # every time. A tenant-pasted own_private_key (no comment
                # header) still matches fine either way.
                if "AGE-SECRET-KEY-" in key_text:
                    age_first_reveal = key_text

            if req.get("action") == "restore_requested" and req.get("restore_snapshot"):
                # Broad except, not just BackupError: a raw docker/SSH
                # exception here must not propagate either -- this loop
                # covers every tenant, same "one tenant's failure can't take
                # the whole pass down" resilience run_all_due_backups needs
                # (see its own comment for the concrete failure that was
                # actually observed escaping a narrower except here).
                try:
                    restore_backup(tenant.domain, req["restore_snapshot"], source="tenant", actor=actor)
                except Exception:
                    pass  # not surfaced anywhere yet -- self-service restore failures are a known UI gap
                remaining = {k: v for k, v in req.items() if k not in ("action", "restore_snapshot")}
                req_file.write_text(json.dumps(remaining))

        marker = _tenant_backup_now_marker(tenant)
        if marker.exists():
            marker.unlink()
            try:
                create_backup(tenant.domain, actor=actor)
            except Exception:
                pass

        if tenant.backup_dest_host:
            _write_backup_status(tenant, age_first_reveal)
