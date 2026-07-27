#!/bin/bash
set -euo pipefail

: "${MAIL_DOMAIN:?MAIL_DOMAIN required}"
: "${DKIM_SELECTOR:=vhsp1}"

MAILBOXES_FILE=/data/mailboxes.txt
# Presence alone is the toggle -- same marker-file convention as
# images/web/'s own .vhsp-no-404-fallback. Set by the operator only (see
# vhsp_ctl/provisioner.py's set_tenant_maintenance_mode) -- tenant-admin
# has no route that ever writes this file, by design: the whole point is
# an operator-only hold (e.g. a lapsed bill) the tenant can't self-service
# lift. Deliberately does NOT touch inbound port-25 delivery at all (see
# write_dovecot_conf below) -- losing/bouncing inbound mail during a
# maintenance hold would be worse than the hold itself, and the user was
# explicit that only outbound access (IMAP login, authenticated submission)
# should be blocked.
MAINTENANCE_MARKER=/data/.vhsp-maintenance

if ! getent group vmail >/dev/null; then
    groupadd -g 5000 vmail
fi
if ! getent passwd vmail >/dev/null; then
    useradd -u 5000 -g vmail -d /var/mail/vhosts -s /usr/sbin/nologin vmail
fi
# Dovecot/LMTP create each mailbox's own maildir under here automatically
# on first login/delivery -- only the domain directory itself needs to
# pre-exist and be writable by vmail.
mkdir -p "/var/mail/vhosts/$MAIL_DOMAIN"
chown -R vmail:vmail /var/mail/vhosts

mkdir -p /var/log/vhsp
chmod 1777 /var/log/vhsp
# Postfix/dovecot create mail.log with their own restrictive umask
# (verified: root:root 600) regardless of the directory's mode -- opening
# an *existing* file for append doesn't change its mode, so pre-creating
# it here with open permissions is what actually makes it readable from
# the tenant-admin container.
touch /var/log/vhsp/mail.log
chmod 666 /var/log/vhsp/mail.log

TLS_DIR=/etc/ssl/mail
mkdir -p "$TLS_DIR"
if [ ! -f "$TLS_DIR/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -subj "/CN=mail.$MAIL_DOMAIN"
fi

# --- DKIM: outbound signing only (Mode "s"), one keypair per domain -------
# Lives on its own bind-mounted volume (/etc/opendkim/keys, see
# provisioner.py's _create_mail_container), NOT the /var/mail/vhosts
# maildir volume -- that one gets chowned wholesale to vmail on every
# start (see _relocate_mail_domain_dir's docstring), which key material
# has no business being subject to. Generated once and left alone after
# that: regenerating would invalidate the DNS TXT record an operator has
# already published, so this only creates a key if one doesn't already
# exist on the volume, same "generate if missing, otherwise reuse"
# pattern as the TLS cert above.
DKIM_DIR="/etc/opendkim/keys/$MAIL_DOMAIN"
mkdir -p "$DKIM_DIR"
if [ ! -f "$DKIM_DIR/$DKIM_SELECTOR.private" ]; then
    opendkim-genkey -b 2048 -d "$MAIL_DOMAIN" -s "$DKIM_SELECTOR" -D "$DKIM_DIR"
fi
# opendkim refuses to start if ANY directory in the KeyFile's path chain
# -- including the bind-mounted volume root itself, not just the
# immediate parent -- is owned by a uid that's neither its own nor root's
# (verified directly: "is writeable and owned by uid 1000 ... not the
# executing uid (100) or the superuser", uid 1000 being astjohn, the host
# process that originally created the volume's host directory). Recurse
# from the mount root, not just $DKIM_DIR, to cover the whole chain.
chown -R opendkim:opendkim /etc/opendkim/keys
chmod 400 "$DKIM_DIR/$DKIM_SELECTOR.private"

mkdir -p /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim

cat > /etc/opendkim.conf <<EOF
Domain                  $MAIL_DOMAIN
Selector                $DKIM_SELECTOR
KeyFile                  $DKIM_DIR/$DKIM_SELECTOR.private
Mode                     s
Socket                   inet:8891@127.0.0.1
PidFile                  /var/run/opendkim/opendkim.pid
UserID                   opendkim
Syslog                   no
EOF

/usr/sbin/opendkim -x /etc/opendkim.conf

# --- Dovecot: IMAP + LMTP delivery + SASL auth backend for Postfix + Sieve ---
# "sieve" in protocols registers Pigeonhole's ManageSieve service (port
# 4190, script upload/activate -- e.g. Roundcube's filter UI) using
# Dovecot's own built-in default listener for that protocol, the same way
# "imap" alone already gets us both 143 and (via global ssl=yes) implicit
# TLS on 993 with no explicit service block needed.
#
# Regenerated (not just written once at boot) so the watcher loop below
# can flip the maintenance deny-passdb in and out without a container
# restart -- same "regenerate the whole file, then reload" shape as
# images/web/entrypoint.sh's write_tenant_nginx_conf.
write_dovecot_conf() {
    maintenance_passdb=""
    if [ -f "$MAINTENANCE_MARKER" ]; then
        # A deny passdb listed FIRST short-circuits auth for EVERY login
        # attempt before Dovecot ever consults the real passwd-file passdb
        # below -- regardless of whether the password given was correct.
        # Two things verified the hard way against a real running
        # container, not assumed from docs: `deny` has to be a block-level
        # setting (`deny = yes`), NOT `args = deny=1` -- the latter parses
        # fine (doveconf accepts it silently) but does nothing, since
        # `deny` isn't a static-driver arg at all. And the static driver
        # needs `args = nopassword=1` or its lookup errors out with "No
        # password returned" before Dovecot ever gets to apply the deny,
        # letting the real passdb answer instead -- confirmed via
        # auth_debug logs showing the lookup failing internally rather
        # than denying. Both together, tested against a real IMAP LOGIN
        # (not just `doveadm auth test`, which can behave differently):
        # correctly returns "NO [AUTHENTICATIONFAILED]".
        #
        # Blocks IMAP login directly, and blocks SMTP submission (465) as
        # a side effect -- Postfix's smtps service authenticates via this
        # exact same passdb over the dovecot SASL socket (see
        # smtpd_sasl_path below), so denying it here denies both at once
        # with no separate Postfix change needed. LMTP delivery (inbound
        # mail landing in a mailbox) never consults passdb at all -- it's
        # local delivery keyed by recipient address, not a login -- so
        # inbound mail keeps flowing untouched the whole time.
        maintenance_passdb="passdb {
  driver = static
  args = nopassword=1
  deny = yes
}"
    fi
    cat > /etc/dovecot/dovecot.conf <<EOF
protocols = imap lmtp sieve
listen = *

mail_location = maildir:/var/mail/vhosts/%d/%n
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
first_valid_gid = 5000

$maintenance_passdb
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}
# passwd-file instead of the previous "driver = static" -- static hands
# every user the identical uid/gid/home template with no way to vary
# anything per-user. Per-mailbox quotas (see plugin{} below) need a
# per-user quota_rule, so each line in /etc/dovecot/userdb now carries its
# own optional quota_rule extra field alongside the same uid/gid/home
# every mailbox already had.
userdb {
  driver = passwd-file
  args = /etc/dovecot/userdb
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}

# ManageSieve (RFC 5804) only ever does STARTTLS, not implicit TLS like
# 993/465 -- there's no separate well-known "implicit TLS" port for it the
# way IMAP/SMTP-submission have. That means Traefik's SNI-based TCP
# passthrough (what routes IMAPS/SMTPS per-tenant) can't route it either,
# same fundamental problem architecture.md already hit with inbound SMTP's
# port 25. Deliberately NOT given a Traefik router or a published host
# port for that reason -- left reachable only *within* the shared gateway
# network, by container name (vhsp-<slug>-mail:4190), for an in-network
# client like a future Roundcube container's own Managesieve plugin. A
# tenant-facing client connecting directly over the public internet would
# need the same kind of dedicated-port-per-tenant scheme SFTP already
# uses (see provisioner.py's SSH_PORT_RANGE) -- not built here since
# nothing needs it yet.
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

protocol lmtp {
  mail_plugins = \$mail_plugins sieve quota
}

# imap needs the quota plugin too even though enforcement already happens
# at delivery time (lmtp above) -- without it here, IMAP clients (e.g.
# Roundcube, or a real mail client) can't see usage/limit via the IMAP
# QUOTA extension, and Dovecot also uses this to reject an IMAP APPEND
# that would exceed the mailbox's quota_rule, not just LMTP deliveries.
protocol imap {
  mail_plugins = \$mail_plugins quota
}

# doveadm runs under its own protocol context, not lmtp/imap's -- without
# this, "doveadm quota get"/"doveadm quota recalc" (handy for checking a
# mailbox's usage from a shell, e.g. during ops/debugging) fail with
# "Unknown command 'quota'" even though enforcement itself (lmtp/imap
# above) already works fine without it.
protocol doveadm {
  mail_plugins = \$mail_plugins quota
}

plugin {
  sieve = /var/mail/vhosts/%d/%n/.dovecot.sieve
  sieve_dir = /var/mail/vhosts/%d/%n/sieve

  # Per-mailbox quota -- default plugin backend/root only, no global limit
  # set here. Actual limits come entirely from each mailbox's own
  # userdb "quota_rule" extra field (see write_mail_users below); a
  # mailbox with no quota_rule set has nothing for the plugin to enforce,
  # i.e. unlimited, matching "default: no quota" from the user's request.
  # This is a separate mechanism from the tenant-wide combined quota in
  # config.py/provisioner.py (which spans web+DB+mail and has no single
  # enforcement point) -- this one only ever touches mail, and Dovecot
  # enforces it for real (delivery gets rejected once over), unlike the
  # soft/monitor-only tenant-wide one. Whatever bytes a mailbox actually
  # uses still shows up in the tenant-wide disk-usage total regardless of
  # whether it has its own quota_rule -- nothing extra needed there.
  quota = maildir:User quota
}

ssl = yes
ssl_cert = <$TLS_DIR/cert.pem
ssl_key = <$TLS_DIR/key.pem

# Default is syslog; there's no syslog daemon in this minimal container
# (verified: /dev/log doesn't exist), so without this, dovecot's own
# logging -- including auth failures/successes -- goes nowhere.
log_path = /var/log/vhsp/mail.log

namespace inbox {
  inbox = yes
}
EOF
}

write_dovecot_conf

# Regenerates dovecot's passwd-file(s) and postfix's vmailbox map from
# $MAILBOXES_FILE (username:SHA512-CRYPT-hash:quota_bytes per line, one
# mailbox per line -- quota_bytes empty/absent means unlimited; older
# entries written before per-mailbox quotas existed only have the first
# two fields, which `read` below just leaves quota empty for, so no
# migration of existing data is needed). Seeded with the one required
# `postmaster` entry by provisioner.py before this container ever starts,
# then grown/edited from images/tenant-admin/'s Email page.
# postmaster must always be present -- it's the RFC 5321-mandated address
# every domain must accept, and tenant-admin's own UI already refuses to
# let it be deleted, but this is the actual trust boundary (the code that
# decides what accounts postfix/dovecot will actually accept mail for), so
# it's re-checked here too rather than assumed. Missing/corrupt input
# leaves the LAST-KNOWN-GOOD dovecot/postfix state in place rather than
# wiping every mailbox out from under a running mail server.
write_mail_users() {
    if [ ! -s "$MAILBOXES_FILE" ] || ! grep -q '^postmaster:' "$MAILBOXES_FILE"; then
        echo "vhsp: $MAILBOXES_FILE missing or has no postmaster entry, leaving mail accounts unchanged" >> /var/log/vhsp/mail.log
        return
    fi

    users_tmp="$(mktemp)"
    userdb_tmp="$(mktemp)"
    vmailbox_tmp="$(mktemp)"
    while IFS=':' read -r user hash quota_bytes; do
        [ -n "$user" ] && [ -n "$hash" ] || continue
        case "$user" in
            *[!A-Za-z0-9_.-]*) continue ;;
        esac
        echo "$user@$MAIL_DOMAIN:$hash" >> "$users_tmp"
        echo "$user@$MAIL_DOMAIN OK" >> "$vmailbox_tmp"

        extra=""
        case "$quota_bytes" in
            ''|*[!0-9]*) ;; # empty or non-numeric -- no quota_rule, unlimited
            0) ;;           # 0 means "no quota set", not "0 bytes allowed"
            *) quota_mb=$(( (quota_bytes + 1048575) / 1048576 )) # round up
               # "userdb_" prefix required even though this passwd-file is
               # used ONLY as a userdb (never passdb) -- verified live:
               # without it Dovecot silently accepts the field and shows
               # no error, but doveadm quota get/actual enforcement both
               # just treat the mailbox as unlimited.
               extra="userdb_quota_rule=*:storage=${quota_mb}M" ;;
        esac
        echo "$user@$MAIL_DOMAIN:x:5000:5000::/var/mail/vhosts/$MAIL_DOMAIN/$user::$extra" >> "$userdb_tmp"
    done < "$MAILBOXES_FILE"

    mv "$users_tmp" /etc/dovecot/users
    mv "$userdb_tmp" /etc/dovecot/userdb
    # Dovecot's auth worker reads these as the unprivileged `dovecot` user,
    # not root -- root:600 (verified) leaves it unreadable and every login
    # fails with an opaque "temp_fail". Needs group-readable by the
    # dovecot group.
    chown root:dovecot /etc/dovecot/users /etc/dovecot/userdb
    chmod 640 /etc/dovecot/users /etc/dovecot/userdb

    mv "$vmailbox_tmp" /etc/postfix/vmailbox
    postmap /etc/postfix/vmailbox
}

write_mail_users

postconf -e "myhostname = mail.$MAIL_DOMAIN"
postconf -e "mydomain = $MAIL_DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination ="
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"
postconf -e "mynetworks = 127.0.0.0/8"
postconf -e "virtual_mailbox_domains = $MAIL_DOMAIN"
postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_tls_cert_file = $TLS_DIR/cert.pem"
postconf -e "smtpd_tls_key_file = $TLS_DIR/key.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination"
# non_smtpd_milters covers mail submitted via sendmail(1)/the pickup
# queue (e.g. a future cron/PHP mail() path), not just smtpd -- without
# it, only mail arriving via smtpd/smtps gets signed. accept on milter
# failure: an OpenDKIM outage should degrade to unsigned mail, not stop
# outbound delivery entirely.
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:127.0.0.1:8891"
postconf -e "non_smtpd_milters = inet:127.0.0.1:8891"
# Same reasoning as dovecot's log_path above -- no syslog daemon here, and
# Postfix's own start-fg stdout output (visible via `docker logs`) isn't
# reachable from the tenant-admin container without docker.sock access.
# maillog_file writes Postfix's logging directly to a file instead,
# bypassing syslog entirely -- same combined mail.log dovecot uses, since
# that's the traditional single-mail-log layout tenants would expect.
postconf -e "maillog_file = /var/log/vhsp/mail.log"

# Submission over implicit TLS (465) -- SNI-routable via Traefik TCP
# passthrough, unlike STARTTLS-based 587 where TLS doesn't start until
# mid-session.
if ! grep -q '^smtps' /etc/postfix/master.cf; then
    cat >> /etc/postfix/master.cf <<EOF
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
EOF
fi

mkdir -p /var/spool/postfix/private
chown postfix:postfix /var/spool/postfix/private
chmod 730 /var/spool/postfix/private

# See images/mailgw/entrypoint.sh for the full explanation: Debian's
# default master.cf chroots the outbound smtp(8) delivery agent, which
# breaks its DNS resolution (can't see /etc/resolv.conf inside the jail).
# Relevant here too for any mail this tenant sends onward to the internet.
postconf -F 'smtp/unix/chroot=n'

/usr/sbin/dovecot -F &

# Same "poll a shared file's mtime, regenerate, reload" watcher as the web
# container's PHP/nginx toggles -- images/tenant-admin/'s Email page never
# touches postfix/dovecot directly, just $MAILBOXES_FILE. $MAINTENANCE_MARKER
# is folded into the same combined fingerprint (stat silently skips it in
# the mtime list while absent -- same multi-file pattern images/web/'s own
# write_tenant_nginx_conf watcher uses) since it's written by the operator
# control plane, never tenant-admin, but still needs the same "notice it
# changed, regenerate, reload" handling.
(
    last_mtime=""
    while true; do
        sleep 3
        mtime="$(stat -c %Y "$MAILBOXES_FILE" "$MAINTENANCE_MARKER" 2>/dev/null | tr '\n' ',' || true)"
        if [ "$mtime" != "$last_mtime" ]; then
            last_mtime="$mtime"
            write_mail_users
            write_dovecot_conf
            postfix reload >/dev/null 2>&1 || true
            doveadm reload >/dev/null 2>&1 || true
        fi
    done
) &

exec /usr/sbin/postfix start-fg
