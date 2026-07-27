#!/bin/bash
set -euo pipefail

MAPS_DIR=/etc/postfix/maps
mkdir -p "$MAPS_DIR"

# Control plane regenerates these from the tenant registry and postmaps
# them after every create/destroy (see provisioner._regenerate_mail_gateway_maps).
# Touch+postmap here only so postfix has *something* to reference on a
# completely fresh boot before any tenant exists.
for f in relay_domains transport; do
    [ -f "$MAPS_DIR/$f" ] || touch "$MAPS_DIR/$f"
    [ -f "$MAPS_DIR/$f.db" ] || postmap "$MAPS_DIR/$f"
done

TLS_DIR=/etc/ssl/mailgw
mkdir -p "$TLS_DIR"
if [ ! -f "$TLS_DIR/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -subj "/CN=${GATEWAY_HOSTNAME:-mail-gateway.vhsp.local}"
fi

postconf -e "myhostname = ${GATEWAY_HOSTNAME:-mail-gateway.vhsp.local}"
postconf -e "mydestination ="
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"
postconf -e "mynetworks = 127.0.0.0/8"
postconf -e "relay_domains = hash:$MAPS_DIR/relay_domains"
postconf -e "transport_maps = hash:$MAPS_DIR/transport"
postconf -e "smtpd_tls_cert_file = $TLS_DIR/cert.pem"
postconf -e "smtpd_tls_key_file = $TLS_DIR/key.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"

# Debian's default master.cf chroots the outbound smtp(8) delivery agent,
# which can't see /etc/resolv.conf inside the jail -- verified this breaks
# DNS resolution for container-name nexthops entirely (Postfix logs a
# retryable "Name service error", mail sits queued forever, even though
# the container's own resolver works fine outside the chroot). Chroot
# matters much more for smtpd (handles untrusted external connections)
# than for the outbound client, so disabling it here is standard practice,
# not a meaningful security regression.
postconf -F 'smtp/unix/chroot=n'

exec /usr/sbin/postfix start-fg
