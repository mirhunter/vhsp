"""Tests for dns_records.is_cert_live/cert_status -- the SSL-cert
visibility check added alongside the existing DNS-liveness check (see
README's "DNS records and SSL certificate status" section for why the
two are checked separately: Traefik requests/retries a tenant's cert
when Traefik discovers the router, not on request, and never retried
afterwards -- so cert state can disagree
with DNS-record liveness for a while).
"""
import socket

import pytest

from vhsp_ctl import dns_records


def test_is_cert_live_false_when_nothing_is_listening():
    # No Traefik (or anything) bound to 127.0.0.1:443 in the test
    # environment -- connection should fail cleanly, never raise.
    assert dns_records.is_cert_live("example.com") is False


def test_is_cert_live_false_on_handshake_failure(monkeypatch):
    """Even if something IS listening on 127.0.0.1:443, a non-TLS
    responder (or a self-signed/untrusted cert) must resolve to False,
    not raise -- same never-raises contract as is_record_live."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    # Bind the real function before patching. Referring to
    # `socket.create_connection` from inside the replacement resolves the
    # patched attribute, so the lambda calls itself until the stack runs
    # out -- which is what this test did before, failing with a
    # RecursionError that looked like a handshake failure.
    real_create_connection = socket.create_connection
    monkeypatch.setattr(
        socket, "create_connection",
        lambda addr, timeout=None: real_create_connection((addr[0], port), timeout=timeout),
    )
    try:
        assert dns_records.is_cert_live("example.com") is False
    finally:
        server.close()


def test_cert_status_shape(monkeypatch):
    monkeypatch.setattr(dns_records, "is_cert_live", lambda hostname: hostname == "example.com")
    result = dns_records.cert_status("example.com", "admin.example.com")
    assert result == [
        {"label": "Main site", "hostname": "example.com", "ok": True},
        {"label": "Admin panel", "hostname": "admin.example.com", "ok": False},
    ]
