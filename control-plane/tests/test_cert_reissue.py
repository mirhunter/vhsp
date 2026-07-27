"""Tests for the per-tenant certificate reissue action.

The action exists because a failed ACME order never retries itself, and
it works because replacing a container is the one thing that makes
Traefik re-resolve a router's certificate -- a restart does not, since
the labels are identical and there is no configuration change to react
to. Measured directly (issue #18): attempts held at 4 while idle and
across a `docker restart`, and went to 5 on remove-and-recreate.

The DNS precondition carries as much weight as the recreate. Let's
Encrypt allows five failed validations per hostname per hour, so an
action that retries against still-wrong DNS spends a scarce budget to
achieve nothing and can exhaust the retry that would have worked. These
tests pin that it refuses rather than tries.
"""

from unittest.mock import MagicMock, patch

import pytest

from vhsp_ctl import provisioner
from vhsp_ctl.provisioner import CertReissueError


def _tenant(domain="t.example.com"):
    return type("T", (), {
        "domain": domain, "slug": domain.replace(".", "-"),
        "waf_container": f"vhsp-{domain.replace('.', '-')}-waf",
        "tenant_admin_container": f"vhsp-{domain.replace('.', '-')}-tenant-admin",
        "phpconf_host_path": "/srv/vhsp/tenants/t/phpconf",
        "phpconf_volume": "v-phpconf", "logs_volume": "v-logs",
        "webroot_volume": "v-web", "mail_volume": "v-mail",
        "db_network": "n", "db_container": "db", "db_name": "d",
        "db_user": "u", "db_password": "p", "ssh_port": 2200, "sftp_user": "s",
    })()


@pytest.fixture
def wired(monkeypatch):
    """Everything stubbed except the logic under test."""
    client = MagicMock()
    monkeypatch.setattr(provisioner, "_client", lambda: client)
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "203.0.113.1")
    monkeypatch.setattr(provisioner, "_create_waf_container",
                        lambda *a, **k: "new-waf")
    monkeypatch.setattr(provisioner, "_create_tenant_admin_container",
                        lambda *a, **k: ("new-admin", "admin.t.example.com", "pw"))
    monkeypatch.setattr(provisioner.registry, "set_tenant_waf_container", lambda *a: None)
    monkeypatch.setattr(provisioner.audit, "log_action", lambda *a, **k: None)
    return client


def test_refuses_when_dns_does_not_point_here(wired, monkeypatch):
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "is_record_live", lambda *a: False)

    with pytest.raises(CertReissueError, match="does not resolve"):
        provisioner.reissue_tenant_certificates("t.example.com")

    wired.containers.get.assert_not_called()


def test_refuses_when_only_one_hostname_is_ready(wired, monkeypatch):
    """Both the apex and admin hostnames need to be live. Reissuing for a
    half-ready tenant would burn a validation on the half that isn't."""
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "is_record_live",
                        lambda kind, host, ip: not host.startswith("admin."))

    with pytest.raises(CertReissueError, match="admin.t.example.com"):
        provisioner.reissue_tenant_certificates("t.example.com")

    wired.containers.get.assert_not_called()


def test_recreates_both_router_containers_when_dns_is_ready(wired, monkeypatch):
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "is_record_live", lambda *a: True)

    result = provisioner.reissue_tenant_certificates("t.example.com")

    assert result["hostnames"] == ["t.example.com", "admin.t.example.com"]
    # Removal is the whole mechanism -- a restart would not have worked.
    removed = [c.args[0] for c in wired.containers.get.call_args_list]
    assert "vhsp-t-example-com-waf" in removed
    assert "vhsp-t-example-com-tenant-admin" in removed
    assert wired.containers.get.return_value.remove.call_count == 2


def test_webmail_is_left_alone(wired, monkeypatch):
    """webmail.<domain>'s router lives on the shared Roundcube container,
    so reissuing it would recreate infrastructure every other tenant is
    served by. Out of scope on purpose."""
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "is_record_live", lambda *a: True)

    result = provisioner.reissue_tenant_certificates("t.example.com")

    assert not any("webmail" in h for h in result["hostnames"])
    assert not any("roundcube" in str(c).lower() for c in wired.containers.get.call_args_list)


def test_unknown_tenant_is_refused(wired, monkeypatch):
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: None)
    with pytest.raises(CertReissueError, match="no active tenant"):
        provisioner.reissue_tenant_certificates("nope.example.com")


def test_refuses_when_the_platform_ip_is_unconfigured(wired, monkeypatch):
    """With nothing to compare against, is_record_live can't be meaningful
    -- better to say so than to reissue on an unchecked assumption."""
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "PLATFORM_PUBLIC_IP", "")

    with pytest.raises(CertReissueError, match="VHSP_PLATFORM_PUBLIC_IP"):
        provisioner.reissue_tenant_certificates("t.example.com")


def test_the_action_is_audit_logged(wired, monkeypatch):
    monkeypatch.setattr(provisioner.registry, "get_tenant", lambda d: _tenant())
    monkeypatch.setattr(provisioner.dns_records, "is_record_live", lambda *a: True)
    logged = []
    monkeypatch.setattr(provisioner.audit, "log_action",
                        lambda action, domain, actor, **k: logged.append((action, domain, actor)))

    provisioner.reissue_tenant_certificates("t.example.com", actor="admin-ui:alice")

    assert ("tenant.cert_reissue", "t.example.com", "admin-ui:alice") in logged


def test_the_web_route_requires_2fa():
    """Recreating containers is destructive-adjacent -- brief downtime for
    the tenant plus a rate-limited validation spent."""
    import ast
    from pathlib import Path
    src = Path(provisioner.__file__).parent / "web.py"
    tree = ast.parse(src.read_text())
    gated = {
        n.name for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and any(getattr(d, "id", getattr(d, "attr", None)) == "require_2fa" for d in n.decorator_list)
    }
    assert "tenant_reissue_cert" in gated
