"""Tests for the audit log's tamper-evident hash chain.

The chain is what makes editing or truncating the local log *detectable*
between off-host ships, so a silent regression here quietly removes the
only thing standing between "compromised" and "next successful ship".
The old-format case is covered explicitly because audit.verify_chain's
own docstring calls it out as the subtle one: entries predating the
prev_hash field must not be reported as a break.
"""

import json

import pytest

from vhsp_ctl import audit


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", path)
    return path


def test_empty_log_is_trivially_intact(log_path):
    assert audit.verify_chain() == (True, 0)


def test_chain_verifies_across_many_entries(log_path):
    for i in range(5):
        audit.log_action("tenant.create", f"t{i}.example", "admin")
    intact, count = audit.verify_chain()
    assert (intact, count) == (True, 5)


def test_detects_an_edited_entry(log_path):
    for i in range(4):
        audit.log_action("tenant.create", f"t{i}.example", "admin")
    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["actor"] = "attacker"
    lines[1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n")

    intact, first_bad = audit.verify_chain()
    assert not intact
    # The break shows at the entry AFTER the edited one -- entry 1's own
    # prev_hash still matches entry 0, but entry 2's no longer matches the
    # rewritten entry 1.
    assert first_bad == 2


def test_detects_a_deleted_entry(log_path):
    for i in range(4):
        audit.log_action("tenant.create", f"t{i}.example", "admin")
    lines = log_path.read_text().splitlines()
    del lines[1]
    log_path.write_text("\n".join(lines) + "\n")

    intact, _ = audit.verify_chain()
    assert not intact


def test_detects_truncation_of_a_middle_entry_to_garbage(log_path):
    audit.log_action("tenant.create", "a.example", "admin")
    audit.log_action("tenant.create", "b.example", "admin")
    lines = log_path.read_text().splitlines()
    lines[1] = "{not json"
    log_path.write_text("\n".join(lines) + "\n")

    assert audit.verify_chain() == (False, 1)


def test_entries_predating_prev_hash_are_not_a_break(log_path):
    """Old-format entries have no prev_hash key at all. Treating a missing
    key as "prev_hash was empty" would report a spurious break on every
    log that predates the feature -- i.e. every log on first deploy."""
    old = [
        {"ts": "2026-01-01T00:00:00+00:00", "action": "tenant.create", "domain": "a", "actor": "admin"},
        {"ts": "2026-01-02T00:00:00+00:00", "action": "tenant.create", "domain": "b", "actor": "admin"},
    ]
    log_path.write_text("".join(json.dumps(e) + "\n" for e in old))
    assert audit.verify_chain() == (True, 2)


def test_new_entries_appended_after_old_ones_still_verify(log_path):
    old = {"ts": "2026-01-01T00:00:00+00:00", "action": "tenant.create", "domain": "a", "actor": "admin"}
    log_path.write_text(json.dumps(old) + "\n")
    audit.log_action("tenant.create", "b.example", "admin")
    audit.log_action("tenant.destroy", "b.example", "admin")

    intact, count = audit.verify_chain()
    assert (intact, count) == (True, 3)


def test_ip_is_omitted_entirely_when_not_passed(log_path):
    """Callers that never had an IP concept must not gain an empty field --
    fail2ban's admin-login jail matches on this file's shape."""
    audit.log_action("tenant.create", "a.example", "admin")
    audit.log_action("admin.login", "admin", "admin", ip="203.0.113.9")
    first, second = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert "ip" not in first
    assert second["ip"] == "203.0.113.9"
