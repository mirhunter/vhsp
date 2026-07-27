"""Keeps real infrastructure identifiers out of a now-public repo.

Tenant domains belong to customers, not to this project. Once they're
committed to a public repo they're indexed and archived regardless of any
later edit, so the cheap win is not letting new ones in. Documentation
uses RFC 2606 reserved names (`example.com` and friends), which are
guaranteed never to resolve to anyone's real host.

The operator host's own hostname is deliberately NOT covered here -- that
one is the maintainer's own machine and its presence is a decision, not
an accident.
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Customer/tenant domains that were used as live examples before this repo
# went public. Listed explicitly rather than pattern-matched: "looks like a
# real domain" is not decidable, and a vague rule that fires on
# example.com would just get disabled.
FORMER_TENANT_DOMAINS = ["bigchimp", "demandcommonsense"]

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "rendered"}
SKIP_SUBSTR = ("swagger", "bundle.js")


def _tracked_text_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    files = []
    for rel in out:
        p = REPO / rel
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if any(s in rel for s in SKIP_SUBSTR):
            continue
        if p.name == Path(__file__).name:  # this file names them on purpose
            continue
        files.append(p)
    return files


def test_repo_has_tracked_files():
    assert len(_tracked_text_files()) > 30


@pytest.mark.parametrize("domain", FORMER_TENANT_DOMAINS)
def test_no_real_tenant_domains_anywhere(domain):
    offenders = []
    for p in _tracked_text_files():
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        if domain in text:
            offenders.append(str(p.relative_to(REPO)))
    assert not offenders, (
        f"{domain!r} is a real tenant domain and this repo is public. "
        f"Use an RFC 2606 name (example.com) instead. Found in: {offenders}"
    )


def test_documentation_uses_reserved_example_domains():
    """Positive check -- confirms the placeholders are actually present, so
    the test above can't pass merely because the docs stopped having
    examples at all."""
    readme = (REPO / "control-plane" / "README.md").read_text()
    assert re.search(r"\bexample\.com\b", readme)
