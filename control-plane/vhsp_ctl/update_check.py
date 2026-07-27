"""Checks GitHub Releases for a newer version, for the operator UI's
update banner.

**This is the only outbound HTTP request anything in this codebase
makes.** Everything else reaches the network through ssh/scp (backups),
dig (DNS checks), or the Docker proxy on loopback. That makes this a
posture change, not just a feature: on a schedule, it tells GitHub this
host's IP address and that it runs vhsp. For a platform whose entire
pitch is self-hosting and isolation, that has to be the operator's
choice, so it is **off by default** and opt-in via the same
platform_settings.json toggle the REST API and MCP server already use.

It notifies and nothing else. It does not download, verify, stage, or
apply anything. That restraint is the point: this control plane is
root-equivalent on its host (scoped Docker proxy plus the sudo wrappers),
and a root-equivalent process that automatically applies code fetched
from the internet is precisely the supply-chain failure this project
exists as a reaction to -- see architecture.md's motivation section on
CyberPanel. Anything that ever *applies* an update needs signed releases
and real verification first; backup.py's manifest signing is the model to
copy, not this module.

The release body is deliberately never fetched into the UI. Only the tag
name, the release URL, and the publish timestamp are stored, all of them
re-validated below. Release notes are attacker-influenced text if a
maintainer account is ever compromised, and the smallest safe amount of
that to render is none.
"""

import json
import os
import re
import stat
from datetime import datetime, timezone

import requests

from vhsp_ctl import __version__
from vhsp_ctl.config import STATE_DIR

# Public repo, so no token and no authentication: unauthenticated GitHub
# API allows 60 requests/hour/IP and the timer uses one per day. Adding a
# token would mean storing a credential on every deployment to read
# something already world-readable.
RELEASES_API_URL = "https://api.github.com/repos/mirhunter/vhsp/releases/latest"
RELEASES_PAGE_URL = "https://github.com/mirhunter/vhsp/releases"
# Where the banner's "How to update" link points. A fixed constant, not
# anything derived from the API response -- the update instructions are
# the one thing an operator follows while holding root, so the
# destination must not be influenced by a remote response at all.
UPDATING_DOC_URL = "https://github.com/mirhunter/vhsp/blob/main/UPDATING.md"

STATE_PATH = STATE_DIR / "update_check.json"

# Short, and never retried in-process: this runs on a daily timer, so a
# GitHub outage costs a day's staleness, which is nothing. Blocking the
# admin UI or piling up retries would cost more.
TIMEOUT_SECONDS = 10

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
# Only what we will actually render or link to, and only in the shapes we
# expect. A tag is compared and displayed; a URL becomes an href.
_TAG_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._/-]{1,200}$")


class UpdateCheckError(Exception):
    pass


def parse_version(text: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) from `1.2.3` or `v1.2.3`, else None.

    Anything trailing the patch number (`-rc1`, `+build`) is ignored
    rather than parsed. This deliberately does NOT implement semver
    pre-release precedence: getting that subtly wrong would mean either
    nagging about a release that isn't newer, or staying silent about one
    that is. Comparing only the numeric core is a rule that is easy to
    state and hard to get wrong, and a pre-release tag would compare
    equal to its final release rather than pretending to know better.
    """
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    return tuple(int(g) for g in match.groups())  # type: ignore[return-value]


def is_newer(latest: str, current: str) -> bool:
    """True only when `latest` parses, `current` parses, and latest is
    strictly greater. Unparseable input on either side means False --
    an update banner is an interruption, so silence is the right failure
    mode when we can't be sure."""
    latest_parsed = parse_version(latest)
    current_parsed = parse_version(current)
    if latest_parsed is None or current_parsed is None:
        return False
    return latest_parsed > current_parsed


def _load() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))
    os.chmod(STATE_PATH, stat.S_IRUSR | stat.S_IWUSR)


def fetch_latest() -> dict:
    """One request to GitHub. Returns the validated subset we keep.

    Raises UpdateCheckError for anything that isn't a well-formed
    response -- including a 200 whose fields don't match the shapes
    expected below, since "GitHub returned something unexpected" and
    "GitHub is unreachable" both mean the same thing to every caller:
    no trustworthy answer this round.
    """
    try:
        response = requests.get(
            RELEASES_API_URL,
            timeout=TIMEOUT_SECONDS,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"vhsp-control-plane/{__version__}",
            },
        )
    except requests.RequestException as exc:
        raise UpdateCheckError(f"could not reach GitHub: {exc}") from exc

    if response.status_code != 200:
        raise UpdateCheckError(f"GitHub returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise UpdateCheckError("GitHub returned a non-JSON body") from exc

    tag = str(payload.get("tag_name", "")).strip()
    url = str(payload.get("html_url", "")).strip()
    published = str(payload.get("published_at", "")).strip()

    # Validated, not trusted. `tag` is rendered into the operator UI and
    # `url` becomes an href; Jinja autoescaping already covers the former,
    # but an href is exactly where autoescaping does not save you from a
    # javascript: or attacker-chosen destination. Pinning the URL to this
    # repo's own path on github.com means a compromised API response can
    # not turn the banner into a link somewhere else.
    if not _TAG_RE.match(tag):
        raise UpdateCheckError(f"unexpected tag_name in response: {tag!r}")
    if not _URL_RE.match(url):
        raise UpdateCheckError(f"unexpected html_url in response: {url!r}")

    return {"tag": tag, "url": url, "published_at": published}


def run_check() -> dict:
    """Fetch, compare against the running version, persist, and return
    the new state. Records failures too -- an operator looking at a stale
    "last checked" timestamp deserves to see why, and a check that has
    been quietly failing for a month is itself worth noticing."""
    state = _load()
    state["current_version"] = __version__
    state["last_checked_at"] = datetime.now(timezone.utc).isoformat()
    try:
        latest = fetch_latest()
    except UpdateCheckError as exc:
        state["last_error"] = str(exc)
        _write(state)
        return state

    state.pop("last_error", None)
    state["latest_tag"] = latest["tag"]
    state["latest_url"] = latest["url"]
    state["latest_published_at"] = latest["published_at"]
    state["update_available"] = is_newer(latest["tag"], __version__)
    _write(state)
    return state


def banner_state() -> dict | None:
    """What the operator UI renders, or None for "show nothing".

    Returns None unless a check has genuinely succeeded and found a
    strictly newer release. Re-derives `update_available` from the stored
    tag against the *currently running* version rather than trusting the
    stored boolean: the stored value was computed by whichever version
    was running at check time, and an upgrade is exactly the moment that
    goes stale -- otherwise the banner would keep insisting an update is
    available immediately after someone applied it, until the next timer
    run.
    """
    state = _load()
    tag = state.get("latest_tag")
    url = state.get("latest_url")
    if not tag or not url or not is_newer(tag, __version__):
        return None
    # Re-validate on the way out as well as on the way in: this file is
    # 0600 and host-local, but it is still parsed input, and the href is
    # the one field where being wrong is expensive.
    if not _TAG_RE.match(tag) or not _URL_RE.match(url):
        return None
    return {
        "current_version": __version__,
        "latest_tag": tag,
        "latest_url": url,
        "published_at": state.get("latest_published_at", ""),
    }


def status() -> dict:
    """Everything known, for the CLI and the settings page -- including
    the failure and never-run cases the banner deliberately hides."""
    state = _load()
    return {
        "current_version": __version__,
        "last_checked_at": state.get("last_checked_at"),
        "last_error": state.get("last_error"),
        "latest_tag": state.get("latest_tag"),
        "latest_url": state.get("latest_url"),
        "update_available": banner_state() is not None,
    }
