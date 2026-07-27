"""Platform-wide feature toggles (currently: the operator REST API and the
operator MCP server) -- mutable at runtime via the operator UI, unlike
every other config.py setting, which is env-var-only and fixed at process
start.

Write side only. config.py does its own independent read of the same
file (see its API_ENABLED/MCP_ENABLED computation) rather than importing
this module -- config.py is imported by everything else in this codebase
and stays dependency-light on purpose, so a few lines of read logic are
duplicated here intentionally rather than shared.

Once this file exists, its values take precedence over the env var
(VHSP_API_ENABLED / VHSP_MCP_ENABLED) that seeded the original deploy --
a deployment that's never used the toggle keeps behaving exactly as
before, env-var-only.
"""

import json
import os
import stat

from vhsp_ctl import audit
from vhsp_ctl.config import STATE_DIR

PLATFORM_SETTINGS_PATH = STATE_DIR / "platform_settings.json"


def _load() -> dict:
    if not PLATFORM_SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(PLATFORM_SETTINGS_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def _write(settings: dict) -> None:
    PLATFORM_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    PLATFORM_SETTINGS_PATH.write_text(json.dumps(settings))
    os.chmod(PLATFORM_SETTINGS_PATH, stat.S_IRUSR | stat.S_IWUSR)


def set_api_enabled(enabled: bool, actor: str) -> None:
    settings = _load()
    settings["api_enabled"] = enabled
    _write(settings)
    audit.log_action("admin.api_enable" if enabled else "admin.api_disable", "", actor)


def set_mcp_enabled(enabled: bool, actor: str) -> None:
    settings = _load()
    settings["mcp_enabled"] = enabled
    _write(settings)
    audit.log_action("admin.mcp_enable" if enabled else "admin.mcp_disable", "", actor)


def set_update_check_enabled(enabled: bool, actor: str) -> None:
    """Opt-in for the GitHub release check (update_check.py). Same
    toggle mechanism as the two above, but gating a different kind of
    thing: those expose a surface inbound, this one makes an outbound
    request. See update_check.py's module docstring for why that is the
    operator's call to make rather than a default."""
    settings = _load()
    settings["update_check_enabled"] = enabled
    _write(settings)
    audit.log_action(
        "admin.update_check_enable" if enabled else "admin.update_check_disable", "", actor
    )
