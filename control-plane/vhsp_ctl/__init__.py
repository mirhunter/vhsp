"""VHSP control plane.

`__version__` is the single source of truth for this deployment's
version -- pyproject.toml reads it from here (`dynamic = ["version"]`)
rather than carrying its own copy, so there is exactly one line to bump
at release time and no way for the two to disagree.

Bump this in the release commit, then tag that commit `v<version>`;
.github/workflows/release.yml turns the tag into a GitHub Release, which
is what update_check.py compares against. See UPDATING.md.

Deliberately a plain string, not read from installed package metadata:
a real deployment runs `pip install -e .`, where metadata reflects
whatever version was current the last time pip ran, not what the working
tree currently holds -- and the working tree is what actually executes.
A stale-but-honest constant beats a value that confidently describes
different code than the one running.
"""

__version__ = "0.1.0"
