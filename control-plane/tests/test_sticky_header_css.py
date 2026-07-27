"""Guards the sticky table headers in the operator UI against the scroll
container that broke them.

The bug: a `.card` carrying `overflow-x:auto` becomes a scroll container,
and a scroll container between a `position: sticky` element and the
viewport becomes that element's containing block. `thead th { top:
var(--topbar-h) }` then stops meaning "sit under the topbar" and starts
meaning "sit --topbar-h down from the top of this card" -- an empty band
where the header belongs, and the header floating over the second row.

This is a static check because the failure is a rendering one: there's no
assertion to make against a Flask response that would catch it, and the
CSS relationship it depends on isn't visible from any single line. Two
things have to stay true together, and either one alone looks harmless.
"""

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "vhsp_ctl" / "web.py"


@pytest.fixture(scope="module")
def source():
    return WEB.read_text()


def test_the_headers_are_still_meant_to_be_sticky(source):
    """If sticky headers are ever dropped on purpose, the rest of this
    module stops being meaningful and should go with them -- rather than
    sitting here passing vacuously."""
    assert re.search(r"thead th\s*\{[^}]*position:\s*sticky", source, re.S)


def test_the_sticky_offset_still_depends_on_the_topbar(source):
    """`top: var(--topbar-h)` is what makes a stray scroll container
    visible rather than merely wrong -- with `top: 0` the header would
    pin to the container's own top and nobody would notice."""
    assert re.search(r"thead th\s*\{[^}]*top:\s*var\(--topbar-h", source, re.S)


def test_no_card_containing_a_table_creates_a_scroll_container(source):
    """The specific regression. A `.card` with inline overflow that wraps
    a <table> puts a scroll container between the sticky header and the
    viewport."""
    offenders = []
    for match in re.finditer(r'<div class="card"[^>]*style="[^"]*overflow[^"]*"[^>]*>(.{0,400})', source, re.S):
        if "<table" in match.group(1):
            line = source[: match.start()].count("\n") + 1
            offenders.append(line)
    assert not offenders, (
        f"card(s) at line(s) {offenders} set overflow and contain a table. "
        f"That makes the card a scroll container, which silently offsets the "
        f"sticky <thead> by --topbar-h inside it. Wrap the table in its own "
        f"div and set `thead th {{ position: static }}` there instead."
    )


def test_overflow_is_not_set_on_the_table_element_itself(source):
    """Not a rendering bug -- `overflow` simply does not apply to a
    `display: table` element, so a rule here is inert and reads as
    handling something it does not handle."""
    match = re.search(r"\.card table \{([^}]*)\}", source)
    assert match, ".card table rule not found"
    assert "overflow" not in match.group(1), (
        "overflow on a <table> element has no effect -- wrap the table in a "
        "block-level div if it needs to scroll."
    )
