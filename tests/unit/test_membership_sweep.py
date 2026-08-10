"""Every product-scoped tool must check membership. Swept, not spot-checked.

`CLAUDE.md` has claimed for a while that "a test sweeps every product-scoped
tool rather than spot-checking, because the one gap that ever existed got in
through a handler written without the check its neighbours had". That test did
not exist. What existed was one `test_a_non_member_…` per module — which is
precisely the spot-checking the sentence says it is not, and it covers a module
rather than a tool, so a new handler in an already-covered module inherits
nothing.

This is the sweep. It is a **source-level** check: it asserts that each
product-scoped handler calls one of the membership helpers, not that the call
is correct. That is a real limitation and it is the right trade — the
alternative, invoking all forty-odd tools with plausible arguments, needs a
hand-maintained argument table which is the same kind of list that let the gap
through. Omitting the check entirely is the failure mode that has actually
happened; calling it with the wrong minimum role has not.

The per-module `test_a_non_member_…` tests stay. They prove the check *works*
on a representative tool; this proves nobody forgot to write one.
"""

from __future__ import annotations

import inspect

from cra.agents import dispatch

# Any of these means the handler has asked the question. `_require_member` is
# the row-backed form in `reporting.py`; `_member` is the state-blob form.
_HELPERS = ("_member(", "_require_member(")

# Tools that take no product. `_SESSION_AGNOSTIC` is the codebase's own answer
# to "which tools are not product-scoped", so it is read rather than restated —
# a second list would drift, and the drifting one would silently excuse a tool
# from the check.
_EXEMPT = set(dispatch._SESSION_AGNOSTIC)


def test_every_product_scoped_tool_checks_membership():
    dispatch._ensure_handlers_loaded()
    handlers = {**dispatch._READ, **dispatch._MUTATING}
    missing = []
    for name, fn in handlers.items():
        if name in _EXEMPT:
            continue
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):  # pragma: no cover — builtins, partials
            continue
        if not any(h in src for h in _HELPERS):
            missing.append(name)

    assert not missing, (
        "these product-scoped tools never call a membership helper, so a "
        f"product id alone would reach them: {sorted(missing)}. Use the "
        "module's _member() / _require_member() — a product id is not a "
        "capability, and these handlers return unreported exploited-"
        "vulnerability details and frozen legal artefacts."
    )


def test_the_sweep_actually_looks_at_something():
    """A guard on the guard.

    Every assertion above passes vacuously if the dispatch tables are empty or
    every tool lands in `_EXEMPT` — which is exactly what a refactor that moved
    registration elsewhere would produce, silently.
    """
    dispatch._ensure_handlers_loaded()
    handlers = {**dispatch._READ, **dispatch._MUTATING}
    scoped = [n for n in handlers if n not in _EXEMPT]
    assert len(scoped) > 25, (
        f"only {len(scoped)} product-scoped tools found out of {len(handlers)} "
        "registered — the sweep is no longer looking at the real surface."
    )
