"""Which build is this, and which tools does it really have?

Both questions were unanswerable from outside, and that cost a real debugging
session. `/version` reported the packaging version — `0.1.0`, unchanged across
every deploy — so a running instance could not say what code it held. And an
MCP client fetches the tool list once at `initialize` and caches it, so a
session opened before a deploy keeps offering yesterday's menu while the server
answers with today's code. The visible symptom is a tool result referring to a
tool the client cannot see, which reads like a server bug and is not one.

Two answers, both delivered as *data in a tool result* rather than as a
capability the client caches:

`build_info()` — what code this is. Populated from `cra._build`, a module
`deploy.sh` generates into the package before the image is built, because the
package is pip-installed and cannot read a file from the repo root at runtime.
Absent in a dev tree, which is why every field is optional and `source` says
where the answer came from.

`tool_names()` — the authoritative tool list, from the dispatcher tables the
MCP layer wraps. `cra_overview` returns it so a caller can compare it against
what its client is offering. A client cannot be asked whether its cache is
stale; it can be handed the truth and left to notice.
"""

from __future__ import annotations

import os
from typing import Optional

from cra import __version__


def build_info() -> dict:
    """What code this process is running, as far as it can tell."""
    info: dict[str, Optional[str]] = {
        "version": __version__,
        "release": os.environ.get("CRA_RELEASE") or None,
        "commit": None,
        "branch": None,
        "built_at": None,
        "source": "unknown",
    }
    try:
        from cra import _build  # type: ignore[attr-defined]
    except ImportError:
        # A dev tree, or an image built without deploy.sh. Say so rather than
        # inventing a commit — "unknown" is a usable answer and a wrong hash
        # is not.
        info["source"] = "dev" if info["release"] is None else "env"
        return info

    info.update(
        commit=getattr(_build, "COMMIT", None),
        branch=getattr(_build, "BRANCH", None),
        built_at=getattr(_build, "BUILT_AT", None),
        source="build",
    )
    if info["release"] is None:
        info["release"] = info["commit"]
    elif info["commit"] and info["release"] != info["commit"]:
        # A hand-set CRA_RELEASE that no longer matches the deployed commit.
        # It rots the moment someone forgets to update `.env`, and it is what
        # Sentry tags every error with — so a stale one quietly files today's
        # crashes under a build from weeks ago. Surfaced rather than silently
        # preferred; the fix is usually to unset it and let the stamp win.
        info["release_stale"] = True
    return info


def release() -> Optional[str]:
    """What this instance should call itself to an error tracker.

    `CRA_RELEASE` when an operator has set one, otherwise the deployed commit.
    Having the stamp as the fallback is the point: nobody has to remember to
    update anything for Sentry to tag the right build.
    """
    return build_info().get("release")


def tool_names() -> list[str]:
    """Every tool this server exposes, from the dispatcher's own tables.

    Same source the MCP layer wraps, so it cannot drift from what is actually
    callable the way a hand-maintained list would.
    """
    from cra.agents import dispatch

    dispatch._ensure_handlers_loaded()
    return sorted({*dispatch._READ, *dispatch._MUTATING})


def server_identity() -> dict:
    """The block `cra_overview` and `/version` both hand back."""
    names = tool_names()
    return {
        "build": build_info(),
        "tool_count": len(names),
        "tools": names,
        "if_your_tool_list_differs": (
            "This is the authoritative list — it comes from the running server, "
            "whereas your client fetched its tool list once when the session "
            "opened and cached it. If a tool named here is not one you can "
            "call, that session predates the current build: reconnect the "
            "connector rather than working around the gap. Do not conclude the "
            "server is wrong, and do not invent a substitute procedure — a "
            "workaround derived from a stale menu produces confident, wrong "
            "compliance advice."
        ),
    }
