"""Parsing a timestamp that a legal clock will be measured from.

One function, extracted the moment a third module wanted it. Two near-identical
copies had already drifted — one normalised to UTC and one did not — which is
exactly the divergence that ends with two tools disagreeing about when
something happened.

The insistence on a timezone is the point. A naive timestamp on a statutory
clock is a bug waiting to happen: "09:00" is two different instants in Lisbon
and Helsinki, and on a 24-hour reporting deadline that difference is the
difference between on time and late. Refusing is better than guessing, and
guessing UTC is still guessing.

**`parse_ts` preserves the caller's offset; `parse_ts_utc` converts.** Two
functions rather than one with a flag, because the difference is visible: the
reporting tools echo the timestamp they were given back in the response, and a
caller who sent `+02:00` seeing `+00:00` returned would reasonably wonder
whether something had been reinterpreted. It has not — the two are the same
instant — but a compliance tool should not make a user check that.

Storage is `timestamptz` and `deadlines._as_utc` normalises at the point of
arithmetic, so nothing downstream depends on which of these was used. The
choice is purely about what the caller sees.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cra.server.errors import InvalidState


def parse_ts(value: Optional[str], *, field: str, what: str = "a statutory date") -> Optional[datetime]:
    """ISO 8601, timezone required, offset preserved. `None` passes through.

    `what` completes the sentence explaining why a bare local time is refused,
    so the error says what is actually at stake — a reporting deadline, a
    market placement — rather than complaining about formatting.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise InvalidState(
            f"{field} is not a valid ISO 8601 timestamp: {value!r} — "
            "e.g. 2026-09-01T14:00:00Z"
        ) from e
    if parsed.tzinfo is None:
        raise InvalidState(
            f"{field} needs a timezone offset (e.g. 2026-09-01T14:00:00Z) — "
            f"a bare local time cannot anchor {what}"
        )
    return parsed


def parse_ts_utc(value: Optional[str], *, field: str, what: str = "a statutory date") -> Optional[datetime]:
    """As `parse_ts`, converted to UTC.

    For callers that do date arithmetic on the result and report it back in
    their own words rather than echoing the input — a release date, the span of
    a support period.
    """
    parsed = parse_ts(value, field=field, what=what)
    return parsed.astimezone(timezone.utc) if parsed else None
