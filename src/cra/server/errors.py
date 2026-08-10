"""Transition error hierarchy.

Carried over from Coauthor's `transitions.py` (lines 37-63 there) — the shape
was right, only the domain changed. Each class carries a stable `code` that
the dispatcher puts into the `{ok: false, code: ...}` envelope, so an agent can
branch on the failure without parsing prose.
"""

from __future__ import annotations


class TransitionError(Exception):
    code = "transition_error"


class PermissionDenied(TransitionError):
    code = "permission_denied"


class NotFound(TransitionError):
    code = "not_found"


class InvalidState(TransitionError):
    code = "invalid_state"


class IntegrityError(TransitionError):
    code = "integrity_error"


class VersionConflict(TransitionError):
    """Optimistic-concurrency clash: another member's agent wrote first.

    Several developers work one product concurrently. Writes are keyed and
    mostly independent, so this should be rare and is resolved by retrying
    against fresh state rather than by locking.
    """

    code = "version_conflict"


class AuditWriteFailed(TransitionError):
    """The audit row could not be written, so the mutation was rolled back.

    Deliberately fatal. Coauthor swallowed activity-log failures — "never block
    the originating action" — which is right for a social feed and wrong here:
    under the CRA the audit trail *is* the deliverable, retained 10 years. A
    state change nobody can evidence is worse than no state change.
    """

    code = "audit_write_failed"
