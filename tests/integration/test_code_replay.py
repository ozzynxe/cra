"""A correct code submitted twice must not read as a wrong code.

From a real connect: the first submit verified, returned 302 and completed the
grant; the form was then re-posted and each replay answered "That code is not
valid." The connector was live the whole time. The user saw the last response
and concluded it had failed — which is worse than an outright failure, because
it teaches them to distrust something that works.

The single-use rule itself is correct and stays. What changes is that a replay
of the *correct* code is reported as a replay.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

_NEEDS_DB = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from cra.server import signup  # noqa: E402


@pytest.fixture
def outbox(monkeypatch):
    """Capture the mail instead of sending it, so the test can read the code
    the user would have received."""
    sent: list[dict] = []
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: sent.append(kw) or "m")
    return sent


def _fresh_email() -> str:
    import uuid

    return f"{uuid.uuid4().hex[:12]}@example.test"


def _issue(outbox) -> tuple[str, str]:
    """A challenge and the code that was mailed for it."""
    email = _fresh_email()
    challenge = signup.start_code_challenge(
        email, purpose=signup.PURPOSE_LOGIN, what="test"
    )
    body = outbox[-1]["plain"].replace("\n", " ")
    code = next(w for w in body.split() if w.isdigit() and len(w) == 6)
    return challenge, code


@_NEEDS_DB
def test_the_first_submit_succeeds(outbox):
    challenge, code = _issue(outbox)
    assert signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)["ok"]


@_NEEDS_DB
def test_a_replay_says_already_used_not_invalid(outbox):
    challenge, code = _issue(outbox)
    signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)

    with pytest.raises(signup.CodeAlreadyUsed) as caught:
        signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)

    message = str(caught.value)
    assert "already been used" in message
    assert "not valid" not in message
    # And it points at the likely truth rather than sending them round again.
    assert "connected already" in message


@_NEEDS_DB
def test_a_replay_is_still_a_signup_error(outbox):
    """Every existing `except SignupError` must keep catching it — the type is
    for callers that want to be kinder, not a new failure mode to handle."""
    challenge, code = _issue(outbox)
    signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)
    with pytest.raises(signup.SignupError):
        signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)


@_NEEDS_DB
def test_a_wrong_code_is_still_just_invalid(outbox):
    """The kinder message must not leak to guessers: reaching it requires
    presenting the code that was actually correct."""
    challenge, _code = _issue(outbox)
    with pytest.raises(signup.SignupError) as caught:
        signup.verify_code(challenge, "000000", purpose=signup.PURPOSE_LOGIN)
    assert not isinstance(caught.value, signup.CodeAlreadyUsed)
    assert "not valid" in str(caught.value)


@_NEEDS_DB
def test_a_wrong_code_after_a_successful_use_is_not_called_a_replay(outbox):
    """Spent challenge, wrong code — that is an invalid code, not a replay.
    Anything else would confirm to a guesser that the challenge existed."""
    challenge, code = _issue(outbox)
    signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)
    with pytest.raises(signup.SignupError) as caught:
        signup.verify_code(challenge, "000000", purpose=signup.PURPOSE_LOGIN)
    assert not isinstance(caught.value, signup.CodeAlreadyUsed)


@_NEEDS_DB
def test_a_replay_does_not_re_grant_anything(outbox):
    """The single-use rule is the security property and is unchanged. The
    replay is reported differently, never honoured."""
    challenge, code = _issue(outbox)
    first = signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)
    assert first["ok"]
    with pytest.raises(signup.CodeAlreadyUsed):
        signup.verify_code(challenge, code, purpose=signup.PURPOSE_LOGIN)
