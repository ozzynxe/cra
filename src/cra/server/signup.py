"""Self-serve access: email in, connector token out, nobody in the middle.

Access used to run through `scripts/dev_token.py`, which put the operator in the
path of every single signup. That does not scale past the people you already
know, and it is the reason the site said "there is no self-service sign-up".

The flow is a magic link, and there are no passwords anywhere:

    POST /api/access/request   email → a single-use link, mailed
    GET  /api/access/complete  link  → a fresh `cra_*` token, shown once

The same proof is also presented as a six-digit code, for the OAuth consent
page (`start_code_challenge` / `verify_code`). See "Why a code, there" below.

## Why no password

A password would need storage, reset, rotation and a session concept, all to
authenticate someone whose only action is collecting an API token. The email
round-trip proves the same thing with none of that, and the reset flow *is* the
signup flow — one path, exercised constantly, so it cannot rot unnoticed.

## Why the link is stateful

A signed stateless token can carry an expiry but cannot be spent. These land in
inboxes that are forwarded, backed up and indexed by mail providers, so one use
and fifteen minutes. The secret itself is never stored; the row keeps a sha256
and the link carries `<id>.<secret>`, so a database dump contains nothing
redeemable.

## Why the token is never emailed

The completion page renders it once. A credential in an inbox is a credential
that outlives its usefulness by years, and this one can read unreported
vulnerability records.

## Why a code, there

A link opens in whatever browser the mail is in — frequently a phone — while
the OAuth flow sits waiting in a tab on a laptop. Finishing in the wrong
browser sends the authorization code to a client callback with no session
behind it, so the connection fails after the user did everything right. A code
is read across the gap instead of clicked, and the waiting tab never moves.

The cost is that six digits is a guessable space where 32 random bytes is not.
`verify_code` counts attempts and spends the row at five; the per-address cap
bounds how many rows an attacker can have alive at once; and every guess costs
them an email in the victim's inbox, which is the loudest possible signal.

## Enumeration

`request_access` always reports the same thing. Whether an address already has
an account is not something a stranger gets to learn by asking, and the OAuth
sign-in path already holds that line.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
# The client name comes from OAuth dynamic client registration, which anyone
# can call — it is attacker-controlled text on its way into an HTML email.
from html import escape as _esc
from typing import Optional

from sqlalchemy import select

from cra.db import SignupLink, User, session_scope
from cra.server import connector_tokens, mailer

log = logging.getLogger(__name__)

# Terms version recorded against an acceptance. Bump when the published terms
# change materially — "they agreed" means nothing without what they agreed to.
TERMS_VERSION = "2026-08-06"

_LINK_TTL_MINUTES = 15
# Shorter than the link: the user is staring at a waiting tab, not coming back
# to an inbox later, and a smaller window is a smaller guessing window.
_CODE_TTL_MINUTES = 10
# How many live challenges one address may hold, links and codes together.
# Without this, repeatedly posting someone else's address turns this endpoint
# into a mail bomb aimed at them. Counted across both kinds because the thing
# being limited is mail arriving in someone's inbox, not a data structure.
_MAX_LIVE_LINKS_PER_EMAIL = 3
# Wrong codes before the row is spent. Five leaves room for a misread digit and
# takes the odds of a blind guess to 5 in a million per emailed code.
_MAX_CODE_ATTEMPTS = 5

PURPOSE_LINK = "link"
# Codes are issued for two different jobs, and a code is only spendable on the
# one it was issued for. A code mailed to connect an app must not open somebody
# else's billing page, even though both prove the same address — the proof is
# the same, what it is worth is not.
PURPOSE_CODE = "code"
PURPOSE_BILLING = "billing"
PURPOSE_LOGIN = "login"
CODE_PURPOSES = (PURPOSE_CODE, PURPOSE_BILLING, PURPOSE_LOGIN)

# Deliberately permissive. Email validity is decided by whether the message
# arrives, not by a regex, and over-strict patterns reject real addresses.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SignupError(Exception):
    """Something the caller can be told about safely."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def signup_enabled() -> bool:
    """Open by default; a switch for when it is being abused.

    `CRA_SIGNUP_INVITE_CODE`, when set, additionally requires that code. That is
    the middle setting between open and closed: still no operator in the path
    for anyone holding the code.
    """
    raw = os.environ.get("CRA_SIGNUP_ENABLED", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _required_invite_code() -> str:
    return os.environ.get("CRA_SIGNUP_INVITE_CODE", "").strip()


def normalise_email(raw: str) -> str:
    email = (raw or "").strip().lower()
    if not _EMAIL_RE.match(email) or len(email) > 254:
        raise SignupError("That does not look like an email address.")
    return email


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _live_challenges(db, email: str, now: datetime) -> int:
    """How many unspent, unexpired challenges this address already holds."""
    rows = db.execute(
        select(SignupLink).where(
            SignupLink.email == email,
            SignupLink.used_at.is_(None),
            SignupLink.expires_at > now,
        )
    ).scalars()
    return len(list(rows))


def request_access(email_raw: str, *, invite_code: str = "") -> dict:
    """Create a single-use link and mail it. Always answers the same way."""
    if not signup_enabled():
        raise SignupError(
            "Self-serve access is closed on this deployment. Ask the operator."
        )
    required = _required_invite_code()
    if required and not secrets.compare_digest(invite_code.strip(), required):
        raise SignupError("That invite code is not valid.")

    email = normalise_email(email_raw)
    origin = mailer.app_origin()
    if not origin:
        # A link with no origin is not a link. Fail loudly to the operator
        # rather than mailing something unusable to a stranger.
        raise SignupError(
            "This deployment has no CRA_APP_ORIGIN set, so an access link "
            "cannot be built. Nothing was sent."
        )

    now = _now()
    with session_scope() as db:
        if _live_challenges(db, email, now) >= _MAX_LIVE_LINKS_PER_EMAIL:
            # Silently succeed. Telling the caller they have hit a per-address
            # cap confirms the address is being targeted, and the person who
            # owns it already has a usable link.
            log.info("access link suppressed: %s already has live links", email)
            return _accepted()

        secret = secrets.token_urlsafe(32)
        row = SignupLink(
            email=email,
            purpose=PURPOSE_LINK,
            secret_sha256=_hash(secret),
            expires_at=now + timedelta(minutes=_LINK_TTL_MINUTES),
        )
        db.add(row)
        db.flush()
        link_id = row.id
        link = f"{origin}/api/access/complete?t={link_id}.{secret}"

    subject = "Your Skarp CRA access link"
    plain = (
        "Someone asked for access to Skarp CRA with this address.\n\n"
        f"{link}\n\n"
        f"The link works once and expires in {_LINK_TTL_MINUTES} minutes. It "
        "will show you a connector token — the only time it is shown.\n\n"
        "If this was not you, ignore this email. No account is created until "
        "the link is opened."
    )
    html = (
        "<p>Someone asked for access to Skarp CRA with this address.</p>"
        f'<p><a href="{link}">Get my connector token</a></p>'
        f"<p>The link works once and expires in {_LINK_TTL_MINUTES} minutes. "
        "It will show you a connector token — the only time it is shown.</p>"
        "<p>If this was not you, ignore this email. No account is created "
        "until the link is opened.</p>"
    )
    try:
        mailer.send(
            to_email=email,
            subject=subject,
            plain=plain,
            html=html,
            hint="Set it, or set CRA_SIGNUP_ENABLED=0 to close self-serve access.",
        )
    except mailer.NotConfigured as e:
        _discard(link_id)
        log.error("access link could not be delivered: %s", e)
        raise SignupError(
            "This deployment cannot send email, so access links cannot be "
            "delivered. Nothing was sent."
        ) from e
    except Exception:  # noqa: BLE001 — never leak provider detail to a stranger
        _discard(link_id)
        log.exception("access link delivery failed for %s", email)
        raise SignupError("The email could not be sent. Try again shortly.") from None

    return _accepted()


def _discard(link_id: str) -> None:
    """Drop a link whose email never left the building.

    The row is written before the send so the secret exists to put in the mail,
    which means a delivery failure leaves a link nobody received. Harmless on
    its own — but live links are capped per address, so three failed sends
    would lock an address out for fifteen minutes over an outage that was
    never the user's fault. Found by the first real signup against production,
    where the send failed and the row stayed.
    """
    try:
        with session_scope() as db:
            row = db.get(SignupLink, link_id)
            if row is not None and row.used_at is None:
                db.delete(row)
    except Exception:  # noqa: BLE001 — cleanup must not mask the send failure
        log.exception("could not discard undelivered link %s", link_id)


def _accepted() -> dict:
    return {
        "ok": True,
        "message": (
            "If that address can receive mail, a single-use access link is on "
            "its way. It expires in 15 minutes."
        ),
    }


# Filled by `_claim_account`, drained by `_apply_invitations` once its
# transaction has committed.
_pending_invitations: list[tuple[str, str]] = []


def _apply_invitations() -> None:
    """Join any product this address was invited to. Never raises.

    A colleague's invitation failing must not stop somebody signing up: the
    account is the thing they asked for, the membership is a convenience, and
    the invitation row survives to be applied on their next sign-in.
    """
    while _pending_invitations:
        email, user_id = _pending_invitations.pop()
        try:
            from cra.server import invitations

            invitations.apply_pending(email, user_id)
        except Exception:  # noqa: BLE001
            log.exception("could not apply invitations for %s", email)


def _claim_account(db, email: str, now: datetime) -> tuple[str, bool]:
    """Find or create the account behind a proven address. Returns (id, new).

    Shared by both proofs, because they prove exactly the same thing: whoever
    is asking can read mail at this address. What they are then allowed to do
    differs — a link shows a token, a code authorizes an app — but the account
    is reached the same way, and having one function for it means a change to
    what verification implies cannot land on only half the paths.
    """
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    created = user is None
    if user is None:
        user = User(id=str(uuid.uuid4()), email=email)
        db.add(user)
    # Answering the challenge is the proof, so it stamps every time — including
    # for an account created by hand before self-serve existed.
    user.email_verified_at = now
    if user.terms_accepted_at is None:
        user.terms_accepted_at = now
        user.terms_version = TERMS_VERSION
    db.flush()
    user_id = user.id

    # Any product this address was invited to before it had an account. Done
    # here because this is the one place an address becomes one, so it lands
    # whichever door they came through — magic link, OAuth code, billing, or
    # console login. Deferred so it runs after this transaction commits: the
    # membership write is a separate save_state and must not see a half-made
    # user.
    _pending_invitations.append((email, user_id))
    return user_id, created


def start_code_challenge(
    email_raw: str,
    *,
    client_name: str = "",
    purpose: str = PURPOSE_CODE,
    what: str = "",
) -> str:
    """Mail a six-digit code and return the challenge id the page must quote.

    `what` is the sentence telling the reader why they got this, and it is not
    decoration: a code arriving with no stated reason is indistinguishable from
    a phishing attempt, and the one defence a recipient has is being able to
    tell whether the thing described is something they just did.

    The id is not a secret — the browser that asked for the code already has
    it, and an attacker who typed someone else's address holds it too. It
    names the row; the code is what proves anything.
    """
    if purpose not in CODE_PURPOSES:
        raise ValueError(f"unknown code purpose: {purpose!r}")
    if not signup_enabled():
        raise SignupError(
            "Self-serve access is closed on this deployment. Ask the operator."
        )
    email = normalise_email(email_raw)

    now = _now()
    with session_scope() as db:
        if _live_challenges(db, email, now) >= _MAX_LIVE_LINKS_PER_EMAIL:
            # Unlike the link flow this cannot silently succeed — the user is
            # watching a box that needs a code. The wording still says nothing
            # about whether the address has an account.
            raise SignupError(
                "Too many codes have been requested for that address recently. "
                "Use the most recent one, or try again in a few minutes."
            )

        code = f"{secrets.randbelow(1_000_000):06d}"
        row = SignupLink(
            email=email,
            purpose=purpose,
            code_sha256=_hash(code),
            expires_at=now + timedelta(minutes=_CODE_TTL_MINUTES),
        )
        db.add(row)
        db.flush()
        challenge_id = row.id

    who = client_name.strip() or "An application"
    reason = what.strip() or (
        f"{who} is asking to connect to Skarp CRA using this address."
    )
    subject = f"{code} is your Skarp CRA verification code"
    plain = (
        f"{reason}\n\n"
        f"Your code is {code}\n\n"
        f"It expires in {_CODE_TTL_MINUTES} minutes and works once.\n\n"
        "Only enter it on the page you opened yourself. Nobody from CRA "
        "Assistant will ever ask you for this code.\n\n"
        "If you were not connecting anything, ignore this email — no account "
        "is created and nothing is granted until the code is entered."
    )
    html = (
        f"<p>{_esc(reason)}</p>"
        f'<p style="font-size:28px;letter-spacing:4px;font-weight:600">{code}</p>'
        f"<p>It expires in {_CODE_TTL_MINUTES} minutes and works once.</p>"
        "<p><strong>Only enter it on the page you opened yourself.</strong> "
        "Nobody from Skarp CRA will ever ask you for this code.</p>"
        "<p>If you were not connecting anything, ignore this email — no "
        "account is created and nothing is granted until the code is "
        "entered.</p>"
    )
    try:
        mailer.send(
            to_email=email,
            subject=subject,
            plain=plain,
            html=html,
            hint="Set it, or set CRA_SIGNUP_ENABLED=0 to close self-serve access.",
        )
    except mailer.NotConfigured as e:
        _discard(challenge_id)
        log.error("verification code could not be delivered: %s", e)
        raise SignupError(
            "This deployment cannot send email, so it cannot verify an "
            "address. Nothing was sent."
        ) from e
    except Exception:  # noqa: BLE001 — never leak provider detail to a stranger
        _discard(challenge_id)
        log.exception("verification code delivery failed for %s", email)
        raise SignupError("The email could not be sent. Try again shortly.") from None

    return challenge_id


class CodeAlreadyUsed(SignupError):
    """A correct code, presented after it was spent.

    A subclass so every existing `except SignupError` keeps catching it; the
    type only exists so a caller that wants to say something kinder than
    "invalid" can tell the two apart."""


def verify_code(
    challenge_id: str, presented: str, *, purpose: str = PURPOSE_CODE
) -> dict:
    """Spend a code challenge. Returns the account behind the proven address.

    Deliberately does not mint anything. The caller decides what the proof is
    worth — the OAuth path turns it into a grant for one named client, which is
    narrower than the token `complete()` hands over.
    """
    digits = "".join(ch for ch in (presented or "") if ch.isdigit())
    bad = SignupError("That code is not valid. Check the latest email, or start again.")
    try:
        uuid.UUID((challenge_id or "").strip())
    except ValueError:
        raise bad from None
    if len(digits) != 6:
        raise bad

    now = _now()
    # Nothing raises inside the transaction. `session_scope` rolls back on an
    # exception, so raising on a wrong code would discard the attempt counter
    # in the same breath as incrementing it — and an unbounded number of
    # guesses against six digits is not a secret at all. Decide in here, raise
    # out there, so the increment commits.
    ok = False
    # A correct code submitted twice is not a wrong code, and saying so matters:
    # the first submit completes the connection and redirects, so any resubmit —
    # a double click, a browser retry, a back-navigation — lands here and used to
    # report "that code is not valid". The user is then told their successful
    # connection failed, which is worse than a plain failure because it teaches
    # them to distrust a connector that works.
    #
    # Only reachable by presenting the code that was actually correct, so it
    # discloses nothing: a guesser cannot get here without already having it.
    replayed = False
    with session_scope() as db:
        row = db.get(SignupLink, challenge_id)
        usable = (
            row is not None
            and row.purpose == purpose
            and row.code_sha256 is not None
            and row.used_at is None
            and row.expires_at > now
        )
        replayed = (
            row is not None
            and row.purpose == purpose
            and row.code_sha256 is not None
            and row.used_at is not None
            and secrets.compare_digest(row.code_sha256, _hash(digits))
        )
        if usable and secrets.compare_digest(row.code_sha256, _hash(digits)):
            row.used_at = now
            email = row.email
            user_id, created = _claim_account(db, email, now)
            ok = True
        elif usable:
            row.attempts += 1
            if row.attempts >= _MAX_CODE_ATTEMPTS:
                # Spend it. Retrying then costs another email to the address —
                # which is the point: guessing has to be visible to its victim.
                row.used_at = now
                log.warning("verification code exhausted for %s", row.email)

    if not ok:
        if replayed:
            raise CodeAlreadyUsed(
                "That code has already been used, and it only works once. If you "
                "were connecting an app, it is most likely connected already — "
                "check before asking for a new code."
            )
        raise bad

    _apply_invitations()
    log.info("address verified by code: %s (new account: %s)", email, created)
    return {
        "ok": True,
        "email": email,
        "user_id": user_id,
        "new_account": created,
        "terms_version": TERMS_VERSION,
    }


def complete(presented: str) -> dict:
    """Spend a link: verify the address, mint a token, return it once."""
    raw = (presented or "").strip()
    link_id, _, secret = raw.partition(".")
    if not link_id or not secret:
        raise SignupError("That link is malformed.")
    try:
        uuid.UUID(link_id)
    except ValueError:
        raise SignupError("That link is malformed.") from None

    now = _now()
    with session_scope() as db:
        row = db.get(SignupLink, link_id)
        # One message for every failure mode. Expired, spent, forged and
        # unknown are all "not usable", and distinguishing them tells someone
        # holding a stolen link which part to attack.
        bad = SignupError("That link is no longer valid. Request a new one.")
        if row is None or row.purpose != PURPOSE_LINK or row.secret_sha256 is None:
            raise bad
        if not secrets.compare_digest(row.secret_sha256, _hash(secret)):
            raise bad
        if row.used_at is not None or row.expires_at <= now:
            raise bad

        row.used_at = now
        email = row.email
        user_id, created = _claim_account(db, email, now)

    _apply_invitations()
    label = f"self-serve {now.date().isoformat()}"
    plaintext, _row = connector_tokens.mint_token(
        user_id=user_id, product_id=None, label=label
    )
    log.info("self-serve access granted to %s (new account: %s)", email, created)
    return {
        "ok": True,
        "email": email,
        "new_account": created,
        "token": plaintext,
        "terms_version": TERMS_VERSION,
    }
