"""Self-serve access, which is the only unauthenticated write path in the app.

A stranger can cause this service to send email to an address they typed, and
can end up holding a credential that reads compliance records. So the tests are
mostly about what it refuses: to say whether an address is known, to let a link
be spent twice, to distinguish an expired link from a forged one, or to be used
as a mail cannon aimed at a third party.

Delivery is stubbed. What matters is the state machine, not SES.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs DATABASE_URL"
)

from sqlalchemy import select  # noqa: E402

from cra.db import ConnectorToken, SignupLink, User, session_scope  # noqa: E402
from cra.server import connector_tokens, signup  # noqa: E402

UTC = timezone.utc


@pytest.fixture(autouse=True)
def outbox(monkeypatch):
    """Capture mail instead of sending it, and give the links an origin."""
    sent: list[dict] = []
    monkeypatch.setenv("CRA_APP_ORIGIN", "https://cra.example.test")
    monkeypatch.setenv("CRA_ALERTS_FROM", "alerts@example.test")
    monkeypatch.delenv("CRA_SIGNUP_INVITE_CODE", raising=False)
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "1")
    monkeypatch.setattr(
        signup.mailer,
        "send",
        lambda **kw: sent.append(kw) or "msg-1",
    )
    return sent


def _email() -> str:
    return f"{uuid.uuid4().hex[:12]}@example.test"


def _link_from(outbox) -> str:
    body = outbox[-1]["plain"]
    url = next(w for w in body.split() if w.startswith("https://"))
    return url.split("t=", 1)[1]


# ---- requesting --------------------------------------------------------------


def test_a_request_sends_a_single_use_link(outbox):
    email = _email()
    out = signup.request_access(email)
    assert out["ok"] is True
    assert len(outbox) == 1
    assert outbox[0]["to_email"] == email
    assert "https://cra.example.test/api/access/complete?t=" in outbox[0]["plain"]


def test_the_token_is_never_emailed(outbox):
    """A credential in an inbox outlives its usefulness by years."""
    signup.request_access(_email())
    body = outbox[0]["plain"] + outbox[0]["html"]
    assert "cra_" not in body


def test_no_account_exists_until_the_link_is_opened(outbox):
    email = _email()
    signup.request_access(email)
    with session_scope() as s:
        assert s.execute(select(User).where(User.email == email)).scalar_one_or_none() is None


def test_the_answer_does_not_reveal_whether_the_address_is_known(outbox):
    """Enumeration. A stranger does not get to learn who has an account."""
    known = _email()
    signup.request_access(known)
    first = signup.request_access(known)
    second = signup.request_access(_email())
    assert first["message"] == second["message"]


def test_a_bad_address_is_refused(outbox):
    for bad in ("", "   ", "not-an-email", "@example.test", "a@b"):
        with pytest.raises(signup.SignupError):
            signup.request_access(bad)
    assert outbox == []


def test_one_address_cannot_be_mail_bombed(outbox):
    """Rate limiting is by IP, which does not protect the person being
    targeted. The cap is per address, and hitting it still answers normally so
    the attacker learns nothing."""
    victim = _email()
    for _ in range(6):
        out = signup.request_access(victim)
        assert out["ok"] is True
    assert len(outbox) == 3


def test_signup_can_be_closed(outbox, monkeypatch):
    monkeypatch.setenv("CRA_SIGNUP_ENABLED", "0")
    with pytest.raises(signup.SignupError, match="closed"):
        signup.request_access(_email())
    assert outbox == []


def test_an_invite_code_gates_without_an_operator(outbox, monkeypatch):
    monkeypatch.setenv("CRA_SIGNUP_INVITE_CODE", "let-me-in")
    with pytest.raises(signup.SignupError, match="invite code"):
        signup.request_access(_email(), invite_code="wrong")
    assert outbox == []
    assert signup.request_access(_email(), invite_code="let-me-in")["ok"] is True


def test_a_deployment_with_no_origin_sends_nothing(outbox, monkeypatch):
    """A link with no origin is not a link — fail to the operator rather than
    mail something unusable to a stranger."""
    monkeypatch.delenv("CRA_APP_ORIGIN", raising=False)
    with pytest.raises(signup.SignupError, match="CRA_APP_ORIGIN"):
        signup.request_access(_email())
    assert outbox == []


# ---- completing --------------------------------------------------------------


def test_completing_creates_a_verified_account_and_a_usable_token(outbox):
    email = _email()
    signup.request_access(email)
    out = signup.complete(_link_from(outbox))

    assert out["new_account"] is True
    assert out["token"].startswith("cra_")

    verified = connector_tokens.verify_token(out["token"])
    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalar_one()
    assert verified.user_id == user.id
    assert verified.product_id is None       # user-wide, not product-scoped
    assert user.email_verified_at is not None
    assert user.terms_accepted_at is not None
    assert user.terms_version == signup.TERMS_VERSION


def test_only_a_hash_of_the_secret_is_stored(outbox):
    """A database dump must contain nothing redeemable."""
    signup.request_access(_email())
    secret = _link_from(outbox).split(".", 1)[1]
    with session_scope() as s:
        rows = list(s.execute(select(SignupLink)).scalars())
    assert all(secret not in r.secret_sha256 for r in rows if r.secret_sha256)
    assert all(len(r.secret_sha256) == 64 for r in rows if r.secret_sha256)


def test_a_link_works_exactly_once(outbox):
    signup.request_access(_email())
    link = _link_from(outbox)
    assert signup.complete(link)["ok"] is True
    with pytest.raises(signup.SignupError, match="no longer valid"):
        signup.complete(link)


def test_an_expired_link_is_refused(outbox):
    signup.request_access(_email())
    link = _link_from(outbox)
    with session_scope() as s:
        row = s.get(SignupLink, link.split(".", 1)[0])
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(signup.SignupError, match="no longer valid"):
        signup.complete(link)


def test_a_forged_secret_is_refused(outbox):
    signup.request_access(_email())
    link_id = _link_from(outbox).split(".", 1)[0]
    with pytest.raises(signup.SignupError, match="no longer valid"):
        signup.complete(f"{link_id}.not-the-secret")


def test_every_failure_reads_the_same(outbox):
    """Expired, spent, forged and unknown are all "not usable". Telling them
    apart tells someone holding a stolen link which part to attack."""
    signup.request_access(_email())
    link = _link_from(outbox)
    signup.complete(link)                                   # spend it
    messages = set()
    for bad in (link, f"{uuid.uuid4()}.x", f"{link.split('.')[0]}.wrong"):
        try:
            signup.complete(bad)
        except signup.SignupError as e:
            messages.add(str(e))
    assert len(messages) == 1


def test_malformed_links_are_refused_without_touching_the_database(outbox):
    for bad in ("", "no-dot", "not-a-uuid.secret", "."):
        with pytest.raises(signup.SignupError):
            signup.complete(bad)


def test_an_existing_account_gets_a_new_token_not_a_second_account(outbox):
    """The same flow is the 'I lost my token' path, so it cannot rot."""
    email = _email()
    signup.request_access(email)
    first = signup.complete(_link_from(outbox))
    signup.request_access(email)
    second = signup.complete(_link_from(outbox))

    assert second["new_account"] is False
    assert first["token"] != second["token"]
    with session_scope() as s:
        users = list(s.execute(select(User).where(User.email == email)).scalars())
        tokens = list(
            s.execute(select(ConnectorToken).where(ConnectorToken.user_id == users[0].id)).scalars()
        )
    assert len(users) == 1
    assert len(tokens) == 2  # the old one keeps working until revoked


def test_the_address_is_normalised(outbox):
    email = _email()
    signup.request_access(f"  {email.upper()}  ")
    out = signup.complete(_link_from(outbox))
    assert out["email"] == email


# ---- codes, for the OAuth consent page ---------------------------------------


def _code_from(outbox) -> str:
    body = outbox[-1]["plain"]
    return next(w for w in body.replace("\n", " ").split() if w.isdigit() and len(w) == 6)


def test_a_code_challenge_verifies_an_address(outbox):
    email = _email()
    cid = signup.start_code_challenge(email, client_name="Claude")
    out = signup.verify_code(cid, _code_from(outbox))

    assert out["email"] == email
    assert out["new_account"] is True
    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalar_one()
    assert out["user_id"] == user.id
    assert user.email_verified_at is not None
    assert user.terms_accepted_at is not None


def test_verifying_a_code_mints_nothing(outbox):
    """The proof and what it is worth are separate decisions. The OAuth path
    turns this into a grant for one named client — narrower than the token
    `complete()` hands over — so this must not issue a token of its own."""
    email = _email()
    cid = signup.start_code_challenge(email, client_name="Claude")
    result = signup.verify_code(cid, _code_from(outbox))

    assert "token" not in result
    with session_scope() as s:
        user = s.execute(select(User).where(User.email == email)).scalar_one()
        tokens = list(
            s.execute(
                select(ConnectorToken).where(ConnectorToken.user_id == user.id)
            ).scalars()
        )
    assert tokens == []


def test_the_code_is_never_stored(outbox):
    """Same rule as the link: a database dump contains nothing redeemable."""
    signup.start_code_challenge(_email(), client_name="Claude")
    code = _code_from(outbox)
    with session_scope() as s:
        rows = list(s.execute(select(SignupLink)).scalars())
    assert all(r.code_sha256 != code for r in rows)
    assert all(len(r.code_sha256) == 64 for r in rows if r.code_sha256)


def test_the_email_names_the_client_and_escapes_it(outbox):
    """The client name comes from dynamic client registration, which anyone can
    call. It is attacker-controlled text going into an HTML email."""
    signup.start_code_challenge(_email(), client_name='<script>alert(1)</script>')
    assert "<script>" not in outbox[-1]["html"]
    assert "&lt;script&gt;" in outbox[-1]["html"]


def test_five_wrong_codes_spend_the_challenge(outbox):
    """Six digits is twenty bits. Attempt counting is the entire defence — and
    burning the row means guessing again costs another email in the victim's
    inbox, which is the loudest signal available."""
    email = _email()
    cid = signup.start_code_challenge(email, client_name="Claude")
    real = _code_from(outbox)
    wrong = "000000" if real != "000000" else "111111"

    for _ in range(5):
        with pytest.raises(signup.SignupError):
            signup.verify_code(cid, wrong)

    # Even the right code no longer works — the row was spent by the guessing.
    with pytest.raises(signup.SignupError):
        signup.verify_code(cid, real)


def test_a_code_works_exactly_once(outbox):
    cid = signup.start_code_challenge(_email(), client_name="Claude")
    code = _code_from(outbox)
    assert signup.verify_code(cid, code)["ok"] is True
    with pytest.raises(signup.SignupError):
        signup.verify_code(cid, code)


def test_an_expired_code_is_refused(outbox):
    cid = signup.start_code_challenge(_email(), client_name="Claude")
    with session_scope() as s:
        s.get(SignupLink, cid).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(signup.SignupError):
        signup.verify_code(cid, _code_from(outbox))


def test_a_code_is_not_redeemable_as_a_link_and_vice_versa(outbox):
    """The two proofs are worth different things — a code authorizes one named
    client, a link hands over an account-wide token. Neither may be spent where
    the other was meant to go."""
    email = _email()
    cid = signup.start_code_challenge(email, client_name="Claude")
    code = _code_from(outbox)
    # A code challenge is not a link, even knowing its id.
    with pytest.raises(signup.SignupError):
        signup.complete(f"{cid}.{code}")

    signup.request_access(email)
    link = _link_from(outbox)
    link_id, secret = link.split(".", 1)
    with pytest.raises(signup.SignupError):
        signup.verify_code(link_id, secret)
    # And neither attempt spent the other's challenge.
    assert signup.verify_code(cid, code)["ok"] is True
    assert signup.complete(link)["ok"] is True


def test_codes_and_links_share_one_per_address_cap(outbox):
    """What is being limited is mail arriving in someone's inbox, so the two
    kinds are counted together — otherwise the cap is just twice as large."""
    victim = _email()
    for _ in range(3):
        signup.start_code_challenge(victim, client_name="Claude")
    assert len(outbox) == 3
    signup.request_access(victim)          # silently suppressed
    with pytest.raises(signup.SignupError, match="Too many codes"):
        signup.start_code_challenge(victim, client_name="Claude")
    assert len(outbox) == 3


def test_a_capped_code_request_does_not_reveal_the_account(outbox):
    """The cap message has to be sayable out loud — the user is watching a box
    that needs a code, so it cannot silently succeed the way links do."""
    victim = _email()
    for _ in range(3):
        signup.start_code_challenge(victim, client_name="Claude")
    with pytest.raises(signup.SignupError) as capped:
        signup.start_code_challenge(victim, client_name="Claude")
    assert "account" not in str(capped.value).lower()


def test_a_malformed_code_challenge_is_refused(outbox):
    for cid, code in (("", "123456"), ("not-a-uuid", "123456"), (str(uuid.uuid4()), "123456")):
        with pytest.raises(signup.SignupError):
            signup.verify_code(cid, code)
    cid = signup.start_code_challenge(_email(), client_name="Claude")
    for bad in ("", "12345", "1234567", "abcdef"):
        with pytest.raises(signup.SignupError):
            signup.verify_code(cid, bad)


def test_spacing_in_a_typed_code_is_forgiven(outbox):
    """People retype what they see, and mail clients break digits into groups."""
    cid = signup.start_code_challenge(_email(), client_name="Claude")
    code = _code_from(outbox)
    assert signup.verify_code(cid, f" {code[:3]} {code[3:]} ")["ok"] is True


def test_a_failed_code_send_does_not_consume_the_cap(outbox, monkeypatch):
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: (_ for _ in ()).throw(RuntimeError("SES")))
    email = _email()
    for _ in range(4):
        with pytest.raises(signup.SignupError, match="could not be sent"):
            signup.start_code_challenge(email, client_name="Claude")
    with session_scope() as s:
        assert list(s.execute(select(SignupLink).where(SignupLink.email == email)).scalars()) == []


def test_a_failed_send_does_not_consume_the_per_address_cap(outbox, monkeypatch):
    """Found by the first real signup against production: the row is written
    before the send, so a delivery failure left a link nobody received. Three
    of those would lock an address out for fifteen minutes over an outage that
    was never the user's fault."""
    def boom(**kw):
        raise RuntimeError("SES is having a day")

    monkeypatch.setattr(signup.mailer, "send", boom)
    email = _email()
    for _ in range(4):
        with pytest.raises(signup.SignupError, match="could not be sent"):
            signup.request_access(email)

    with session_scope() as s:
        stranded = list(
            s.execute(select(SignupLink).where(SignupLink.email == email)).scalars()
        )
    assert stranded == []

    # And the address is still usable the moment delivery recovers.
    monkeypatch.setattr(signup.mailer, "send", lambda **kw: outbox.append(kw) or "ok")
    assert signup.request_access(email)["ok"] is True
    assert signup.complete(_link_from(outbox))["ok"] is True


def test_a_code_is_only_spendable_on_the_purpose_it_was_issued_for(outbox):
    """Both codes prove the same address; they are not worth the same thing.
    One mailed to connect an app must not open somebody's billing page.

    This held by accident and then stopped: generalising the purpose updated
    the write side and silently missed the read side, so every billing code was
    checked against the OAuth purpose. A browser test caught it — this one
    states the rule directly."""
    email = _email()
    oauth_cid = signup.start_code_challenge(email, client_name="Claude")
    oauth_code = _code_from(outbox)

    with pytest.raises(signup.SignupError):
        signup.verify_code(oauth_cid, oauth_code, purpose=signup.PURPOSE_BILLING)
    # Still spendable for what it was actually for.
    assert signup.verify_code(oauth_cid, oauth_code)["ok"] is True

    billing_cid = signup.start_code_challenge(
        email, purpose=signup.PURPOSE_BILLING, what="Someone asked to subscribe."
    )
    billing_code = _code_from(outbox)
    with pytest.raises(signup.SignupError):
        signup.verify_code(billing_cid, billing_code)          # defaults to OAuth
    assert signup.verify_code(
        billing_cid, billing_code, purpose=signup.PURPOSE_BILLING
    )["ok"] is True


def test_an_unknown_purpose_is_refused_at_issue_time(outbox):
    with pytest.raises(ValueError):
        signup.start_code_challenge(_email(), purpose="whatever", what="x")
    assert outbox == []


def test_the_code_email_says_what_it_is_for(outbox):
    """A code arriving with no stated reason is indistinguishable from a
    phishing attempt, and that sentence is the recipient's only defence."""
    signup.start_code_challenge(
        _email(), purpose=signup.PURPOSE_BILLING,
        what="Someone asked to subscribe to the team plan.",
    )
    assert "subscribe to the team plan" in outbox[-1]["plain"]
    assert "Only enter it on the page you opened yourself" in outbox[-1]["plain"]
