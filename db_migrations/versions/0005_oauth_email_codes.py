"""emailed six-digit codes, so OAuth no longer needs a pasted token

The consent page could only identify a browser by a `cra_…` token pasted into
it, which meant self-serve access issued a credential the user then had to
carry by hand to the client they actually wanted to connect. The magic link was
already a proof of address; this lets the same proof be presented as a code.

A code rather than a link, on this path only: the link opens in whatever
browser the mail is in — often a phone — while the OAuth flow waits in a tab on
a laptop, and landing the redirect in the wrong browser delivers the callback
to a client session that isn't there. A code moves nothing.

`attempts` is the substantive addition. Six digits is twenty bits, which is a
guessable space, so the row has to count wrong answers and die at five. The
link secret is 256 bits and needs no such thing — hence one nullable column
each and a check constraint rather than a second table.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing rows are all links, and the server default keeps it that way for
    # any in flight during the deploy.
    op.execute(
        "ALTER TABLE signup_links "
        "ADD COLUMN purpose VARCHAR(16) NOT NULL DEFAULT 'link'"
    )
    op.execute("ALTER TABLE signup_links ADD COLUMN code_sha256 VARCHAR(64)")
    op.execute(
        "ALTER TABLE signup_links ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
    )
    # Code rows carry no link secret.
    op.execute("ALTER TABLE signup_links ALTER COLUMN secret_sha256 DROP NOT NULL")
    op.execute(
        "ALTER TABLE signup_links ADD CONSTRAINT signup_links_has_a_secret "
        "CHECK (secret_sha256 IS NOT NULL OR code_sha256 IS NOT NULL)"
    )


def downgrade() -> None:
    # Code rows cannot survive a downgrade: the column that proves them is
    # going away, and a row with no secret would violate the restored NOT NULL.
    # They are short-lived by construction, so dropping them costs a re-request.
    op.execute("DELETE FROM signup_links WHERE secret_sha256 IS NULL")
    op.execute(
        "ALTER TABLE signup_links DROP CONSTRAINT IF EXISTS signup_links_has_a_secret"
    )
    op.execute("ALTER TABLE signup_links ALTER COLUMN secret_sha256 SET NOT NULL")
    op.execute("ALTER TABLE signup_links DROP COLUMN IF EXISTS attempts")
    op.execute("ALTER TABLE signup_links DROP COLUMN IF EXISTS code_sha256")
    op.execute("ALTER TABLE signup_links DROP COLUMN IF EXISTS purpose")
