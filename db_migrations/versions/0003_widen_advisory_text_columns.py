"""widen advisory_candidates.severity and .disposition to TEXT

Both were sized against imagined values rather than real ones, and the first
production scan against a real SBOM failed on the insert.

`severity` was String(32). OSV puts a CVSS *vector* in `severity.score`, not a
number — 44 characters for v3.1, 63 for v4.0. A fixed width here is a bet
against the next CVSS revision, so it becomes TEXT rather than a bigger number.

`disposition` was String(48), and the longest VEX justification this repo
defines — "vulnerable_code_cannot_be_controlled_by_adversary" — is 49. A closed
vocabulary defined in this codebase did not fit a column defined in this
codebase, and no test caught it because they all used the shorter members.

Widening only: no data can be lost, and nothing had been written to either
column before this ran.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE advisory_candidates ALTER COLUMN severity TYPE TEXT")
    op.execute("ALTER TABLE advisory_candidates ALTER COLUMN disposition TYPE TEXT")


def downgrade() -> None:
    # Narrowing can truncate. Anything stored under the wider type may not fit,
    # so this fails loudly on real data rather than silently discarding a CVSS
    # vector or a justification.
    op.execute(
        "ALTER TABLE advisory_candidates ALTER COLUMN severity TYPE VARCHAR(32)"
    )
    op.execute(
        "ALTER TABLE advisory_candidates ALTER COLUMN disposition TYPE VARCHAR(48)"
    )
