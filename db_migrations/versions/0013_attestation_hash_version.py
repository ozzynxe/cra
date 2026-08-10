"""record which definition of "file content" a signature was taken over

The technical-file hash is computed over a payload. On 2026-08-10 that payload
widened to include what each requirement and Annex II item actually says, having
previously carried only counts of them — so an implementation note could be
rewritten after signature and the digest would not move.

Widening it changes every hash. Without a version recorded alongside, an
existing signature would compare unequal to the new digest and report as no
longer covering the current version — asserting that the file changed when what
changed was the ruler. This column is what lets the two be told apart.

NULL means signed before this existed, i.e. under payload version 1. Those
cannot be recomputed here and are reported as incomparable rather than as
superseded: the frozen body they were taken over is preserved in the statutory
archive and in `evidence`, so verifying one is a question for the artefact
rather than for this table.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE attestations "
        "ADD COLUMN hash_payload_version INTEGER"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE attestations DROP COLUMN hash_payload_version")
