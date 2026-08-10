"""record which build's component list a scan actually checked

`advisory_scans.sbom_source_ref` said *which* SBOM was scanned but not which
build it described, so nothing could tell whether the scan behind a release had
run against that release's components.

It could not: an end-to-end run recorded 1.0.0, then recorded 2.0.0 minutes
later with no new SBOM and no new scan, and the frozen Annex I Pt I(2)(a)
position for 2.0.0 carried the 1.0.0 scan silently. The seven-day staleness
bound is a time check, not a build check, so a same-day major release inherits
the previous build's evidence by construction.

NULL is a scan recorded before this column, or one whose SBOM carried no
version. Both are reported as unknown rather than assumed to match — the
distinction the release gate turns on.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE advisory_scans ADD COLUMN sbom_applies_to_version TEXT")


def downgrade() -> None:
    op.execute("ALTER TABLE advisory_scans DROP COLUMN sbom_applies_to_version")
