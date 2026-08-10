"""record EPSS scores and their provenance on advisory candidates

EPSS is the Exploit Prediction Scoring System: a daily probability that a CVE
will be exploited in the next 30 days, and that probability's percentile among
all scored CVEs. It informs the exploitability judgement Annex I Pt I(2)(a)
requires and never makes it — Art 3(41) turns on realistic possibility rather
than observed use, which is the gap between KEV and this requirement.

Five columns, and every one of them is nullable on purpose.

`epss_probability` / `epss_percentile` — both, always. Probability alone is the
number people act on and the number that misleads: CVE-2020-8203 scores 0.05213
on the current model, which reads as negligible and is the 91.7th percentile.

NULL means the model has not scored that CVE. A `server_default` of 0 here
would have been the natural-looking choice and would have silently converted
"nothing is known" into "negligible" for every row written before this
migration — the absence-of-knowledge-as-knowledge-of-absence trap the scanner
closes in three other places.

`epss_model_version` / `epss_score_date` — scores move when the model does, so
a stored score without both cannot be reproduced or explained later. For a
number that informed a compliance judgement that is the difference between
evidence and an assertion.

`epss_probability_at_decision` / `epss_percentile_at_decision` — the scores as
they stood when somebody dismissed the candidate, kept apart from the live pair
that every scan overwrites. What re-opens a dismissal is a material rise *since
the judgement was made*, not since last night. The trigger reads the
probability: percentile compresses near the top of the distribution, so an
advisory going from a 5% to a 71% chance of exploitation moves only 0.917 →
0.990 and a percentile rule would miss it.

Additive; no backfill is possible or wanted, since the historical scores for a
past scan date are not what the feed serves today.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_probability", sa.Float(), nullable=True),
    )
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_percentile", sa.Float(), nullable=True),
    )
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_model_version", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_score_date", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_probability_at_decision", sa.Float(), nullable=True),
    )
    op.add_column(
        "advisory_candidates",
        sa.Column("epss_percentile_at_decision", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    for column in (
        "epss_percentile_at_decision",
        "epss_probability_at_decision",
        "epss_score_date",
        "epss_model_version",
        "epss_percentile",
        "epss_probability",
    ):
        op.drop_column("advisory_candidates", column)
