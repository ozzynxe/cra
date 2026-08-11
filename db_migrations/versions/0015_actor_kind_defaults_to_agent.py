"""actor_kind defaults to agent, and the evidence rows that never said so

Issue #46, second pass. The first fixed eleven handlers that passed
`actor_kind="human"` to `audit.record`, and a source sweep now keeps them
fixed. It did not touch either column's `server_default`, both of which still
said `human`:

  * `audit_events.actor_kind` — harmless in practice, because `record()`'s
    Python default is `agent` and everything goes through it. But a default
    that disagrees with the only writer is a trap for the next one.

  * `evidence.actor_kind` — not harmless. **No code has ever assigned this
    column.** All eight `Evidence(...)` construction sites leave it out, and
    six of them build artefacts the server generates itself: the technical
    file snapshot, the Declaration of Conformity, the risk assessment
    snapshot, the SRP draft, the Annex I Pt I(2)(a) determination. So every
    value in the column is the default's, and every `human` in it was a claim
    the schema made about a row nobody looked at, in the table a technical
    file cites.

Both defaults become `agent`.

The backfill is `evidence` only, and it is not a tidy-up. Because no writer
has ever set the column, `human` cannot be anybody's assertion — it is
provably the default, for every row, and correcting a value the system
invented about itself is not editing someone's record.

`audit_events` is deliberately left alone. Fifteen rows written before the
handler fix say `human`, and that trail is append-only: it is retained so an
authority can see what was recorded at the time, which includes what we
recorded wrongly. Rewriting it to look better afterwards is the one thing it
must not do.
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("evidence", "actor_kind", server_default="agent")
    op.alter_column("audit_events", "actor_kind", server_default="agent")
    op.execute("UPDATE evidence SET actor_kind = 'agent' WHERE actor_kind = 'human'")


def downgrade() -> None:
    # The rows are not put back. See the module docstring: `human` was never a
    # claim anyone made, so there is nothing to restore it to.
    op.alter_column("evidence", "actor_kind", server_default="human")
    op.alter_column("audit_events", "actor_kind", server_default="human")
