#!/usr/bin/env python
"""Carry existing product state across the Annex I Part I renumbering.

The catalogue used to number Part I as (1), (2), (3)(a)-(l). The regulation
numbers it (1), then (2)(a)-(m) under a single chapeau: there is no point (3),
and every letter was shifted by one. Reconciling against the published text on
2026-08-06 fixed the catalogue; this fixes the data that already cites it.

Without it, `_seed_requirements` — which is idempotent *by id* — would treat the
corrected ids as new and append thirteen fresh, empty requirements beside the
thirteen the team had already worked, leaving 27 entries and two answers for
every question.

What moves:

  products.state    requirements[].req_id, and risk_assessment.risks[]
                    .affects_requirements + requirements[].risk_basis, which
                    are the links the risk assessment established
  evidence          subject_ref "requirement:<old>" → "requirement:<new>"

What deliberately does not move:

  audit_events      Append-only. Those rows record what someone did at the time,
                    under the id the tool showed them. Rewriting history to look
                    consistent is the opposite of what an audit trail is for —
                    the migration writes its own row instead.

  attestations      A signature binds to a content hash of the frozen file. That
                    hash is a fact about a version that was signed; changing the
                    ids underneath it would silently alter what was attested.
                    `get_conformity_status` will report the signature stale,
                    which is correct — the file it covered cited provisions that
                    do not exist.

Idempotent: rows already carrying new ids are left alone, so a re-run is a
no-op. Run it once per environment, after deploying the corrected catalogue.

    docker cp scripts/migrate_annex_i_ids.py cra:/tmp/m.py
    docker exec cra python /tmp/m.py --dry-run
    docker exec cra python /tmp/m.py
"""

from __future__ import annotations

import argparse
import os
import sys

if not os.environ.get("DATABASE_URL"):
    sys.exit("DATABASE_URL is not set.")

from sqlalchemy import select

from cra.db import Evidence, Product, session_scope
from cra.schemas import ComplianceState
from cra.server import audit, store_pg

# old id -> new id. The bare (2) became (2)(a); (3)(x) became (2)(x+1).
RENAMES: dict[str, str] = {"annex_i.i.2": "annex_i.i.2.a"}
for _old in "abcdefghijkl":
    RENAMES[f"annex_i.i.3.{_old}"] = f"annex_i.i.2.{chr(ord(_old) + 1)}"


def _remap(state: ComplianceState) -> dict:
    """Rewrite every reference in one product's blob. Returns what changed."""
    changed: dict = {"requirements": [], "risk_basis": [], "affects_requirements": []}

    for item in state.requirements:
        new = RENAMES.get(item.req_id)
        if new:
            changed["requirements"].append({"from": item.req_id, "to": new})
            item.req_id = new
        remapped = [RENAMES.get(r, r) for r in item.risk_basis]
        if remapped != item.risk_basis:
            changed["risk_basis"].append({"req_id": item.req_id, "to": remapped})
            item.risk_basis = remapped

    ra = state.risk_assessment
    if ra is not None:
        for risk in ra.risks:
            remapped = [RENAMES.get(r, r) for r in risk.affects_requirements]
            if remapped != risk.affects_requirements:
                changed["affects_requirements"].append(
                    {"risk_id": risk.risk_id, "to": remapped}
                )
                risk.affects_requirements = remapped

    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="report, change nothing")
    args = ap.parse_args()

    with session_scope() as db:
        product_ids = [p.id for p in db.execute(select(Product)).scalars()]

    touched = evidence_moved = 0
    for pid in product_ids:
        try:
            state = store_pg.load_state(pid)
        except FileNotFoundError:
            continue

        changed = _remap(state)
        n = sum(len(v) for v in changed.values())

        with session_scope() as db:
            rows = [
                e
                for e in db.execute(
                    select(Evidence).where(Evidence.product_id == pid)
                ).scalars()
                if e.subject_ref.startswith("requirement:")
                and e.subject_ref.split(":", 1)[1] in RENAMES
            ]
            if not n and not rows:
                continue

            print(f"{pid}  {state.name}")
            for r in changed["requirements"]:
                print(f"    requirement {r['from']} → {r['to']}")
            for e in rows:
                new_ref = "requirement:" + RENAMES[e.subject_ref.split(":", 1)[1]]
                print(f"    evidence {e.id[:8]} {e.subject_ref} → {new_ref}")
                if not args.dry_run:
                    e.subject_ref = new_ref
                evidence_moved += 1
            for r in changed["risk_basis"]:
                print(f"    risk_basis on {r['req_id']} → {r['to']}")
            for r in changed["affects_requirements"]:
                print(f"    {r['risk_id']}.affects_requirements → {r['to']}")

            if not args.dry_run:
                audit.record(
                    db,
                    product_id=pid,
                    subject_type="product",
                    op="migrate_annex_i_ids",
                    accountable_user_id=None,
                    actor_kind="human",
                    rationale=(
                        "Annex I Part I renumbered to the published text "
                        "(CELEX 32024R2847, verified 2026-08-06): (2) became "
                        "(2)(a) and (3)(a)-(l) became (2)(b)-(m). No point (3) "
                        "exists in the regulation."
                    ),
                    payload={
                        "renames": changed["requirements"],
                        "evidence_rows": len(rows),
                    },
                )

        if not args.dry_run:
            store_pg.save_state(state)
        touched += 1

    verb = "would update" if args.dry_run else "updated"
    print(f"\n{verb} {touched} product(s), {evidence_moved} evidence row(s).")
    if touched and not args.dry_run:
        print(
            "Any technical file frozen before this cited provisions that do not "
            "exist. get_conformity_status will report those signatures stale — "
            "re-freeze and re-sign."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
