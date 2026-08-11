#!/usr/bin/env python
"""Drive the whole product end to end and print what happens.

Two acts, because the tool has two halves that get used at very different
times:

  Act 1 — the incident. A vulnerability turns out to be actively exploited at
          09:00 on a Monday. Watch the clocks start on their own.
  Act 2 — the quiet work. The Annex I checklist, the technical file, the
          declaration, the signature.

Reads and writes a real database. Point DATABASE_URL at a scratch one:

    DATABASE_URL=postgresql+psycopg://localhost/cra_demo \\
    CRA_STORE=pg .venv/bin/python scripts/demo.py

Idempotent in the sense that matters — it creates a fresh product each run, so
running it twice is safe. It does not clean up after itself; that is what a
scratch database is for.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

if not os.environ.get("DATABASE_URL"):
    sys.exit(
        "DATABASE_URL is not set. This demo writes real rows — point it at a "
        "scratch database, not one you care about.\n\n"
        "  DATABASE_URL=postgresql+psycopg://localhost/cra_demo \\\n"
        "  CRA_STORE=pg .venv/bin/python scripts/demo.py"
    )
os.environ.setdefault("CRA_STORE", "pg")

from cra.agents import dispatch as dispatcher  # noqa: E402
from cra.db import User, session_scope  # noqa: E402
from cra.regulation import requirements, technical_file_slots  # noqa: E402
from cra.schemas import ComplianceState, MemberInfo, Role  # noqa: E402
from cra.server import store_pg  # noqa: E402

UTC = timezone.utc

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[0m",
)


def heading(text: str) -> None:
    print(f"\n{BOLD}{'─' * 72}\n{text}\n{'─' * 72}{RESET}")


def call(name: str, product_id: str, actor: str, **args) -> dict:
    """Invoke a tool exactly as the MCP layer does, and show the result."""
    result = dispatcher.dispatch(name, product_id, actor, args)
    mark = f"{GREEN}ok{RESET}" if result.get("ok") else f"{RED}refused{RESET}"
    shown = {k: v for k, v in args.items() if v not in (None, "", [])}
    print(f"\n{BOLD}{name}{RESET}({DIM}{json.dumps(shown, default=str)[:110]}{RESET}) → {mark}")
    if not result.get("ok"):
        print(f"  {RED}{result.get('error')}{RESET}")
    return result


def show(result: dict, *keys: str) -> None:
    for k in keys:
        if k in result:
            v = result[k]
            if isinstance(v, (dict, list)):
                v = json.dumps(v, default=str)
            v = str(v)
            print(f"  {DIM}{k}:{RESET} {v[:300]}{'…' if len(v) > 300 else ''}")


def main() -> None:
    # A user and a product. In real use `create_product` does this; here we
    # write the row directly so the demo has a stable owner id.
    owner = str(uuid.uuid4())
    with session_scope() as s:
        s.add(User(id=owner, email=f"demo-{owner[:8]}@example.test"))
    product = str(uuid.uuid4())
    now = datetime.now(UTC)
    store_pg.save_state(
        ComplianceState(
            product_id=product,
            name="Acme Gateway",
            description="A self-hosted API gateway shipped to EU customers.",
            members={owner: MemberInfo(role=Role.OWNER, user_id=owner, joined_at=now)},
            created_at=now,
            updated_at=now,
        )
    )
    print(f"{DIM}product {product}\nowner   {owner}{RESET}")

    # ---- Act 1: the incident -------------------------------------------------

    heading("ACT 1 — Monday 09:00. A CVE turns out to be exploited in the wild.")

    print(
        f"\n{DIM}First, the thing you should have done weeks ago. Note that\n"
        f"EU Login enrolment cannot be arranged inside a 24-hour window.{RESET}"
    )
    r = call("check_reporting_readiness", product, owner)
    show(r, "ready", "summary")
    for b in r["blockers"]:
        print(f"  {YELLOW}✗{RESET} {b['item']}: {b['why'][:90]}")

    call(
        "set_submitter_profile",
        product,
        owner,
        legal_name="Acme Oy",
        member_states_available=["FI", "SE", "DE"],
        eu_login_registered=True,
        srp_registered=True,
        security_contact="security@acme-gateway.example.com",
    )
    show(call("check_reporting_readiness", product, owner), "ready", "summary")

    print(f"\n{DIM}A vulnerability comes in. Nothing legal happens yet.{RESET}")
    v = call(
        "record_vulnerability",
        product,
        owner,
        summary="Unauthenticated RCE in the config parser",
        identifier="CVE-2026-1234",
        severity="9.8",
    )
    show(v, "actively_exploited", "note")

    print(
        f"\n{DIM}Then a customer sends log evidence of exploitation. This one\n"
        f"flag is what the CRA's reporting duty turns on — not severity.{RESET}"
    )
    r = call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        actively_exploited=True,
    )
    show(r, "incident_id", "urgent")
    for d in r["deadlines"]:
        print(f"  {YELLOW}⏱{RESET}  {d['stage']:<14} due {d['due_at'][:16]}  "
              f"({d['hours_remaining']}h)  [{d['state']}]")
    print(f"  {DIM}not yet scheduled: {r['not_yet_scheduled']['stages']}"
          f" — {r['not_yet_scheduled']['why'][:100]}{RESET}")
    print(f"  {DIM}{r['anchor_assumed'][:150]}…{RESET}")

    print(f"\n{DIM}And it was: reviewing the logs shows the first successful\n"
          f"exploit was 30 hours ago. The clocks run from when you became\n"
          f"AWARE — so correcting the anchor makes the early warning late,\n"
          f"which it already was.{RESET}")
    fixed = call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        became_aware_at=(now - timedelta(hours=30)).isoformat(),
        awareness_rationale="WAF logs show the first successful exploit at "
        "02:14; the on-call engineer saw the alert the same morning.",
    )
    for m in fixed["awareness_reanchored"]["deadlines_moved"]:
        print(f"  {YELLOW}⏱{RESET}  {m['stage']:<14} {m['was_due_at'][:16]}"
              f"  →  {m['now_due_at'][:16]}")
    print(f"  {RED}{fixed['backdated']}{RESET}")

    print(f"\n{DIM}What is due across everything this user owns.{RESET}")
    show(call("get_reporting_deadlines", "", owner), "counts", "attention")

    print(f"\n{DIM}Draft the early warning. It always emits, even half-empty.{RESET}")
    d = call("draft_report", product, owner, incident_id=r["incident_id"])
    show(d, "missing_required", "template_version")
    print(f"{DIM}{d['markdown']}{RESET}")

    call(
        "record_report_submission",
        product,
        owner,
        obligation_id=next(
            o["obligation_id"]
            for o in call("get_reporting_deadlines", product, owner)["deadlines"]
            if o["stage"] == "early_warning"
        ),
        submission_ref="SRP-2026-000123",
    )

    print(f"\n{DIM}The fix ships. Only now does the final report's clock start.{RESET}")
    r2 = call(
        "update_vulnerability",
        product,
        owner,
        vulnerability_id=v["vulnerability_id"],
        corrective_measure_available_at=(now + timedelta(days=3)).isoformat(),
        remediation_ref="https://acme.example/advisory/2026-01",
    )
    for o in r2.get("final_report_scheduled", []):
        print(f"  {YELLOW}⏱{RESET}  {o['stage']:<14} due {o['due_at'][:16]}")

    # ---- Act 2: the quiet work ----------------------------------------------

    heading("ACT 2 — The 2027 obligations. This is what gets used between incidents.")

    print(f"\n{DIM}Explore the classification question. Writes nothing.{RESET}")
    aid = call("classify_product", product, owner)
    for c in aid["classes"]:
        nb = "notified body" if c["notified_body_required"] else "self-assess"
        print(f"  {c['product_class']:<20} {nb:<14} {len(c['categories'])} categories")

    print(f"\n{DIM}Committing to an answer requires reasoning.{RESET}")
    call("classify_product", product, owner, product_class="default")

    c = call(
        "classify_product",
        product,
        owner,
        product_class="default",
        in_scope=True,
        rationale="An API gateway is not a network management system or a "
        "firewall; no Annex III category matches.",
    )
    show(c, "conformity_route", "notified_body_required", "requirements_seeded")
    show(c, "next")

    print(f"\n{DIM}Article 13(2) first. Annex I Part I applies *on the basis of*\n"
          f"the risk assessment, so the checklist cannot honestly be answered\n"
          f"before it exists.{RESET}")
    frame = call(
        "start_risk_assessment",
        product,
        owner,
        method="STRIDE, informed by ISO/IEC 27005",
        intended_purpose="Routes and authenticates north-south traffic for "
        "enterprise customers' internal services.",
        foreseeable_misuse="Operators expose the admin listener to the public "
        "internet, or run it as the only auth boundary.",
        conditions_of_use="Customer-operated Kubernetes, versions pinned by the "
        "customer, upgrades on their schedule.",
        support_duration_note="Five years from GA, matching the CRA minimum.",
    )
    print(f"  {DIM}the agent is handed {len(frame['map_risks_onto'])} Part I "
          f"requirements to map risks onto{RESET}")

    print(f"\n{DIM}The agent drafts — it can see the code, the dependencies and\n"
          f"the deployment. Nothing it proposes determines anything.{RESET}")
    drafted = call(
        "propose_risks",
        product,
        owner,
        basis="repository at 9f2a1c4, Helm chart, dependency manifest",
        model="claude-opus-5",
        risks=[
            {
                "title": "Admin API reachable without authentication",
                "asset": "administrative control plane",
                "threat": "an unauthenticated caller rewrites routing rules",
                "attack_vector": "admin listener bound to 0.0.0.0 by default",
                "preconditions": "operator does not override the default bind",
                "impact": "full interception of customer traffic",
                "affects_requirements": ["annex_i.i.2.e", "annex_i.i.2.f"],
            },
            {
                "title": "Upstream TLS verification disabled by a convenience flag",
                "asset": "traffic in transit to backends",
                "threat": "machine-in-the-middle between gateway and backend",
                "attack_vector": "insecure_skip_verify left on from a debug session",
                "impact": "silent disclosure and tampering",
                "affects_requirements": ["annex_i.i.2.f", "annex_i.i.2.g"],
            },
        ],
    )
    show(drafted, "determined_nothing")

    print(f"\n{DIM}Requirements are untouched — a draft is a draft.{RESET}")
    still = next(
        x
        for x in call("list_requirements", product, owner)["requirements"]
        if x["req_id"] == "annex_i.i.2.e"
    )
    print(f"  annex_i.i.2.e applicability: {YELLOW}{still['applicability']}{RESET}")

    print(f"\n{DIM}Accepting one without saying what you will do about it is\n"
          f"refused. 'We live with it' is an answer; silence is not.{RESET}")
    call(
        "decide_risk",
        product,
        owner,
        risk_id="risk-001",
        decision="accept",
        rationale="Confirmed against the default Helm values.",
    )

    print(f"\n{DIM}The human decides each one. This is the act that counts.{RESET}")
    call(
        "decide_risk",
        product,
        owner,
        risk_id="risk-001",
        decision="accept",
        treatment="mitigate",
        rationale="Real: the chart's default values do bind the admin listener "
        "to 0.0.0.0. Mitigated by requiring mTLS and changing the default.",
    )
    call(
        "decide_risk",
        product,
        owner,
        risk_id="risk-002",
        decision="accept",
        treatment="mitigate",
        rationale="The flag exists and is undocumented. Removing it and failing "
        "closed instead.",
    )

    print(f"\n{DIM}Confirming freezes the assessment and sets applicability from\n"
          f"the accepted risks — and never rules anything out.{RESET}")
    confirmed = call(
        "confirm_risk_assessment",
        product,
        owner,
        rationale="Reviewed with the platform team against the shipped chart "
        "and the 2.4 release branch.",
    )
    show(confirmed, "content_hash", "requirements_made_applicable")
    print(f"  {DIM}still undetermined (NOT ruled out): "
          f"{len(confirmed['still_undetermined'])} Part I requirements{RESET}")
    print(f"  {DIM}{confirmed['still_undetermined_note'][:150]}…{RESET}")

    print(f"\n{DIM}The checklist, seeded from Annex I. Everything is a gap.{RESET}")
    show(call("list_requirements", product, owner, filter="gaps"), "gaps_total", "next")

    print(f"\n{DIM}not_applicable without reasoning is refused.{RESET}")
    call(
        "update_requirement",
        product,
        owner,
        req_id="annex_i.i.2.m",
        applicability="not_applicable",
    )

    print(f"\n{DIM}Working through them properly.{RESET}")
    for req in requirements():
        call_args = dict(
            req_id=req.id, applicability="applicable", status="verified"
        )
        dispatcher.dispatch("update_requirement", product, owner, call_args)
        dispatcher.dispatch(
            "attach_evidence",
            product,
            owner,
            {
                "subject_ref": f"requirement:{req.id}",
                "title": f"Evidence for {req.anchor}",
                "body": json.dumps({"requirement": req.id, "result": "pass"}),
                "source_ref": "git:9f2a1c4",
            },
        )
    for slot in technical_file_slots():
        if slot.satisfied_by or slot.auto_from_part:
            continue
        dispatcher.dispatch(
            "attach_evidence",
            product,
            owner,
            {
                "subject_ref": f"technical_file:{slot.id}",
                "title": slot.title,
                "body": f"Content for {slot.anchor}.",
                "source_ref": "git:9f2a1c4",
            },
        )
    print(f"  {GREEN}✓{RESET} {len(requirements())} requirements settled with evidence")

    print(f"\n{DIM}Annex VII, as a gap report.{RESET}")
    tf = call("assemble_technical_file", product, owner)
    for s in tf["slots"]:
        mark = f"{GREEN}✓{RESET}" if s["complete"] else f"{YELLOW}…{RESET}"
        print(f"  {mark} {s['slot']:<6} {s['title'][:52]}")
    show(tf, "missing_slots", "deferred_slots")

    print(f"\n{DIM}Freeze → declare → re-freeze → sign. That order is forced by\n"
          f"Annex VII(7) holding a copy of the declaration.{RESET}")
    first = call("assemble_technical_file", product, owner, finalize=True)
    show(first, "content_hash", "next")

    doc = call(
        "generate_declaration_of_conformity",
        product,
        owner,
        standards_applied="EN 18031-1 applied in full",
    )
    show(doc, "technical_file_hash", "missing_fields")

    second = call("assemble_technical_file", product, owner, finalize=True)
    show(second, "content_hash", "deferred_slots")

    sig = call(
        "sign_off",
        product,
        owner,
        signer_name="P. Virtanen",
        signer_role="CTO",
        statement="I attest that this technical file is complete and accurate.",
    )
    show(sig, "bound_to_hash")

    print(f"\n{DIM}Now edit the file and watch the signature go stale.{RESET}")
    dispatcher.dispatch(
        "attach_evidence",
        product,
        owner,
        {
            "subject_ref": "technical_file:tf.6",
            "title": "Second penetration test round",
            "body": "Retest after the 2026-01 advisory.",
            "source_ref": "git:aa71fe0",
        },
    )
    call("assemble_technical_file", product, owner, finalize=True)
    status = call("get_conformity_status", product, owner)
    for a in status["attestations"]:
        state = (
            f"{GREEN}current{RESET}"
            if a["covers_current_version"]
            else f"{RED}STALE — signed against a superseded version{RESET}"
        )
        print(f"  {a['signer_name']} ({a['signer_role']}): {state}")

    heading("The trail an auditor reads")
    for e in call("get_recent_activity", product, owner, limit=12)["events"]:
        print(f"  {e['ts'][:19]}  {e['op']:<34} {e['actor_kind']:<6} {e['accountable_user_id'][:8]}")

    print(
        f"\n{DIM}Every mutation above wrote its audit row in the same "
        f"transaction as the change.\nproduct id: {product}{RESET}\n"
    )


if __name__ == "__main__":
    main()
