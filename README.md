# Skarp CRA

An MCP server that helps software makers meet **EU Cyber Resilience Act**
(Regulation 2024/2847) obligations from inside their coding agent: scope
classification, the Article 13(2) risk assessment, Annex I requirements with
versioned evidence, vulnerability and incident records with their Article 14
reporting clocks, and the Annex VII technical file.

Not a regulation-lookup tool. It does not quote the CRA at you; it helps you
produce and maintain the artefacts that evidence compliance, in the order the
regulation actually requires them.

> **A working aid, not a compliance determination.** This server records what
> you have decided and evidenced, and shows what is missing. It cannot certify
> that a product is compliant, and it does not replace legal review or a
> notified body where the product class requires one.

---

## Hosted service

If you want to try it, there is a hosted service available. Nothing to install. Add it to Claude, Codex or another MCP client as a connector:

```
https://cra.skarp.app/mcp/me/mcp
```

You are asked for an email address and sent a six-digit code — no password, no
token to copy. **[Setup and the first three things to ask
it](https://cra.skarp.app/docs)**.


---

## Compliance timeline

| Date | What binds |
|---|---|
| **11 Sept 2026** | Reporting begins. Actively exploited vulnerabilities and severe incidents: **24h** early warning, **72h** full notification, **14 days** final report (**1 month** for severe incidents), via ENISA's Single Reporting Platform to the relevant CSIRT. |
| **11 Dec 2027** | Full application: secure-by-design, vulnerability handling, technical documentation, conformity assessment, EU Declaration of Conformity, CE marking, ≥5-year support period. |

The clocks start when the manufacturer becomes **aware** — which is why
deadline tracking, rather than document drafting, is this tool's centre of
gravity.

**The reporting duty arrives fifteen months before the obligation that makes it
survivable.** Article 71 applies the Regulation from 11 December 2027, "however,
Article 14 shall apply from 11 September 2026" — so from this September a
manufacturer owes a 24-hour notification, while Annex I Part II, which requires
a vulnerability handling *process*, does not bind until the following December.
Anyone who waits for the second date spends fifteen months answering statutory
clocks with nothing behind them.

Part II is the eight requirements the process has to satisfy — a bill of
materials, remediation without delay, regular testing, public disclosure of
fixed vulnerabilities, a coordinated disclosure policy, a contact address for
reports, and secure, free distribution of updates. This tool *operates* the
first two and records the rest against them: `record_sbom` and the nightly scan
maintain the component picture, `record_vulnerability` → `update_vulnerability`
carries a flaw to a corrective measure with its clocks attached, and
`set_submitter_profile` holds the disclosure policy and contact address that
II(5) and II(6) ask for. Publishing advisories for fixed vulnerabilities —
II(4) — is not built yet and is tracked as an open issue rather than implied by
the list above.

## Self-hosting

The hosted service is [cra.skarp.app](https://cra.skarp.app) — see the top of
this file. To run your own:

```bash
./scripts/dev_up.sh                  # venv, Postgres, migrations
.venv/bin/python scripts/demo.py     # the whole product, narrated
```

[QUICKSTART.md](QUICKSTART.md) covers connecting your own agent, including
`scripts/dev_token.py` for a local credential.
`deploy/` has the Dockerfile, the compose example and the scripts a real
deployment needs.

The MCP endpoint is `POST /mcp/me/mcp` with `Authorization: Bearer cra_…`, or
`/mcp/{product_id}/mcp` for a token scoped to one product. Configure
`DATABASE_URL` for anything but local development — see [Limitations](#limitations).

## Tools

47 tools. Grouped by the obligation they serve:

- **Scope** — `classify_product` against the Annex III/IV class lists,
  `get_applicable_csirt`, `record_sbom`, `set_support_period` with the Article
  13(8) five-year floor
- **Risk** — `start_risk_assessment` → `propose_risks` → `decide_risk` →
  `confirm_risk_assessment`, the Article 13(2) assessment everything else rests
  on
- **Requirements** — the Annex I checklist (22 requirements) and the Annex II
  user information (15 items), with `attach_evidence` storing artefacts by
  value against the release they evidence
- **Detection** — `scan_advisories` over your SBOM against OSV, CISA KEV and
  EPSS, plus a nightly sweep; `confirm_advisory` / `dismiss_advisory`
- **Reporting** — `record_vulnerability` → `update_vulnerability` →
  `report_incident` → `get_reporting_deadlines` → `record_report_submission`,
  with `draft_report` rendering ENISA's own field layout
- **Conformity** — `record_build` (free) records that a version exists;
  `place_on_market` is the legal act that starts the Article 13(13) clock, and
  the two are separate on purpose. Then `assemble_technical_file`,
  `generate_declaration_of_conformity`, `sign_off`
- **Yours to take** — `export_product` returns everything held about a product,
  and `delete_product` removes one that was never placed on the market. Both
  free, and the first will stay that way: a paywall on getting your own data out
  would make every other promise here conditional on a subscription

The regulation itself is versioned data in
[`src/cra/regulation/`](src/cra/regulation/) — Annex I Parts I and II, Annex
II, the Annex III/IV classes, the Annex VII slots and the Annex V declaration
fields — each entry carrying its own provenance.

## Design decisions

Most of the design exists to prevent one failure: **a technical file that looks
considered and is not.** These are the load-bearing decisions.

### Requirement applicability

`confirm_risk_assessment` marks the requirements that accepted risks name as
`applicable`, and leaves everything else `undetermined` — which still reads as
a gap. It never writes `not_applicable`.

That flag reads as a considered decision, and "the model did not mention it" is
not a justification. An AI-drafted assessment quietly dismissing two thirds of
Annex I Part I is the exact failure worth designing against. Ruling a
requirement out stays a deliberate act with reasoning attached, and a
requirement named by a standing accepted risk cannot be ruled out at all.

### Risk assessment workflow

The model invoking this connector is already sitting in the repository with the
code, the dependency manifest and the deployment topology — the material a risk
assessment is actually made from. A server-side model would see four free-text
fields.

So `propose_risks` takes the agent's draft, records **which model wrote it**,
and determines nothing. Only `decide_risk` — a separately recorded act with a
mandatory rationale — moves a risk to accepted, and only accepted risks touch
the checklist. There is deliberately no path that accepts and applies in one
call.

### Reporting clock anchoring

Article 14 counts from when the manufacturer became *aware*, so
`record_vulnerability` and `update_vulnerability` both take `became_aware_at`
and the cascade anchors on it.

They used to anchor on the moment of the call, which meant a team that learned
of exploitation on Friday and logged it on Monday got a 24-hour clock starting
Monday — reported as comfortably on time while roughly two days late. Omitting
the anchor still falls back to now, because the tool cannot know, but it says
so and points at the correction.

Its mirror: **a clock that has not started shows no deadline.** The final
report's 14 days run from when a corrective measure becomes available, which
has usually not happened when the incident is recorded. That obligation is
materialised later, when the anchor arrives. Showing a fabricated due date
would be worse than showing none.

### Advisory matching

`advisories.py` is the only code here that can *produce* awareness rather than
record it — and awareness starts a 24-hour clock, on the strength of a
version-range match that may be wrong: vendored patches, unreachable code,
over-broad affected ranges.

So a scan writes candidate rows and stops. It never opens an incident. A person
confirms, and the clocks anchor on when the tool notified them rather than when
they got round to agreeing. A person dismisses with a VEX justification, which
is itself Annex I Pt II(2) evidence of vulnerability handling rather than an
absence of it.

Three ways to report an absence of knowledge as knowledge of absence, all
closed: an unreachable feed reports `sources_ok: false` rather than an empty
result; components with no version or an unsupported ecosystem are counted and
named; and absence from CISA KEV is never rendered as "not exploited", because
KEV is high-precision and lags real exploitation.

#### Scanning and legal awareness

A reasonable objection: Article 14's clocks run from awareness, scanning
produces awareness, so not looking can seem like the safer option. It is not,
on three separate grounds.

**Not looking is itself a breach.** Article 13(5): "manufacturers **shall
exercise due diligence** when integrating components sourced from third parties
so that those components do not compromise the cybersecurity of the product,
including when integrating components of free and open-source software". Annex I
Pt II(1) requires you to "identify and document vulnerabilities and components",
including a bill of materials. The Regulation does not merely permit looking; it
requires it. Not scanning trades one obligation for another and keeps both.

**A scan does not make you aware in Article 14's sense.** The duty is to notify
"any actively exploited vulnerability **contained in the product** with digital
elements that it becomes aware of". A feed match is not that: version ranges
over-match, vendored patches are invisible to them, and the affected code may
not be reachable in your build. It is a question about whether you are affected,
and the answer is a determination only a person can make. That is the whole
reason a scan writes candidates and stops — the design is not squeamishness
about clocks, it is that a match and an awareness are different things.

**And you will find out anyway, later and worse.** A researcher emails you, a
customer forwards a CISA bulletin, an upstream maintainer publishes. Awareness
arrives on somebody else's schedule, the 24-hour clock starts then regardless,
and you have no contemporaneous record of when you learned. The manufacturer who
scanned and ruled a candidate out with a VEX justification has evidence of
diligence dated before the incident; the one who never looked has no answer to
"when did you know?".

### EPSS scoring

EPSS scores how likely a CVE is to be exploited in the next 30 days — close
enough to Article 3(41)'s *potential to be effectively used* to be genuinely
useful, and close enough to look like an answer.

So: no threshold anywhere a user can see, because any cutoff is a compliance
policy rather than a fact. A missing score is *unscored*, never low. Both
probability and percentile are always shown, because 5% reads as negligible and
can be the 92nd percentile. And EPSS can never be a dismissal on its own — the
VEX justification is a statement about your product and stays required.

Both feeds are mirrored whole rather than queried per-CVE. Asking a scoring API
about a customer's CVEs would disclose exactly what the mirror exists to avoid.

### Derived state

Deadline status, risk-assessment staleness and evidence currency are all
computed on read. Persisting an `overdue` boolean flipped by a cron would let a
sweeper outage silently mark a user compliant.

Evidence currency is the subtlest: Annex I attaches to the product *as placed
on the market*, so evidence records which release it proves something about.
Three verdicts, and the distinction between the last two carries weight —
`current`, `stale` (covers only superseded releases; counts as a gap), and
`unversioned` (evidence predating the column; reported, *not* a gap). Calling
those stale would have turned every requirement in every account into a gap on
deploy, on the strength of something nobody had checked.

### Evidence storage

`attach_evidence` demands the artefact itself plus a `source_ref` — a git SHA,
a CI run URL, a tool and version — and stores it by value with a SHA-256. A
link evidences nothing in ten years, which is how long the file is retained.

### Audit trail

Under the CRA the technical file is retained ten years and the trail is what
evidences every change to it. So a failed audit write **fails the tool call**
(`errors.AuditWriteFailed`), and the state write and the audit insert commit in
one transaction. That is why the state blob lives in `products.state` JSONB
behind `SELECT … FOR UPDATE` rather than in a document store.

### Reporting unknown results

When deadlines cannot be read — no database configured — `get_compliance_status`
returns `open_obligations: null` with an explicit `unavailable` note, never an
empty list. An agent must not be able to say "nothing is due" on the strength
of a missing connection string.

The same rule governs the paywall. A refusal names what the tool would have
done and says the plan does not cover it; a free account that cannot reach the
reporting tools has *not* been told its product is fine.

## Regulation data and provenance

The catalogue was reconciled against the published text on **2026-08-06**
(CELEX 32024R2847, via the Publications Office).

It found the summaries faithful and every Annex I Part I *anchor wrong*. Annex
I Part I is (1), then (2)(a)-(m) under one chapeau; the catalogue had (1), (2),
then (3)(a)-(l) — a point that does not exist, and every letter shifted by one.

Nothing in the checklist was missing or invented, because each summary
described a real requirement. What was wrong was the citation attached to it —
the part an auditor reads, and the part that lands in Annex VII(3). A technical
file frozen before this cited provisions that are not in the regulation.

That the numbering survived that long is the argument for the discipline:
every tool had been returning `source_verified: false` to its caller the whole
time. `provenance()` reports the **oldest** verification date across the four
catalogue files, so a freshly transcribed annex cannot make an older one look
re-checked, and its caveat is never null in either state. Verification means
the anchors exist and the paraphrases are faithful. It does not make them the
text of the law, and Article 7(4) delegated acts can amend the annexes.

## Limitations

- **Without a database the file backend is used, and it is not transactional.**
  It cannot commit a state write and its audit row together, so a crash between
  them loses the record of who changed what. `CRA_STORE` follows `DATABASE_URL`
  unless set explicitly, and the fallback logs a warning saying so — but the
  backend still exists and is still selectable.
- **`mcp` is pinned `<2`.** 2.0.0 removed `FastMCP` for a restructured
  `mcpserver` module. Migrating is a scoped task nobody has done.
- **A suppressed alert is never retried.** Fixing a missing sender does not
  re-send what was suppressed while it was unset; the next escalation rung
  fires normally. Treat suppression rows as an incident, not a queue that
  drains itself.
- **There is no organisation object.** A product has members; nothing sits
  above them, and plans hang off individual users.
- **Severe incidents are not detectable** by any feed — no public source knows
  what is happening to your product in operation. The leverage there is
  `check_reporting_readiness` beforehand and fast capture during.


## Development

```bash
.venv/bin/python -m pytest -q                       # most pass; the DB-backed ones skip
DATABASE_URL=postgresql+psycopg://… \
  .venv/bin/python -m pytest -q                     # the skipped ones run too
```

`DATABASE_URL` alone is enough. It did not use to be: the dispatcher read
through `store_backend`, which defaulted to `file` regardless, so ~80 tests
failed on state the integration fixtures had seeded into Postgres — which read
as a broken suite rather than a missing second variable. The default now
follows `DATABASE_URL`, so the trap is gone rather than documented.
`./scripts/dev_up.sh` prints the URL to export.

The skips without a database are the `_NEEDS_DB` pattern, not a broken setup —
the count moves as tests are added, so it is not written down here.

The module docstrings carry the invariants above in more detail, the reasoning
behind them, and the things you can break silently. They are long on purpose:
`risk.py`, `annex.py`, `advisories.py`, `releases.py` and `conformity.py` each
open with why the domain works the way it does before any code runs.

## Contributing

Welcome, and not expected — this works whether or not anyone sends a patch.
[CONTRIBUTING.md](CONTRIBUTING.md) has the detail; two things specific to this
project are worth knowing before you start:

**A change to `src/cra/regulation/` is a claim about the law.** Cite the
provision, and do not set `source_verified` by inspection — fetch the text.
`eur-lex.europa.eu` sits behind a bot challenge that returns HTTP 202 with an
empty body, which reads as an empty document rather than a refusal; use
`https://publications.europa.eu/resource/celex/32024R2847` instead.

**New tools must be classified.** Every tool belongs to `_READ` or `_MUTATING`,
and to exactly one of `_REQUIRES` or `_FREE` in
[`src/cra/agents/dispatch.py`](src/cra/agents/dispatch.py). A test sweeps the
registration tables, so a new tool fails the suite until someone decides which
side it is on. That is the point, not an obstacle.

**Contributions are accepted under a permissive grant, not the AGPL.**
[CLA.md](CLA.md) is derived from the Apache ICLA and lets the project
sublicense your work — including under a paid commercial licence, which is how
this is funded. You keep copyright in what you write.

That asymmetry is deliberate and worth deciding about rather than clicking
through: [CONTRIBUTING.md](CONTRIBUTING.md) explains why it exists and what the
alternative would cost. If you would rather not, a bug report carries no
agreement and is usually worth more than a patch here.

## Security

See [SECURITY.md](SECURITY.md). Please report vulnerabilities to
**security@skarp.app** rather than opening a public issue.

Worth knowing before you test: accounts using the reporting tools store
unreported vulnerability records, including ones marked actively exploited,
before those are filed with a CSIRT. Anything crossing a product or account
boundary is treated as the most severe class.

## Licence

Copyright &copy; 2026 **Linclaw Consulting AB**, published under the Skarp name.

[GNU Affero General Public License v3.0 only](LICENSE). Version 3 only — there
is no "or any later version" option, and `pyproject.toml` says the same.

If you run a modified version of this as a network service, the AGPL requires
you to offer its source to your users. That is the intended effect: self-host
it, change it, and build on it freely — but a hosted fork stays open.

The regulation catalogue in `src/cra/regulation/` is data transcribed from
Regulation (EU) 2024/2847. EU legislation is not subject to copyright; the
paraphrases and the structure around it are covered by the licence above.
