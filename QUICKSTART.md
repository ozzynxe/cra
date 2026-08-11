# Trying it

Three ways in, cheapest first. All of them need Postgres — the deadline
tracking is the product, and it lives in rows.

## 0. Set up

```bash
git clone https://github.com/ozzynxe/cra && cd cra
./scripts/dev_up.sh
```

That creates `.venv`, starts Postgres 16 (in Docker if you have it, otherwise
it uses a local one on :5432), runs the migration, and prints the environment
to export. Everything below assumes you have exported it.

## 1. Run the tests — 30 seconds

```bash
.venv/bin/python -m pytest -q                # the whole suite
```

Without `DATABASE_URL` the suite still runs; the DB-backed tests skip. That is the `_NEEDS_DB` pattern rather than a broken setup — `dev_up.sh` prints the `DATABASE_URL` to export if you want them.
That is the `_NEEDS_DB` pattern, not a broken setup.

Worth reading rather than just running — the test names carry the reasoning,
and a few of them document real bugs found on the way:

```bash
.venv/bin/python -m pytest tests/unit/test_deadlines.py -v      # the statutory clocks
.venv/bin/python -m pytest tests/integration/test_annex.py -v   # the conformity chain
```

## 2. Watch the whole product run — 10 seconds

```bash
.venv/bin/python scripts/demo.py
```

Two acts, narrated:

- **Act 1** — a CVE turns out to be exploited on a Monday morning. The
  readiness check fails on five things you cannot arrange inside 24 hours. One
  flag flips and two clocks start on their own — then the logs show they knew
  30 hours ago, the anchor moves, and the early warning is retroactively late.
  It drafts in ENISA's field layout and is filed anyway.
- **Act 2** — classification (refused without reasoning), the Article 13(2)
  risk assessment the agent drafts and the human decides, the 22-requirement
  Annex I checklist it makes applicable, the technical file as a gap report,
  freeze → declare → re-freeze → sign, and an edit that visibly invalidates
  the signature.

It ends by printing the audit trail an auditor would read.

Writes real rows. Point `DATABASE_URL` at a scratch database.

## 3. Connect your own agent — 2 minutes

Mint a credential. In a local checkout there is no mail to receive a code from, so this script is the
supported way:

```bash
.venv/bin/python scripts/dev_token.py you@example.com
```

It prints a `cra_…` token **once** — only the bcrypt hash is stored. Then, in
another shell:

```bash
./scripts/dev_up.sh --serve
```

and attach Claude Code:

```bash
claude mcp add --transport http cra http://127.0.0.1:8000/mcp/me/mcp \
  --header "Authorization: Bearer cra_…"
```

Then talk to it. Things worth trying, roughly in the order a real user would
hit them:

| Say this | What should happen |
|---|---|
| "What is the Cyber Resilience Act going to require of me?" | `cra_overview` — the two dates and the three clocks |
| "I ship an API gateway to EU customers, track it" | `create_product`, then it should push you toward classification |
| "Which CRA class is it?" | `classify_product` bare first — it must **not** guess from the name |
| "What do we need to do next?" | `start_risk_assessment` — not the checklist. Part I applies on the basis of the assessment |
| "Work out the risks for me" | it drafts from your actual code via `propose_risks`, then makes you decide each one |
| "Just accept them all, they look right" | each needs `decide_risk` with a rationale, and accepting needs a treatment |
| "We found a critical RCE, CVE-2026-1234" | `record_vulnerability` — and it should ask whether it is being exploited |
| "Yeah, a customer sent us exploit logs" | the cascade: an incident opens and 24h/72h clocks start |
| "We actually saw this on Friday" | `became_aware_at` re-anchors the clocks — and tells you what is now already overdue |
| "Draft the early warning" | an SRP-shaped draft with gaps marked, not a refusal |
| "Are we ready to actually file?" | `check_reporting_readiness` — EU Login, SRP registration, security contact |
| "What's left on Annex I?" | `list_requirements(filter='gaps')` |
| "Mark data minimisation as not applicable" | **refused** without a justification |

The last one is the most interesting: the tool is designed to push back, and
watching where it does is the fastest way to judge whether the design is right.

## Poking at it directly

Every tool is reachable without an agent, through the same dispatcher the MCP
layer uses:

```bash
.venv/bin/python -c "
from cra.agents import dispatch as d
import json
print(json.dumps(d.dispatch('cra_overview', '', 'me', {}), indent=2))
"
```

## What is not wired up

- **No mail locally.** `/access` and the OAuth code flow both send email, so
  `scripts/dev_token.py` is how you get a credential in a dev checkout.
- **Deadline alerts are off** in dev (`CRA_DEADLINE_ALERTS_ENABLED=0`); turning
  them on needs `CRA_ALERTS_FROM` and AWS SES credentials. `sweep_once(dry_run=True)`
  shows what would go out without sending:
  ```bash
  .venv/bin/python -c "
  from cra.server.deadline_sweeper import sweep_once
  import json; print(json.dumps(sweep_once(dry_run=True), indent=2, default=str))"
  ```
- **The catalogue is reconciled as of 2026-08-06**, against CELEX 32024R2847.
  Every tool still passes a `provenance` block through: the summaries are
  paraphrases, not quotations, and delegated acts can amend the annexes.
- **`mcp` is pinned `<2`.** A fresh install resolves 2.0.0, which removed
  `FastMCP`.

## Tearing down

```bash
docker rm -f cra-pg     # if Docker was used
rm -rf .venv state
```
