<!--
Thanks for this. Keep it to one thing, and say why rather than what — the diff
already says what.

If this is a security issue, please close this and email security@skarp.app
instead. See SECURITY.md.
-->

## What this changes, and why

<!-- The reasoning, not the diff. What was wrong, or what became possible. -->

## How it was checked

<!--
A test that fails without the change is the strongest answer. Prove it rather
than assuming: stash the fix, watch the test fail, restore it. Tests in this
repo have asserted the wrong property and passed by luck.

If it touches state, say whether the database suite ran:
  DATABASE_URL=… CRA_STORE=pg .venv/bin/python -m pytest -q
-->

- [ ] `.venv/bin/python -m pytest -q` passes
- [ ] There is a test that fails without this change, or it needs no test and I have said why below

## If this touches the regulation catalogue

<!-- Delete this section if it does not. -->

- [ ] I cited the provision
- [ ] I fetched the text rather than setting `source_verified` by inspection
      (see CONTRIBUTING.md — eur-lex returns an empty 202 that reads as an
      empty document)

## Contributor Licence Agreement

This project is AGPL-3.0, and contributions are accepted under a permissive
grant so the project can also be sold under a commercial licence. The reasoning
is in [CONTRIBUTING.md](../CONTRIBUTING.md); the agreement is
[CLA.md](../CLA.md). You keep copyright in your work.

If that trade is not one you want to make, please close this and open an issue
describing the problem instead — a good bug report is worth more here than most
patches, and it carries no agreement at all.

- [ ] I have read [CLA.md](../CLA.md) and I license this contribution under its terms
- [ ] I wrote this, or I have the right to submit it — including my employer's
      permission if my contract gives them rights to what I create
