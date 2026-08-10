# Contributing

Contributions are welcome and none are expected. This is a small commercial
project that happens to be open source, and it will keep working whether or not
anyone sends a patch — so treat everything here as an invitation rather than a
backlog you are being recruited onto.

The most useful thing you can send is not usually code. In rough order:

1. **A case where the tool is wrong about the regulation.** Cite the provision.
   This is the failure that matters most and the one hardest to catch from
   inside.
2. **A case where a refusal was unhelpful** — you hit a wall and could not tell
   what to do next. The wording of a refusal is a feature here, not a message.
3. **A bug**, with what you did and what happened.
4. **A patch.**

Security issues go to **security@skarp.app**, not to the issue tracker. See
[SECURITY.md](SECURITY.md).

## The licence asymmetry, stated plainly

The project is **AGPL-3.0**. Contributions are accepted under a **permissive
grant** — [CLA.md](CLA.md), derived from the Apache ICLA — which lets the
project sublicense your work, including under a paid commercial licence.

That is asymmetric and you should decide about it with your eyes open: the
project's code is copyleft-protected from you, and your contribution is not
copyleft-protected from the project.

**Why it is set up that way.** A meaningful share of buyers in this market
cannot accept AGPL — enterprise legal departments refuse it as a matter of
policy. Selling those buyers a commercial licence is how the work is funded,
and that option closes permanently the moment a contribution lands without a
sublicensable grant, because it would require tracking down every contributor
for permission. Linux is the standard illustration: it can never be relicensed,
by anyone, for any reason.

So the choice is between asking for this and not accepting patches at all. I
would rather ask, explain why, and let you decline.

**What you keep.** Copyright in your contribution stays yours. You can use your
own code anywhere else, under any terms, forever. Your name stays in the Git
history and in `AUTHORS`.

**What you should not do** is contribute if this trade bothers you. It is a
reasonable thing to object to. Open an issue and say so, or send a bug report
instead — bug reports carry no agreement and are worth more than most patches.

## Two rules specific to this project

### A change to `src/cra/regulation/` is a claim about the law

Those YAML files are what the tool cites in a technical file that a market
surveillance authority may read. Every anchor there was once wrong by one
letter, so files were assembled citing provisions that do not exist in the
regulation.

If you change a catalogue entry: cite the provision, and **do not set
`source_verified` by inspection** — fetch the text. `eur-lex.europa.eu` sits
behind a bot challenge that returns HTTP 202 with an empty body, which reads as
an empty document rather than as a refusal. Use the Publications Office
instead:

```bash
curl -H 'Accept: application/xhtml+xml' \
  https://publications.europa.eu/resource/celex/32024R2847
```

### A new tool must be classified before the suite will pass

Every tool belongs to `_READ` or `_MUTATING`, **and** to exactly one of
`_REQUIRES` or `_FREE`, in
[`src/cra/agents/dispatch.py`](src/cra/agents/dispatch.py). A test sweeps the
registration tables, so a new tool fails the suite until someone decides which
side of the paywall it is on. That is the design, not an obstacle — the one
membership gap that ever existed got in through a handler written without the
check its neighbours had.

The dispatcher module docstring has the full checklist for adding a tool, and the
invariants you can break silently. Read it before changing anything in
`src/cra/server/`.

## Getting set up

```bash
./scripts/dev_up.sh                          # venv, Postgres, migrations
.venv/bin/python -m pytest -q                # most pass; the DB-backed ones skip
.venv/bin/python scripts/demo.py             # the whole product, narrated
```

## Before you push

This repository is public, and so are its commit messages. Enable the screen
once per clone:

```bash
git config core.hooksPath .githooks
```

Run the database suite before sending anything that touches state:

```bash
DATABASE_URL=postgresql+psycopg://… .venv/bin/python -m pytest -q
```

`DATABASE_URL` alone is enough — `CRA_STORE` follows it. If you find a runbook
anywhere insisting you also set `CRA_STORE=pg`, it predates that and can be
fixed. `dev_up.sh` prints the URL to export.

## What a good pull request looks like

- **One thing.** A PR that fixes a bug and tidies formatting is two PRs.
- **A test that fails without the change.** Prove it: stash the fix, watch the
  test fail, restore it. Several tests in this repo exist because that step
  caught a test asserting the wrong property and passing by luck.
- **A commit message that says why.** This repository's history explains
  reasoning rather than restating the diff, and that is deliberate — the
  reasoning is the part that is expensive to reconstruct later. Match it
  roughly; nobody will reject a patch over prose.
- **Confirm the CLA statement** in the pull request template.

Anything that changes a refusal's wording, a statutory deadline calculation, or
what the tool asserts about the regulation will get read closely and may take a
while. That is not distrust — those are the parts where being wrong is
expensive and invisible.

## What will not be merged

- Anything that makes the tool assert compliance it cannot evidence.
- Anything that auto-rules-out a requirement, however convenient. See the
  invariants the module docstrings set out.
- Anything that anchors a statutory clock on "now" without saying so.
- A new path that accepts a drafted risk and applies it in one call.

These are not style preferences. Each one exists because the failure it
prevents produces a compliance record that looks considered and is not, which
is the specific harm this project is built against.


`scripts/screen.py` then runs on every push, over the tree and over the commit
messages going out with it. It looks for amounts, the identifying values from
`deploy/deploy.env`, commercial and estate-sizing phrases, and text that
announces its own redaction. If something it flags is fine, say why in the file
— `screen: allow: <reason>` on the line, or
`screen: allow-file <rule>: <reason>` for one rule in one file. The reason is
the point; it is what a reviewer reads later.

**A green run is not a clearance.** It means nothing on the list was found.
Commercial reasoning trips no pattern, and that is the thing most worth keeping
out — read your own diff, including the message.
