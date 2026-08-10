# The SRP reporting template

Source: ENISA's Single Reporting Platform FAQ, **Q16 — "What are the data
fields to be filled in the reporting template?"**

## What Q16 actually is

Not a document template. A **table of data fields**, with a marker per field
per reporting stage. That distinction matters: it means `draft_report` is not
rendering prose into a form, it is resolving a field catalogue against a stage
and the facts already recorded.

ENISA's markers:

| Code | Meaning |
|---|---|
| `X` | Obligatory |
| `O` | Optional |
| `C` | Copied from the previous step by default, or updated |
| `A` | Automated — computed by the platform, **not shown to the submitter** |
| `I` | Obligatory *if the information is available* |

ENISA frames the fields as either flowing directly from the CRA or identified
by logical consequence, and explicitly as **provisional until the platform is
final**.

## What each marker demands of us

Three of the five are behavioural requirements, not annotations:

**`C` — copy-forward.** A stage's draft must be pre-populated from the previous
submission for that incident, with the user editing deltas rather than
retyping. This is the single most consequential item on the list: at hour 70 of
a 72-hour clock, retyping the early warning is how a notification gets filed
late. Our schema already supports it — obligations chain off one `incidents`
row, so the prior stage's payload is reachable.

**`A` — automated.** Platform-computed fields must **not** be collected or
guessed. Rendering a value for one is worse than leaving it blank: it invites
the user to reconcile our number against ENISA's.

**`I` — obligatory if available.** Exactly the regulator's own "send what you
know, then follow up" posture, in the field schema. `draft_report` must never
block on an `I` field; it emits what exists and marks the rest as to-follow.
An `X` gap is a blocker worth naming loudly; an `I` gap is not.

`X` and `O` drive the readiness/gap report.

## Consequences for the implementation

- The catalogue is **data, not code** — `report_templates/v1.yaml`, resolved at
  runtime. ENISA calls the fields provisional and the platform is not live, so
  a field change must be a data edit, not a migration.
- Version the catalogue and record which version a draft was produced under.
  A report filed in September 2026 against v1 must still be reproducible in
  2036, when the technical file is still being retained.
- Two streams (actively exploited vulnerability, severe incident) share stages
  but not necessarily fields; the catalogue is keyed on `(stream, stage,
  field)`.
- Structured payload first, rendered markdown second. When the submission API
  ENISA has signalled arrives, it should be a transport swap, not a rewrite.

## Precedence, and the bug it exists to prevent

`resolve()` has three tiers, not two, and the middle one is why it isn't a
dict merge:

1. **known** — what the caller supplied this call, plus *structured* facts off
   the record: product name, CVE id, the date a fix shipped. Correcting the
   record is how you correct these, so a fresh read beats an earlier draft.
2. **previous** — the last drafted stage's payload. Prose lives here.
3. **fallback** — a seed the record can approximate before anyone has written
   the field properly, typically the one-line description typed while the
   incident was still unfolding.

The first implementation had two tiers and treated the incident description as
authoritative for the narrative fields. Consequence: a user who wrote a careful
account at the 72-hour stage would find it silently replaced by their own terse
first sentence when they drafted the final report. Seeds must lose to carried
values.

## Status

Transcribed in full into `src/cra/report_templates/v1.yaml` from the FAQ as
published 31 July 2026 — 12 common fields, 14 vulnerability, 14 incident,
with ENISA's own row ids and wording. `draft_report`, `check_reporting_readiness`
and `set_submitter_profile` are built on it.

Two transcription notes:

- ENISA's incident "Detailed description" parent row carries no id, unlike its
  vulnerability counterpart `v22`. Ours is `i20a` and is flagged in the YAML as
  ours, not theirs.
- `i22` — the two limbs of the CRA's severe-incident definition — has all three
  cells blank in the published table. It is guidance printed under "Severity",
  not a field, and is rendered as a blockquote rather than collected.
