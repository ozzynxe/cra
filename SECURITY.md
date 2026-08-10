# Security policy

## Reporting a vulnerability

Email **security@skarp.app**. Please do not open a public issue for a
vulnerability, and please do not disclose it publicly until a fix is available
or 90 days have passed, whichever comes first.

If you would like to encrypt the report, say so in a first message with no
detail in it and a key will be sent back.

Useful in a report, roughly in order of usefulness:

- what an attacker can do, stated as an outcome rather than a technique
- the steps to reproduce it, against your own account or a local instance
- the affected version — a commit SHA if you have one, or the date and endpoint
  if you were testing the hosted service at `cra.skarp.app`
- whether you believe it is being exploited

You will get an acknowledgement within **3 working days** and an assessment
within **10**. If a report is valid you will be told when a fix ships and
credited in the release notes unless you would rather not be.

This is a small project without a bug bounty. There is no payment, and saying  <!-- screen: allow: scope of the security programme, which a reporter needs to know -->
so plainly seems better than leaving it to be discovered after the work.

## What is in scope

The code in this repository, and the hosted service at `cra.skarp.app`.

Testing the hosted service is welcome **against data you own**. Create an
account, create a product, and attack that. Two limits, and both are about
other people rather than about protecting the service from scrutiny:

- **Do not access another account's data.** If a bug lets you, that is exactly
  the report worth sending — establish it, stop, and describe it. Do not
  enumerate what else it reaches.
- **No denial of service, no load testing, no automated scanning at volume.**
  This service holds statutory reporting deadlines. Taking it down can cause a
  user to miss one.

Do not test the payment flow with real card details. Stripe test mode is not
enabled on production; stop at the checkout page.

## What is out of scope

Reports that will be closed without much discussion:

- output of an automated scanner with no demonstrated impact
- missing headers or cookie flags on endpoints that serve no content and set
  no cookies
- weaknesses in the deliberately public surface: `/pricing`, `/coverage`, the
  marketing pages
- social engineering of the maintainer, physical attacks, or anything
  requiring a compromised user device
- "no rate limit" on an endpoint where the limit is deliberately absent
  because the operation is idempotent and unauthenticated by design
- the absence of a feature you would prefer existed

## Things worth knowing before you test

Three deliberate design choices that look like bugs and are not, so you can
skip them or — better — tell us why the reasoning is wrong:

**Entitlement checks fail open.** If the plan tier cannot be read, `plan_for`
returns the unlimited plan and logs it. "We could not check" resolving to
"free" would lock someone out of compliance work over a billing lookup. This
is a deliberate availability-over-enforcement trade in one direction only; a
way to *force* that failure to obtain paid features is a valid report.

**The file store backend is not transactional.** `CRA_STORE=file` cannot commit
a state write and its audit row together. It is dev-only: the default follows
`DATABASE_URL`, so anywhere a database is configured resolves to `pg`, and the
fallback logs a warning naming what it costs. A finding that the file backend
loses audit rows is known and documented rather than new.

**User-supplied URLs are recorded and never fetched.** `disclosure_policy_url`
and the simplified declaration's address are stored verbatim and never
requested server-side — fetching them would be an SSRF surface, and a 200 would
prove only that something is served there. If you find a path that *does* fetch
one, that is a report.

## Data this service holds

Worth stating because it should raise your estimate of impact for anything
touching authorisation.

Accounts using the reporting tools store **unreported vulnerability records,
including ones marked actively exploited**, before those are filed with a
CSIRT. A cross-account read here is not a privacy incident in the ordinary
sense — it is a disclosure of live, unpatched exploitation against a third
party's product. Findings that cross a product or account boundary are treated
as the most severe class regardless of how awkward the path to them is.

## This is not a report channel for the CRA itself

If you have found a vulnerability in **your own** product and are trying to
work out what the Cyber Resilience Act requires you to file, that is what the
tool is for and not a matter for this address. Article 14 reports go to your
CSIRT or ENISA, never to us — `get_applicable_csirt` will tell you which, and
we have no standing to receive them.
