"""Server-level MCP `instructions` returned in the `initialize` response.

Tool Search (default on recent MCP clients) defers tool descriptions and
discovers them on demand, so the model decides whether to look at this server
based on this text alone. Without it the connector is invisible until the user
names it explicitly.

Written around the phrases a developer actually says in the moment — "we're
being exploited", "do we need CE marking", "what's the 24 hour thing" — rather
than around the regulation's own vocabulary, which is not what anyone types.
"""

from __future__ import annotations


_INSTRUCTIONS = """\
This connector helps software makers meet EU Cyber Resilience Act (CRA)
obligations: scope classification, Annex I requirements with evidence,
vulnerability and incident records with their statutory reporting clocks,
and the Annex VII technical file.

Search for and use these tools when the user mentions: the Cyber
Resilience Act or CRA, CE marking for software, an EU declaration of
conformity, a technical file, an SBOM for EU compliance, a product
"support period", or reporting a vulnerability to ENISA or a CSIRT.

Reach for them URGENTLY — before answering anything else — if the user
says a vulnerability in their product is being actively exploited, that
they've had a security incident, or asks about the "24 hour" / "72 hour"
deadline. Under Article 14 those clocks start when the manufacturer
becomes AWARE, not when they get round to it: 24h early warning, 72h
full notification, 14 days final report (1 month for severe incidents).
Reporting obligations begin 11 September 2026; full application follows
11 December 2027. Call `get_compliance_status` immediately in that
situation — it leads with open deadlines and time remaining.

Start with `cra_overview()` for orientation, `list_products()` to find a
product id, then `get_compliance_status(product_id)`.

For requirement work the order is `classify_product` →
`start_risk_assessment` → the Annex I checklist, and it is not
interchangeable: Annex I Part I applies on the basis of the Article 13(2)
risk assessment, and Annex VII(3) requires that assessment in the
technical file. You draft the risks — you can see the code, the
dependencies and the deployment; the server cannot. But a risk you draft
determines nothing until the user decides on it.

This connector does NOT return the text of the regulation — use a
regulation-lookup server for that. And it never determines that a product
IS compliant: it tracks evidence and tells the user what is missing.
Do not represent its output as a compliance determination, and do not
substitute it for legal review or a notified body.
"""


def instructions_for(party_id: str) -> str:
    """Return the `instructions` string for a mount.

    Single text for now — per-mount variants (per-product vs user-wide) arrive
    with the product-scoped token flow.
    """
    return _INSTRUCTIONS
