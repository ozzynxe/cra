"""Single dispatch chokepoint for every MCP tool call.

Structure carried over from Coauthor's `agents/tools.py::dispatch` — identity
resolution from contextvars, table-based routing, and uniform error enveloping.
The Coauthor version also recorded a best-effort activity row; here the audit
write is transactional and a failure fails the call (see
`errors.AuditWriteFailed`).

Tools are registered in two tables so the routing stays declarative:

  _READ      — no state change, no audit row
  _MUTATING  — state change, audit row required

`_SESSION_AGNOSTIC` names the tools that work without a product id, so an agent
holding a user-wide token can ask "what's due across everything I own" without
resolving a product first.

`_REQUIRES` names the tools a plan has to cover, and `_FREE` names the rest.
Every registered tool must appear in exactly one of them — a test sweeps the
tables rather than spot-checking, so adding a tool without deciding which side
it falls on fails the suite instead of silently shipping it free. Gates that
depend on more than the tool's name (a second risk-assessment version, a frozen
technical file, the product and member caps) live in the handlers; see
`server/entitlements.py`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from cra.server import entitlements, request_context
from cra.server.errors import TransitionError

log = logging.getLogger(__name__)

# Tool name -> handler. Populated by cra.server.handlers at import time.
_READ: dict[str, Callable[..., dict]] = {}
_MUTATING: dict[str, Callable[..., dict]] = {}

# Tools callable with no product_id.
_SESSION_AGNOSTIC: set[str] = {
    "cra_overview",
    "list_products",
    "create_product",          # creates the product; can't require one
    "get_reporting_deadlines",  # "what's due across everything I own"
    # Billing is an account-level concern, not a product one.
    "get_upgrade_link",
    "manage_subscription",
}


# Tool -> the feature a plan must cover to call it at all.
_REQUIRES: dict[str, str] = {
    # Recording answers against Annex I. The free tier shows you the 22
    # requirements and which apply; putting evidence against them is the record.
    "update_requirement": entitlements.EVIDENCE,
    # Annex II is the same shape of work as the Annex I checklist:
    # reading what you owe is the diagnosis, recording answers is the
    # record.
    "update_user_information": entitlements.EVIDENCE,
    "attach_evidence": entitlements.EVIDENCE,
    # Closing a legal statement.
    # Placing on the market is a legal act and freezes a determination,
    # so it sits with the other things that close a statement. Recording
    # that a build exists is not, and is in `_FREE` — the split is what
    # lets "free until you place it on the market" be said in the domain
    # model rather than only in the price list.
    "place_on_market": entitlements.CONFORMITY,
    # The Article 13(8) determination fills an Annex VII slot and starts
    # the end-of-support alerts, so it is the record rather than the
    # diagnosis. A free account still *sees* that it owes one — that is
    # what the gap report is for.
    "set_support_period": entitlements.CONFORMITY,
    "generate_declaration_of_conformity": entitlements.CONFORMITY,
    "generate_simplified_declaration": entitlements.CONFORMITY,
    "sign_off": entitlements.CONFORMITY,
    # Article 14. `get_reporting_deadlines` is a read, but it is the clock
    # itself, so it is gated with the rest of its module rather than split off.
    "record_vulnerability": entitlements.REPORTING,
    "update_vulnerability": entitlements.REPORTING,
    "report_incident": entitlements.REPORTING,
    "record_report_submission": entitlements.REPORTING,
    "get_reporting_deadlines": entitlements.REPORTING,
    "draft_report": entitlements.REPORTING,
    "check_reporting_readiness": entitlements.REPORTING,
    "set_submitter_profile": entitlements.REPORTING,
    # SBOM → OSV → KEV. `record_sbom` is deliberately not here: recording what
    # you ship is the input to the scan rather than part of it, and a product
    # with no bill of materials on file cannot be scanned at all.
    "scan_advisories": entitlements.ADVISORIES,
    "list_advisory_candidates": entitlements.ADVISORIES,
    "confirm_advisory": entitlements.ADVISORIES,
    "dismiss_advisory": entitlements.ADVISORIES,
}

# The first pass, free: work out what the CRA asks of this product, and where it
# stands. `assemble_technical_file` is here because it is a gap report; the
# `freeze` argument is what costs, and that gate is in the handler.
_FREE: set[str] = {
    "cra_overview",
    "list_products",
    "create_product",
    "get_compliance_status",
    "get_recent_activity",
    "get_applicable_csirt",
    "classify_product",
    # Which CRA role this party plays decides which obligations apply at
    # all, so it belongs with classification on the free side: finding
    # out that Annex I is not yours must not be behind a paywall.
    "set_economic_operator_role",
    # Deleting a product that was never placed on the market is how a free
    # account stops being stuck with its first one, so it cannot sit behind
    # the paywall the trap would otherwise push people through.
    "delete_product",
    # Getting your own data out is never gated. A paywall here would make
    # every other promise in this product conditional on a subscription.
    "export_product",
    "record_sbom",
    "add_member",
    "remove_member",
    "start_risk_assessment",
    "propose_risks",
    "decide_risk",
    "confirm_risk_assessment",
    "get_risk_assessment",
    "list_requirements",
    "list_user_information",
    "list_evidence",
    "list_releases",
    "record_build",
    "assemble_technical_file",
    "get_conformity_status",
    # Necessarily free: a paywall you cannot reach from behind the paywall is
    # a dead end.
    "get_upgrade_link",
    "manage_subscription",
}


def register_read(name: str, fn: Callable[..., dict]) -> None:
    _READ[name] = fn


def register_mutating(name: str, fn: Callable[..., dict]) -> None:
    _MUTATING[name] = fn


_handlers_loaded = False


def _ensure_handlers_loaded() -> None:
    """Import the handler module on first dispatch if nothing has yet.

    Registration is an import side-effect, which makes it order-dependent: a
    caller that reaches `dispatch` without going through `server.tools` would
    otherwise see every tool as unknown. Importing here rather than at module
    scope avoids the circular import (handlers imports this module).

    The guard is an explicit flag, not `if _READ or _MUTATING`. That earlier
    test asked "has anything registered?" when the question is "has the handler
    module been imported?", and the two differ the moment any single domain
    module is imported first — `cra.server.advisories` registers four tools, the
    tables stop being empty, and this function then declines to import the other
    thirty-one. Every other tool becomes `unknown_tool`, with no error anywhere
    to explain it. That is reachable from ordinary code: the advisory sweeper
    imports the advisory module, and a test that imports one domain module hits
    it immediately.
    """
    global _handlers_loaded
    if _handlers_loaded:
        return
    _handlers_loaded = True
    from cra.server import handlers  # noqa: F401,WPS433 — registers on import


def _resolve_identity(product_id: str, actor_id: str) -> tuple[str, str]:
    """Auth middleware wins over closure-bound values.

    A `coauth_*` connector token resolves to a specific (user, product) pair at
    the middleware; those contextvars override whatever the tool closure was
    built with. This is what makes attribution trustworthy — the caller cannot
    assert an identity the token doesn't carry.
    """
    ctx_user = request_context.current_user_id.get()
    ctx_product = request_context.current_product_id.get()
    return (ctx_product or product_id), (ctx_user or actor_id)


def dispatch(
    name: str,
    product_id: str,
    actor_id: str,
    args: Optional[dict[str, Any]] = None,
) -> dict:
    """Route one tool call and return a JSON-serialisable envelope.

    Always returns a dict — never raises — so a tool failure reaches the agent
    as data it can reason about rather than an MCP transport error.
    """
    args = args or {}
    _ensure_handlers_loaded()
    product_id, actor_id = _resolve_identity(product_id, actor_id)

    handler = _READ.get(name) or _MUTATING.get(name)
    if handler is None:
        return {
            "ok": False,
            "code": "unknown_tool",
            "error": f"unknown tool: {name}",
        }

    if name not in _SESSION_AGNOSTIC and not product_id:
        return {
            "ok": False,
            "code": "product_required",
            "error": (
                f"{name} needs a product_id. Call list_products() to find one, "
                "or create_product() if this product isn't tracked yet."
            ),
        }

    feature = _REQUIRES.get(name)
    if feature is not None:
        try:
            # On a product, the governing plan is its owner's — a team plan has
            # to cover the team, or "unlimited members" means only that you may
            # add people who then cannot work.
            #
            # Without a product this is "what is due across everything I am
            # on", and the answer spans products with different owners. Let it
            # through if any of them is covered; the handler then scopes to
            # those and names the ones it could not cover, because a shorter
            # list that does not say what it omitted reads as "nothing due".
            if not product_id and actor_id:
                covered, _ = entitlements.covered_product_ids(actor_id, feature)
                if not covered:
                    entitlements.require(
                        actor_id, feature, what=f"{name} would have run."
                    )
            else:
                entitlements.require(
                    actor_id, feature, what=f"{name} would have run.",
                    product_id=product_id or None,
                )
        except entitlements.UpgradeRequired as e:
            governing = (
                entitlements.plan_for_product(product_id, fallback_user_id=actor_id)
                if product_id
                else entitlements.plan_for(actor_id)
            )
            return {
                "ok": False,
                "code": e.code,
                "feature": feature,
                "plan": governing.name,
                "error": str(e),
            }

    try:
        return handler(product_id=product_id, actor_id=actor_id, **args)
    except TransitionError as e:
        return {"ok": False, "code": e.code, "error": str(e)}
    except TypeError as e:
        # Bad tool arguments from the model — surface as data, not a crash.
        log.warning("bad args for %s: %s", name, e)
        return {"ok": False, "code": "invalid_args", "error": str(e)}
    except Exception as e:  # noqa: BLE001 — the envelope is the contract
        log.exception("tool %s failed", name)
        return {"ok": False, "code": "internal_error", "error": str(e)}
