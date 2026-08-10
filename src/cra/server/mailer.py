"""The one place this service sends email.

Extracted when signup became the third consumer — the deadline sweeper, the
advisory sweeper and now access requests. Before that the advisory sweeper was
importing a private `_send` out of the deadline sweeper, which is the point at
which a shared thing should stop pretending to belong to one of its callers.

`NotConfigured` is deliberately a distinct exception rather than a bool. A
deployment with no sender configured is not the same as a delivery failure: the
first needs an operator and must never be retried into a loop, the second is
transient. The deadline sweeper depends on that distinction to decide between
writing a `suppressed` row and leaving a rung eligible for the next pass.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)


class NotConfigured(RuntimeError):
    """There is no way to deliver mail from this deployment."""


def sender() -> str:
    return os.environ.get("CRA_ALERTS_FROM", "").strip()


def region() -> str:
    return os.environ.get("CRA_ALERTS_SES_REGION", "eu-north-1")


def app_origin() -> str:
    """Public origin, for links in emails.

    Without it a verification link cannot be built at all, so callers that need
    one should check rather than emit a mail containing a relative URL.
    """
    return (os.environ.get("CRA_APP_ORIGIN") or "").rstrip("/")


def send(
    *,
    to_email: str,
    subject: str,
    plain: str,
    html: str,
    from_addr: Optional[str] = None,
    hint: str = "",
) -> str:
    """Send one email, returning the provider message id.

    Raises `NotConfigured` when no sender is set — never swallows it, because a
    deployment that silently stops emailing about statutory deadlines is the
    failure the alerting half exists to prevent.

    `hint` is appended to that error and is not decoration. The message ends up
    in a `notification_log` suppression row, which is the thing an operator
    reads to answer "why did nobody get told" — so it should name the switch
    that turns *this* caller off, not offer generic advice.
    """
    src = (from_addr or sender()).strip()
    if not src:
        raise NotConfigured(
            "CRA_ALERTS_FROM is not set, so this deployment cannot send email. "
            + (hint or "Set it, or disable the feature that needs it deliberately.")
        )
    import boto3  # noqa: WPS433 — local so the module imports without boto3

    client = boto3.client("ses", region_name=region())
    resp = client.send_email(
        Source=src,
        Destination={"ToAddresses": [to_email]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Html": {"Data": html, "Charset": "UTF-8"},
                "Text": {"Data": plain, "Charset": "UTF-8"},
            },
        },
    )
    return resp.get("MessageId", "")
