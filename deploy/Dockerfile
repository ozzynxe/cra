# Production image for cra-assistant.
#
# Slim on purpose: no WeasyPrint, no native PDF stack. This server's outputs are
# structured payloads and markdown, not typeset documents, so the 200MB+
# rendering runtime buys nothing and costs real memory.
#
# Built on the host via `docker compose build`. There is no
# registry push in the flow: the source is rsynced and built in place.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CRA_HOST=0.0.0.0 \
    CRA_PORT=8000 \
    # Postgres, not the file backend. `store_pg` is the only backend that can
    # commit a state write and its audit row in one transaction, and under the
    # CRA the audit trail is the deliverable.
    CRA_STORE=pg

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

# Alembic config and scripts, so `docker exec cra alembic upgrade head` works on
# the host without building a second image.
COPY alembic.ini ./
COPY db_migrations ./db_migrations

# Operational scripts that get exec'd on the host — dev_token.py in particular,
# so a credential can be issued on the box without waiting on mail — it is a
# credential.
COPY scripts ./scripts

EXPOSE 8000

# Liveness only. /health deliberately does not touch the database: a Postgres
# blip should surface as failing tool calls and Sentry events, not as Docker
# restarting a process that is perfectly healthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import httpx,os; httpx.get(f'http://127.0.0.1:{os.environ.get(\"CRA_PORT\",\"8000\")}/health', timeout=3.0).raise_for_status()" || exit 1

CMD ["python", "-m", "cra.server.http_app"]
