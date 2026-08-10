#!/usr/bin/env bash
# Bring up everything needed to try the server locally.
#
#   ./scripts/dev_up.sh          # start Postgres, migrate, print the env
#   ./scripts/dev_up.sh --serve  # ...and run the MCP server in the foreground
#
# Uses Docker for Postgres if it is available, otherwise assumes a local
# `postgres` on 5432 and just creates the database. Nothing here touches
# anything outside the `cra_dev` database and one container named cra-pg.

set -euo pipefail
cd "$(dirname "$0")/.."

DB_NAME="${CRA_DEV_DB:-cra_dev}"
CONTAINER="cra-pg"
PORT="${CRA_DEV_PG_PORT:-55433}"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
dim() { printf '\033[2m%s\033[0m\n' "$*"; }

# ---- Python -----------------------------------------------------------------

if [ ! -x .venv/bin/python ]; then
  say "Creating .venv (project needs Python >= 3.12)"
  PY=$(command -v python3.12 || command -v python3 || true)
  [ -n "$PY" ] || { echo "No python3 found."; exit 1; }
  "$PY" -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -e ".[dev]"
fi

# ---- Postgres ---------------------------------------------------------------

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [ -z "$(docker ps -q -f name="^${CONTAINER}$")" ]; then
    if [ -n "$(docker ps -aq -f name="^${CONTAINER}$")" ]; then
      say "Starting existing ${CONTAINER}"
      docker start "$CONTAINER" >/dev/null
    else
      say "Starting Postgres 16 in Docker on :${PORT}"
      docker run -d --name "$CONTAINER" \
        -e POSTGRES_PASSWORD=cra -e POSTGRES_USER=cra -e POSTGRES_DB="$DB_NAME" \
        -p "${PORT}:5432" postgres:16 >/dev/null
    fi
    printf 'waiting for Postgres'
    for _ in $(seq 1 60); do
      if docker exec "$CONTAINER" pg_isready -U cra >/dev/null 2>&1; then break; fi
      printf '.'; sleep 1
    done
    echo
  fi
  export DATABASE_URL="postgresql+psycopg://cra:cra@localhost:${PORT}/${DB_NAME}"
else
  say "Docker not available — using a local Postgres on :5432"
  createdb "$DB_NAME" 2>/dev/null || true
  export DATABASE_URL="postgresql+psycopg://localhost/${DB_NAME}"
fi

export CRA_STORE=pg

say "Running migrations"
.venv/bin/alembic upgrade head >/dev/null
dim "schema is at head"

# A stable dev token. Not a secret — it only ever guards a local database.
export CRA_TOKEN_A="tok_a_dev_local"
export CRA_PARTIES=a
export CRA_STATE_DIR="./state"
# The sweeper would try to send real email; off unless you configure a sender.
export CRA_DEADLINE_ALERTS_ENABLED="${CRA_DEADLINE_ALERTS_ENABLED:-0}"

cat <<EOF

$(say "Ready.")
$(dim "Copy these into any shell that needs them:")

export DATABASE_URL="${DATABASE_URL}"
export CRA_STORE=pg
export CRA_TOKEN_A="${CRA_TOKEN_A}"
export CRA_PARTIES=a
export CRA_DEADLINE_ALERTS_ENABLED=0

$(dim "Then:")
  .venv/bin/python -m pytest -q          # the whole suite
  .venv/bin/python scripts/demo.py       # the whole product, narrated
  ./scripts/dev_up.sh --serve            # run the MCP server

$(dim "To attach Claude Code once the server is running:")
  claude mcp add --transport http cra http://127.0.0.1:8000/mcp/a/mcp \\
    --header "Authorization: Bearer ${CRA_TOKEN_A}"

EOF

if [ "${1:-}" = "--serve" ]; then
  say "Serving on http://127.0.0.1:8000 — MCP at /mcp/a/mcp"
  exec .venv/bin/python -m cra.server.http_app
fi
