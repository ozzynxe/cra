#!/usr/bin/env bash
# One-time host setup. Run ON THE HOST, once, before the first deploy.
#
#   ssh ubuntu@<ip>
#   bash bootstrap.sh
#
# Creates the database and role, the S3 backup bucket with object lock, and the
# directory layout deploy.sh expects. Idempotent — safe to re-run.

set -euo pipefail

REMOTE="${CRA_REMOTE_DIR:-/home/ubuntu/cra}"
PG_CONTAINER="${CRA_PG_CONTAINER:-deploy-postgres-1}"
# The bootstrap superuser. Not always `postgres`: an image started with
# POSTGRES_USER set has that role as superuser and no `postgres` role at all,
# which fails here as `role "postgres" does not exist`. Check with:
#   docker exec <container> printenv POSTGRES_USER
PG_SUPER="${CRA_PG_SUPERUSER:-postgres}"
DB="${CRA_DB_NAME:-cra}"
DB_USER="${CRA_DB_USER:-cra_app}"
BUCKET="${CRA_BACKUP_BUCKET:-}"
REGION="${CRA_BACKUP_REGION:-eu-north-1}"
RETAIN_DAYS="${CRA_BACKUP_RETAIN_DAYS:-3660}"   # ~10 years, for the locked
                                               # statutory archive only
# COMPLIANCE: nobody, including the account root, can delete before retention
# expires. GOVERNANCE: a principal holding s3:BypassGovernanceRetention can.
# The mode cannot be relaxed afterwards — moving COMPLIANCE → GOVERNANCE means
# a new bucket.
#
# COMPLIANCE is the stronger evidentiary claim. It also makes a GDPR erasure
# request impossible to honour against backups for the whole retention period,
# and this database holds account emails and the names of people who signed
# technical documentation. That is a genuine conflict between two obligations,
# not a detail — decide it deliberately per environment.
#
# NOTE: production was provisioned as GOVERNANCE, which does not match this
# default. Whichever you pick, /privacy.html has to describe it accurately: the
# published policy tells users what deletion can and cannot reach.
LOCK_MODE="${CRA_BACKUP_LOCK_MODE:-COMPLIANCE}"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

say "Directory layout"
mkdir -p "$REMOTE"
# /var/backups is root-owned on a stock Ubuntu image, so a plain mkdir here
# fails and takes the whole script with it. backup.sh runs unprivileged from
# cron, so create the directory with sudo and hand ownership over rather than
# escalating the nightly backup to root.
if [ ! -d /var/backups/cra ]; then
  sudo mkdir -p /var/backups/cra
  sudo chown "$(id -u):$(id -g)" /var/backups/cra
fi

say "Database and role"
# A dedicated role and database, not a schema inside someone else's. This store
# holds unreported exploited-vulnerability details; a credential compromise in
# an unrelated app on the same Postgres must not reach it.
ENV_FILE="${REMOTE}/.env"

role_exists() {
  docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1
}

# The generated password goes straight into ${REMOTE}/.env and is never echoed.
# Printing it puts it in terminal scrollback, shell history, and any transcript
# of the session — for a store of unreported vulnerabilities that is one copy
# too many. The file is the single place it exists.
write_database_url() {
  umask 077
  touch "$ENV_FILE"
  grep -v '^DATABASE_URL=' "$ENV_FILE" > "${ENV_FILE}.tmp" || true
  echo "DATABASE_URL=postgresql+psycopg://${DB_USER}:${1}@${PG_CONTAINER}:5432/${DB}" \
    >> "${ENV_FILE}.tmp"
  mv "${ENV_FILE}.tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

if role_exists; then
  if grep -q '^DATABASE_URL=.*://[^:]*:[^@]\{1,\}@' "$ENV_FILE" 2>/dev/null && \
     ! grep -q '^DATABASE_URL=.*CHANGE_ME' "$ENV_FILE" 2>/dev/null; then
    echo "role ${DB_USER} exists and ${ENV_FILE} already carries its password — left alone"
  else
    # The role exists but nothing knows its password: it was generated on an
    # earlier run and only ever lived in that .env. Rotate rather than guess.
    PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)"
    docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -c \
      "ALTER ROLE ${DB_USER} PASSWORD '${PASS}'" >/dev/null
    write_database_url "$PASS"
    echo "role ${DB_USER} existed with no known password — rotated, ${ENV_FILE} updated"
  fi
else
  PASS="${CRA_DB_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)}"
  docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -c \
    "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${PASS}'" >/dev/null
  write_database_url "$PASS"
  echo "role ${DB_USER} created, DATABASE_URL written to ${ENV_FILE}"
fi

docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -tAc \
  "SELECT 1 FROM pg_database WHERE datname='${DB}'" | grep -q 1 || \
  docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -c \
    "CREATE DATABASE ${DB} OWNER ${DB_USER}"
# CITEXT is used by users.email and must exist before the migration runs.
docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -d "$DB" -c \
  "CREATE EXTENSION IF NOT EXISTS citext"

# Revoke the default PUBLIC connect grant, so only this role reaches it.
docker exec "$PG_CONTAINER" psql -U "$PG_SUPER" -c \
  "REVOKE CONNECT ON DATABASE ${DB} FROM PUBLIC"


if [ -n "$BUCKET" ]; then
  say "Backup bucket with object lock"
  # Object Lock can only be enabled at creation time. If the bucket exists
  # without it, retention cannot be added later — make a new one.
  if ! aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=${REGION}" \
      --object-lock-enabled-for-bucket >/dev/null
    aws s3api put-public-access-block --bucket "$BUCKET" --region "$REGION" \
      --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    aws s3api put-bucket-encryption --bucket "$BUCKET" --region "$REGION" \
      --server-side-encryption-configuration \
      '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
    aws s3api put-object-lock-configuration --bucket "$BUCKET" --region "$REGION" \
      --object-lock-configuration \
      "{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"${LOCK_MODE}\",\"Days\":${RETAIN_DAYS}}}}"
    echo "created ${BUCKET} — ${LOCK_MODE} lock, ${RETAIN_DAYS} days"
    if [ "$LOCK_MODE" = "COMPLIANCE" ]; then
      echo "NOTE: objects in this bucket cannot be deleted by anyone, including"
      echo "      the account root, until their retention expires. That is the point."
    else
      echo "NOTE: retention is ${RETAIN_DAYS} days, but a principal holding"
      echo "      s3:BypassGovernanceRetention can delete anyway. Deny that action"
      echo "      outside a break-glass role, or the retention is decorative."
    fi
  else
    echo "${BUCKET} already exists — verify it has object lock enabled:"
    echo "  aws s3api get-object-lock-configuration --bucket ${BUCKET}"
  fi
else
  say "Skipping backup bucket (CRA_BACKUP_BUCKET unset)"
  echo "Set it and re-run. Ten-year retention is a legal obligation here, not"
  echo "an operational nicety — see deploy/backup.sh."
fi

say "Next"
# NOT `cp env.example .env` — that would clobber the DATABASE_URL this script
# just wrote, and the password it contains exists nowhere else.
echo "  1. append deploy/env.example to ${REMOTE}/.env (keep the DATABASE_URL"
echo "     line already there), then edit the rest"
echo "  2. cp deploy/compose.yml.example ${REMOTE}/compose.yml  &&  edit"
echo "  3. add deploy/Caddyfile.snippet to the host Caddyfile, reload Caddy"
echo "  4. from your laptop: ./deploy/deploy.sh"
