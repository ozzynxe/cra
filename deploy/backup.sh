#!/usr/bin/env bash
# Nightly backup of the cra database to S3, with object-lock retention.
#
# Install on the host as a cron entry:
#   0 3 * * * /home/ubuntu/cra/deploy/backup.sh >> /var/log/cra-backup.log 2>&1
#
# Why this is not ordinary ops hygiene
# ------------------------------------
# Annex VII requires the technical file to be retained for **ten years** after
# the product is placed on the market, and the audit trail is what evidences
# every change to it. Losing this database is not an availability incident, it
# is a compliance failure that cannot be remediated afterwards — you cannot
# reconstruct who attested to what on which date.
#
# **This script does disaster recovery only, and its target must not be a
# locked bucket.** Point `CRA_BACKUP_BUCKET` at a bucket with no Object Lock and
# a short lifecycle; the statutory record is copied separately, per artefact,
# by the application (`server/statutory_export.py`) with retention set from the
# obligation rather than from a backup schedule.
#
# That split is the whole point. A nightly dump of the entire database sent to a
# locked bucket keeps every abandoned draft for a decade because one signed file
# has to be kept, and nothing written under Object Lock can be reclaimed
# afterwards.
#
# If a deployment does point this at a locked bucket, its privacy policy has to
# say so: what users are told about deletion is derived from where these objects
# land and how long they survive. Governance mode leaves erasure possible as a
# privileged manual operation; compliance mode does not, for the full retention
# period, which is a poor position for a service holding account emails and
# signatory names.

set -euo pipefail

BUCKET="${CRA_BACKUP_BUCKET:?CRA_BACKUP_BUCKET is not set}"
REGION="${CRA_BACKUP_REGION:-eu-north-1}"
CONTAINER="${CRA_PG_CONTAINER:-deploy-postgres-1}"
DB="${CRA_DB_NAME:-cra}"
DB_USER="${CRA_DB_USER:-cra_app}"
KEEP_LOCAL_DAYS="${CRA_BACKUP_KEEP_LOCAL_DAYS:-7}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="/var/backups/cra"
FILE="${WORK}/cra-${STAMP}.dump"

mkdir -p "$WORK"

echo "[$(date -u +%FT%TZ)] dumping ${DB}"
# Custom format: compressed, and restorable selectively with pg_restore, which
# matters when you need one table back rather than the whole database.
docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB" -Fc > "$FILE"

SIZE=$(stat -c %s "$FILE")
[ "$SIZE" -gt 4096 ] || { echo "dump is only ${SIZE} bytes — refusing to upload"; exit 1; }

# Verify before uploading. An unrestorable backup that uploads cleanly is worse
# than a failed backup, because it stops anyone looking.
echo "[$(date -u +%FT%TZ)] verifying restorability"
docker exec -i "$CONTAINER" pg_restore --list > /dev/null < "$FILE" \
  || { echo "pg_restore cannot read the dump — NOT uploading"; exit 1; }

SHA=$(sha256sum "$FILE" | cut -d' ' -f1)
echo "[$(date -u +%FT%TZ)] uploading ${SIZE} bytes, sha256 ${SHA}"

aws s3api put-object \
  --bucket "$BUCKET" \
  --key "db/${STAMP}.dump" \
  --body "$FILE" \
  --region "$REGION" \
  --checksum-algorithm SHA256 \
  --metadata "sha256=${SHA},source=cra-assistant" \
  >/dev/null

echo "[$(date -u +%FT%TZ)] uploaded s3://${BUCKET}/db/${STAMP}.dump"

find "$WORK" -name 'cra-*.dump' -mtime "+${KEEP_LOCAL_DAYS}" -delete
echo "[$(date -u +%FT%TZ)] done"
