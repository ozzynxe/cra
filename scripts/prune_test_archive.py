#!/usr/bin/env python
"""List what is in the statutory archive, and delete a named product's artefacts.

    scripts/prune_test_archive.py                          # what is in there
    scripts/prune_test_archive.py --delete-products <id>…   # remove those, with bypass

Every full end-to-end run writes into the ten-year archive: freezing a technical
file, drawing up a declaration, signing off and recording a release each export
an artefact under Object Lock. Test data therefore accumulates in the store that
exists to hold customers' statutory records, somewhere it cannot ordinarily be
deleted from. One run put eight objects there.

## Where this runs, and why it does not touch the database

**An operator workstation, not the host.** The container's AWS identity can
`PutObject` and nothing else — no `ListBucket`, no delete — which is
`deploy/backup-iam-policy.json.template` doing its job: a compromised host can
write records and can neither enumerate nor erase them. Deleting needs
`s3:BypassGovernanceRetention`, which lives with the operator.

That split is also why nothing here reads the product table to decide what is
disposable. It could not reach it from where it runs, and it should not: a regex
over product names deciding what to bypass-delete from an immutable store is a
judgement dressed as a check. **You name the products.** This lists what is
there, and then deletes only what you named, refusing every object that does not
belong to one of them.

## Afterwards

Deleting objects leaves `statutory_exports` rows saying `exported` with storage
keys pointing at nothing — the database asserting artefacts are archived when
they are not, which is the false record this product exists to prevent, in its
own tables. The SQL to clear them is printed at the end; run it on the host.
Deleted rather than reset to `pending`, which would have the nightly sweeper
upload them again.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict

KEY_RE = re.compile(
    r"^product/(?P<pid>[0-9a-f-]{36})/(?P<kind>[a-z_]+)/(?P<digest>[0-9a-f]{64})\.json$"
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bucket", default=os.environ.get("CRA_STATUTORY_BUCKET", ""),
                    help="defaults to $CRA_STATUTORY_BUCKET")
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-north-1"))
    ap.add_argument("--delete-products", nargs="*", default=[], metavar="PRODUCT_ID",
                    help="product ids whose artefacts to remove; anything else is refused")
    args = ap.parse_args()

    if not args.bucket:
        sys.exit(
            "no bucket. Either pass --bucket, or put CRA_STATUTORY_BUCKET in "
            "deploy/deploy.env and `source` it — see deploy/deploy.env.example."
        )

    try:
        import boto3
    except ModuleNotFoundError:
        sys.exit(
            "boto3 is not available to this interpreter. It is in the project "
            "venv:\n"
            "  .venv/bin/python scripts/prune_test_archive.py …\n"
            "(Run from an operator workstation with AWS credentials — the "
            "container cannot list or delete here, by design.)"
        )

    s3 = boto3.client("s3", region_name=args.region)
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=args.bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]

    if not keys:
        print(f"  {args.bucket} is empty.")
        return 0

    by_product: dict[str, list[tuple[str, str]]] = defaultdict(list)
    unparsed: list[str] = []
    for k in keys:
        m = KEY_RE.match(k)
        if m:
            by_product[m.group("pid")].append((k, m.group("kind")))
        else:
            unparsed.append(k)

    print(f"\n  {args.bucket}: {len(keys)} object(s), "
          f"{len(by_product)} product(s)\n")
    for pid, items in sorted(by_product.items()):
        kinds = ", ".join(sorted({k for _key, k in items}))
        marked = " ← named for deletion" if pid in args.delete_products else ""
        print(f"    {pid}  {len(items):>2} object(s)  {kinds}{marked}")
    for k in unparsed:
        print(f"    unrecognised key shape: {k}")

    if not args.delete_products:
        print(
            "\n  Report only. To remove a product's artefacts, name it:\n"
            f"    scripts/prune_test_archive.py --delete-products <product_id>\n"
            "\n  Check first that the id is a test product. On the host:\n"
            "    docker exec deploy-postgres-1 psql -U \"$CRA_DB_SUPERUSER\" -d cra \\\n"
            "      -c \"select id, name from products where id in ('…');\"\n"
        )
        return 0

    unknown = [p for p in args.delete_products if p not in by_product]
    if unknown:
        print(f"\n  Not in this bucket: {', '.join(unknown)}")
        print("  Refusing — a mistyped id that silently matches nothing is how the")
        print("  wrong thing gets deleted on the next attempt.")
        return 1
    if unparsed:
        print("\n  Refusing while an unrecognised key is present: an object this")
        print("  script cannot explain is exactly the one not to bypass-delete.")
        return 1

    targets = [(k, pid) for pid in args.delete_products for k, _kind in by_product[pid]]
    print(f"\n  Deleting {len(targets)} object(s) under "
          f"{len(args.delete_products)} product(s), with governance bypass.")

    deleted = 0
    for k, _pid in targets:
        head = s3.head_object(Bucket=args.bucket, Key=k)
        s3.delete_object(
            Bucket=args.bucket, Key=k,
            VersionId=head["VersionId"],
            BypassGovernanceRetention=True,
        )
        deleted += 1

    left = s3.list_objects_v2(Bucket=args.bucket).get("KeyCount", 0)
    ids = ", ".join(f"'{p}'" for p in args.delete_products)
    print(f"  deleted {deleted}; {args.bucket} now holds {left} object(s)")
    print(
        "\n  Now clear the rows that still claim these are archived. On the host:\n"
        f"    docker exec deploy-postgres-1 psql -U \"$CRA_DB_SUPERUSER\" -d cra \\\n"
        f"      -c \"delete from statutory_exports where product_id in ({ids});\"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
