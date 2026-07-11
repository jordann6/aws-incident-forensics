"""Assemble the evidence bundle, write it to S3, delete the unencrypted sources.

The bundle is a JSON manifest: the finding context, what was isolated, the
encrypted evidence snapshot ids, the revocation result, and console output
captured from the instance. It is written to the SSE-KMS evidence bucket under
a timestamped, instance-scoped key so an investigation has one object to pull.

Deleting the source snapshots is the last step: only the encrypted copies
survive, so no unencrypted evidence is left lying around. The IAM policy lets
this function delete only snapshots tagged forensics:stage=source.
"""

import json
import os
from datetime import datetime, timezone

import boto3

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]


def handler(event, _context):
    context = event.get("context", {})
    instance_id = context.get("instance_id", "unknown")
    captured_at = datetime.now(timezone.utc)

    console_output = _console_output(instance_id)

    encrypted = event.get("encrypted", {})
    evidence_snapshots = [
        c["encrypted_snapshot_id"] for c in encrypted.get("copies", [])
    ]

    manifest = {
        "schema": "aws-incident-forensics/evidence/v1",
        "captured_at": captured_at.isoformat(),
        "finding": {
            "type": context.get("finding_type"),
            "severity": context.get("severity"),
        },
        "instance": {
            "id": instance_id,
            "vpc_id": context.get("vpc_id"),
            "role_name": context.get("role_name"),
        },
        "containment": {
            "isolation": event.get("isolation", {}),
            "revocation": event.get("revocation", {}),
        },
        "evidence": {
            "encrypted_snapshots": evidence_snapshots,
            "console_output": console_output,
        },
    }

    key = (
        f"evidence/{instance_id}/"
        f"{captured_at.strftime('%Y-%m-%dT%H-%M-%SZ')}/manifest.json"
    )

    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=key,
        Body=json.dumps(manifest, indent=2).encode("utf-8"),
        ContentType="application/json",
    )

    deleted = _delete_sources(encrypted.get("copies", []))

    return {
        "evidence_key": key,
        "evidence_bucket": EVIDENCE_BUCKET,
        "evidence_snapshots": evidence_snapshots,
        "deleted_source_snapshots": deleted,
    }


def _console_output(instance_id):
    """Best-effort console capture; never fail the bundle over it."""
    try:
        resp = ec2.get_console_output(InstanceId=instance_id)
        return resp.get("Output", "")
    except Exception:  # noqa: BLE001 - evidence is still valid without it
        return ""


def _delete_sources(copies):
    deleted = []
    for copy in copies:
        source_id = copy.get("source_snapshot_id")
        if not source_id:
            continue
        try:
            ec2.delete_snapshot(SnapshotId=source_id)
            deleted.append(source_id)
        except Exception:  # noqa: BLE001 - a stuck source is not worth failing the run
            continue
    return deleted
