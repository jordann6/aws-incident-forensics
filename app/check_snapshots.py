"""Poll the encrypted snapshot copies for completion.

The state machine calls this on every pass of its wait loop. It reports:
  all_complete - every copy is 'completed', proceed
  exhausted    - too many attempts, give up and notify failure
Neither true -> the Choice state loops back to Wait.

A bounded attempt counter is what keeps the loop from running forever if a
copy gets stuck; SNAPSHOT_POLL_MAX_ATTEMPTS wait cycles is the ceiling.
"""

import os

import boto3

ec2 = boto3.client("ec2")

MAX_ATTEMPTS = int(os.environ.get("SNAPSHOT_POLL_MAX_ATTEMPTS", "40"))


def handler(event, _context):
    copies = event.get("copies", [])
    attempts = int(event.get("attempts", 0)) + 1

    snapshot_ids = [c["encrypted_snapshot_id"] for c in copies]

    states = {}
    if snapshot_ids:
        resp = ec2.describe_snapshots(SnapshotIds=snapshot_ids)
        states = {s["SnapshotId"]: s["State"] for s in resp["Snapshots"]}

    all_complete = bool(snapshot_ids) and all(
        states.get(sid) == "completed" for sid in snapshot_ids
    )
    failed = any(states.get(sid) == "error" for sid in snapshot_ids)
    exhausted = (attempts >= MAX_ATTEMPTS) or failed

    return {
        "copies": copies,
        "attempts": attempts,
        "states": states,
        "all_complete": all_complete,
        "exhausted": exhausted and not all_complete,
    }
