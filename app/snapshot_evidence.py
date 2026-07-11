"""Snapshot every EBS volume attached to the instance.

These are the source snapshots. They inherit the volume's own encryption state
(often none, in the demo). The next step copies each one re-encrypted with the
forensics CMK; these sources are deleted once the encrypted copies land.
"""

import boto3

ec2 = boto3.client("ec2")


def handler(event, _context):
    instance_id = event["instance_id"]
    volume_ids = event.get("volume_ids", [])
    finding_type = event.get("finding_type", "unknown")

    snapshots = []
    for volume_id in volume_ids:
        resp = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"Forensic capture of {volume_id} from {instance_id} ({finding_type})",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "forensics:stage", "Value": "source"},
                        {"Key": "forensics:instance", "Value": instance_id},
                        {"Key": "forensics:volume", "Value": volume_id},
                    ],
                }
            ],
        )
        snapshots.append({"volume_id": volume_id, "snapshot_id": resp["SnapshotId"]})

    return {
        "instance_id": instance_id,
        "source_snapshots": snapshots,
    }
