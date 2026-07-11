"""Re-encrypt each source snapshot into the forensics custody domain.

CopySnapshot with the forensics CMK produces a copy encrypted under a key whose
policy only the pipeline and account admins control. Evidence access is then
governed by that key, independent of whatever (if anything) encrypted the
victim's original volumes.
"""

import os

import boto3

ec2 = boto3.client("ec2")

FORENSICS_KMS_ARN = os.environ["FORENSICS_KMS_ARN"]
SOURCE_REGION = os.environ.get("AWS_REGION", "us-east-1")


def handler(event, _context):
    instance_id = event["instance_id"]
    source_snapshots = event.get("source_snapshots", [])

    copies = []
    for snap in source_snapshots:
        resp = ec2.copy_snapshot(
            SourceRegion=SOURCE_REGION,
            SourceSnapshotId=snap["snapshot_id"],
            Description=f"Encrypted forensic copy of {snap['snapshot_id']}",
            Encrypted=True,
            KmsKeyId=FORENSICS_KMS_ARN,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "forensics:stage", "Value": "evidence"},
                        {"Key": "forensics:instance", "Value": instance_id},
                        {"Key": "forensics:source", "Value": snap["snapshot_id"]},
                    ],
                }
            ],
        )
        copies.append(
            {
                "source_snapshot_id": snap["snapshot_id"],
                "encrypted_snapshot_id": resp["SnapshotId"],
                "volume_id": snap["volume_id"],
            }
        )

    return {
        "instance_id": instance_id,
        "copies": copies,
        "attempts": 0,
    }
