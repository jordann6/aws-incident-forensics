"""Move every network interface on the instance onto the quarantine SG.

Swapping the security group (rather than stopping the instance) freezes the
blast radius while leaving volatile state - running processes, memory-resident
malware, open sockets - intact for later inspection. The quarantine SG has no
ingress and no egress, so the host is cut off in both directions the moment
this returns.
"""

import os

import boto3

ec2 = boto3.client("ec2")

QUARANTINE_SG_ID = os.environ["QUARANTINE_SG_ID"]


def handler(event, _context):
    instance_id = event["instance_id"]
    eni_ids = event.get("eni_ids", [])

    isolated = []
    for eni_id in eni_ids:
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[QUARANTINE_SG_ID],
        )
        isolated.append(eni_id)

    # Tag the instance so it is obvious in the console that it is under
    # investigation and must not be touched.
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "forensics:status", "Value": "quarantined"},
            {"Key": "forensics:isolated", "Value": "true"},
        ],
    )

    return {
        "isolated_enis": isolated,
        "quarantine_sg": QUARANTINE_SG_ID,
    }
