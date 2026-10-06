"""Move every network interface on the instance onto the quarantine SG.

Swapping the security group (rather than stopping the instance) freezes the
blast radius while leaving volatile state - running processes, memory-resident
malware, open sockets - intact for later inspection. The quarantine SG has no
ingress and no egress, so the host is cut off in both directions the moment
this returns.
"""

import os

import target

# Standalone, the quarantine group is passed in. In a landing zone it is found
# by its lz:quarantine tag in the instance's own VPC, so one pipeline serves
# every workload account without per-account configuration.
QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID", "")


def handler(event, _context):
    instance_id = event["instance_id"]
    eni_ids = event.get("eni_ids", [])
    ec2 = target.client("ec2", event.get("account_id"))
    quarantine_sg = QUARANTINE_SG_ID or _tagged_quarantine_sg(ec2, event["vpc_id"])

    isolated = []
    for eni_id in eni_ids:
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[quarantine_sg],
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
        "quarantine_sg": quarantine_sg,
    }


def _tagged_quarantine_sg(ec2, vpc_id):
    groups = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "tag:lz:quarantine", "Values": ["true"]},
        ]
    )["SecurityGroups"]
    if len(groups) != 1:
        raise RuntimeError(f"expected one quarantine group in {vpc_id}, found {len(groups)}")
    # A quarantine group that allows anything is not a quarantine group.
    group = groups[0]
    if group.get("IpPermissions") or group.get("IpPermissionsEgress"):
        raise RuntimeError(f"quarantine group {group['GroupId']} has rules; refusing to use it")
    return group["GroupId"]
