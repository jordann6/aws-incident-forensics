"""Parse a GuardDuty finding, resolve the target instance, decide whether to act.

The pipeline treats real (aws.guardduty) and synthetic (forensics.demo) findings
identically: both arrive as an EventBridge event whose detail is a GuardDuty
finding. This function is the only place that reads the raw finding shape, so
every downstream step works from a small normalized context object.
"""

import target

# Findings that describe reconnaissance or benign behavior are not worth the
# blast radius of isolating a host. Only act at or above this severity; the
# EventBridge rule already filters, this is defense in depth in code.
ACT_SEVERITY = 7.0


def handler(event, _context):
    detail = event.get("detail", {})
    severity = float(detail.get("severity", 0))
    finding_type = detail.get("type", "unknown")

    resource = detail.get("resource", {})
    instance_details = resource.get("instanceDetails", {})
    instance_id = instance_details.get("instanceId")
    account_id = detail.get("accountId")

    if not instance_id:
        return {"should_respond": False, "reason": "no instance in finding"}

    # In a landing zone, only accounts that were granted a target role are
    # in scope; a finding anywhere else is reported, never acted on.
    if target.landing_zone_mode() and not target.has_target(account_id):
        return {
            "should_respond": False,
            "reason": f"account {account_id} has no forensics target role",
        }

    ec2 = target.client("ec2", account_id)

    # Confirm the instance still exists and grab live volume + role details.
    # A finding can lag reality; if the instance is already gone, do nothing.
    try:
        described = ec2.describe_instances(InstanceIds=[instance_id])
    except ec2.exceptions.ClientError as exc:
        if "NotFound" in str(exc):
            return {"should_respond": False, "reason": "instance no longer exists"}
        raise

    reservations = described.get("Reservations", [])
    if not reservations:
        return {"should_respond": False, "reason": "instance not found"}

    instance = reservations[0]["Instances"][0]

    volume_ids = [
        m["Ebs"]["VolumeId"]
        for m in instance.get("BlockDeviceMappings", [])
        if "Ebs" in m
    ]

    eni_ids = [
        ni["NetworkInterfaceId"] for ni in instance.get("NetworkInterfaces", [])
    ]

    # The instance profile ARN is an instance-profile ARN; the role name is
    # the last path segment, which revoke_credentials needs to target the role.
    role_name = None
    profile = instance.get("IamInstanceProfile", {})
    if profile.get("Arn"):
        role_name = _role_from_profile(profile["Arn"])

    return {
        "should_respond": severity >= ACT_SEVERITY,
        "instance_id": instance_id,
        "account_id": account_id,
        "finding_type": finding_type,
        "severity": severity,
        "vpc_id": instance.get("VpcId"),
        "volume_ids": volume_ids,
        "eni_ids": eni_ids,
        "role_name": role_name,
    }


def _role_from_profile(profile_arn):
    """arn:aws:iam::123:instance-profile/forensics-demo/name -> name.

    The instance-profile name equals the role name in this project's Terraform,
    which is the common case for a single-role profile.
    """
    return profile_arn.split("/")[-1]
