"""Revoke any credentials the instance role may have leaked.

An instance role hands out temporary credentials through the metadata service.
If an attacker pulled those, they hold valid STS sessions that isolating the
host does nothing to stop. Attaching an inline policy that denies everything
issued before 'now' (via aws:TokenIssueTime) invalidates every session already
in the wild while leaving the role able to mint fresh sessions if the workload
is later cleared. This is the AWS-documented "revoke sessions" pattern.

The function can only touch roles under DEMO_ROLE_PATH; the IAM policy on this
Lambda enforces that boundary independently.
"""

import json
import os
from datetime import datetime, timezone

import boto3

iam = boto3.client("iam")

DEMO_ROLE_PATH = os.environ["DEMO_ROLE_PATH"]


def handler(event, _context):
    role_name = event.get("role_name")
    if not role_name:
        return {"revoked": False, "reason": "instance had no role"}

    # Confirm the role is under the containment path before mutating it. The
    # IAM policy already scopes this, but failing loudly here is clearer than
    # an opaque AccessDenied.
    role = iam.get_role(RoleName=role_name)
    if role["Role"]["Path"] != DEMO_ROLE_PATH:
        return {
            "revoked": False,
            "reason": f"role path {role['Role']['Path']} outside containment boundary",
        }

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RevokeOldSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
            }
        ],
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="ForensicsRevokeOldSessions",
        PolicyDocument=json.dumps(policy),
    )

    return {"revoked": True, "role_name": role_name, "cutoff": now}
