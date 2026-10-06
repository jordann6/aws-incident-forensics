"""Start the runbook from the landing zone's security-findings SNS topic.

The topic carries every HIGH/CRITICAL GuardDuty and Security Hub finding in the
organization. Only GuardDuty findings against an EC2 instance are runbook
material; everything else is left to the topic's other subscribers. Each SNS
message is the original EventBridge event, which is passed to the state machine
unchanged, so the runbook sees exactly what a direct EventBridge target would.
"""

import json
import os
import re
import uuid

import boto3

sfn = boto3.client("stepfunctions")

STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]


def handler(event, _context):
    started, skipped = [], []
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        detail = message.get("detail", {})
        if (
            message.get("detail-type") != "GuardDuty Finding"
            or detail.get("resource", {}).get("resourceType") != "Instance"
        ):
            skipped.append(message.get("detail-type", "unknown"))
            continue
        # Execution names are unique per state machine and limited to 80
        # characters of [A-Za-z0-9-_].
        finding_id = re.sub(r"[^A-Za-z0-9_-]", "-", str(detail.get("id", "finding")))[:40]
        resp = sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=f"{finding_id}-{uuid.uuid4().hex[:12]}",
            input=json.dumps(message),
        )
        started.append(resp["executionArn"])
    print(json.dumps({"started": started, "skipped": skipped}))
    return {"started": started, "skipped": skipped}
