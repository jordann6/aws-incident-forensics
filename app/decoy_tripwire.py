"""Turn any use of a planted decoy access key into a runbook execution.

A decoy key is a real IAM access key on a user with no policies, written into
.aws/credentials on one server. Nothing legitimate ever calls AWS with it, so
the first CloudTrail event signed by that key means someone read the file. The
EventBridge rule hands this function that CloudTrail event. The function looks
up which server the key was planted on, then starts the same runbook a High
GuardDuty finding would, so the server is isolated, snapshotted, and has its
role sessions revoked.

Each server gets its own key. That is the only way the alert can name the box
to isolate; one shared key would say "something is compromised" and nothing
more.

An attacker usually makes many calls in a burst. The execution name is the
instance plus the UTC day, so the first call starts the runbook and every
repeat that day is a no-op instead of a pile of duplicate snapshots.
"""

import json
import os
import re

import boto3

ssm = boto3.client("ssm")
sfn = boto3.client("stepfunctions")
sns = boto3.client("sns")

STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")
ALERTS_TOPIC_ARN = os.environ.get("ALERTS_TOPIC_ARN", "")
DECOY_PARAM_PREFIX = os.environ.get("DECOY_PARAM_PREFIX", "")

FINDING_TYPE = "Forensics:IAMUser/DecoyCredentialUsed"
SEVERITY = 8

_KEY_ID = re.compile(r"^AKIA[A-Z0-9]{16}$")


def handler(event, _context):
    detail = event.get("detail", {})
    key_id = detail.get("userIdentity", {}).get("accessKeyId", "")
    call = {
        "event_name": detail.get("eventName"),
        "event_source": detail.get("eventSource"),
        "source_ip": detail.get("sourceIPAddress"),
        "user_agent": detail.get("userAgent"),
        "region": detail.get("awsRegion"),
        "error_code": detail.get("errorCode"),
        "event_time": detail.get("eventTime", ""),
    }
    account_id = detail.get("recipientAccountId") or event.get("account")

    instance_id = planted_on(key_id)
    if not instance_id:
        # Still a compromise signal, just one we cannot route to a host.
        _alert(f"[DECOY KEY USED] {key_id} has no instance mapping", key_id, None, call)
        return {"started": None, "reason": "no instance mapping for key"}

    finding = build_finding(key_id, instance_id, account_id, call, detail.get("eventID", ""))
    name = execution_name(instance_id, call["event_time"])

    try:
        resp = sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN, name=name, input=json.dumps(finding)
        )
    except sfn.exceptions.ExecutionAlreadyExists:
        print(json.dumps({"duplicate": name, "key_id": key_id, **call}))
        return {"started": None, "reason": "runbook already running for this instance today"}
    except Exception:
        _alert(
            f"[DECOY KEY USED] {instance_id}, runbook FAILED to start", key_id, instance_id, call
        )
        raise

    _alert(f"[DECOY KEY USED] isolating {instance_id}", key_id, instance_id, call)
    return {"started": resp["executionArn"], "instance_id": instance_id}


def planted_on(key_id):
    """Instance id the key was planted on, from /<project>/decoys/<key id>."""
    if not _KEY_ID.match(key_id or ""):
        return None
    try:
        param = ssm.get_parameter(Name=f"{DECOY_PARAM_PREFIX}/{key_id}")
    except ssm.exceptions.ParameterNotFound:
        return None
    return param["Parameter"]["Value"]


def execution_name(instance_id, event_time):
    day = (event_time or "unknown")[:10].replace("-", "")
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"decoy-{instance_id}-{day}")[:80]


def build_finding(key_id, instance_id, account_id, call, event_id):
    """An EventBridge event shaped like a GuardDuty EC2 finding.

    The runbook only reads detail.severity, detail.type, detail.accountId and
    detail.resource.instanceDetails.instanceId, so this drops straight in.
    """
    return {
        "version": "0",
        "source": "forensics.decoy",
        "detail-type": "GuardDuty Finding",
        "account": account_id,
        "region": call["region"],
        "detail": {
            "schemaVersion": "2.0",
            "id": f"decoy-{key_id}-{event_id}"[:120],
            "accountId": account_id,
            "type": FINDING_TYPE,
            "severity": SEVERITY,
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {"instanceId": instance_id},
                "accessKeyDetails": {"accessKeyId": key_id},
            },
            "service": {
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": call["event_name"],
                        "serviceName": call["event_source"],
                        "callerType": "Remote IP",
                        "errorCode": call["error_code"],
                        "remoteIpDetails": {"ipAddressV4": call["source_ip"]},
                        "userAgent": call["user_agent"],
                    },
                }
            },
        },
    }


def _alert(subject, key_id, instance_id, call):
    if not ALERTS_TOPIC_ARN:
        return
    body = {"decoy_access_key_id": key_id, "planted_on": instance_id, **call}
    sns.publish(
        TopicArn=ALERTS_TOPIC_ARN,
        Subject=subject[:100],
        Message=json.dumps(body, indent=2),
    )
