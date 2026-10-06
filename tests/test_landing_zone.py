"""Landing zone behavior: account scoping, the SNS starter, quarantine lookup."""

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

PROD = "111111111111"
OTHER = "222222222222"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:333333333333:stateMachine:x")
    monkeypatch.setenv(
        "TARGET_ROLES", json.dumps({PROD: f"arn:aws:iam::{PROD}:role/forensics/forensics-step"})
    )


def _load(name):
    import target

    importlib.reload(target)
    return importlib.reload(importlib.import_module(name))


def test_target_refuses_unscoped_account():
    target = _load("target")
    assert target.landing_zone_mode()
    with pytest.raises(PermissionError):
        target.client("ec2", OTHER)


def test_extract_context_does_not_act_outside_scope():
    extract = _load("extract_context")
    event = {"detail": {"severity": 8, "accountId": OTHER,
                        "resource": {"instanceDetails": {"instanceId": "i-0abc"}}}}
    result = extract.handler(event, None)
    assert result["should_respond"] is False
    assert OTHER in result["reason"]


class _Sfn:
    def __init__(self):
        self.calls = []

    def start_execution(self, **kwargs):
        self.calls.append(kwargs)
        return {"executionArn": f"arn:exec:{len(self.calls)}"}


def _record(event):
    return {"Sns": {"Message": json.dumps(event)}}


def test_starter_runs_only_guardduty_instance_findings():
    starter = _load("start_from_sns")
    starter.sfn = _Sfn()
    gd = {"detail-type": "GuardDuty Finding",
          "detail": {"id": "abc/def:1", "resource": {"resourceType": "Instance"}}}
    gd_s3 = {"detail-type": "GuardDuty Finding",
             "detail": {"id": "x", "resource": {"resourceType": "S3Bucket"}}}
    hub = {"detail-type": "Security Hub Findings - Imported", "detail": {}}
    result = starter.handler({"Records": [_record(gd), _record(gd_s3), _record(hub)]}, None)
    assert len(result["started"]) == 1
    assert len(result["skipped"]) == 2
    call = starter.sfn.calls[0]
    assert json.loads(call["input"]) == gd
    assert len(call["name"]) <= 80 and "/" not in call["name"] and ":" not in call["name"]


class _Ec2:
    def __init__(self, groups):
        self.groups = groups

    def describe_security_groups(self, **_kwargs):
        return {"SecurityGroups": self.groups}


def test_quarantine_lookup_requires_exactly_one_rule_free_group():
    clean_sg = {"GroupId": "sg-1", "IpPermissions": [], "IpPermissionsEgress": []}
    isolate = _load("isolate_instance")
    assert isolate._tagged_quarantine_sg(_Ec2([clean_sg]), "vpc-1") == "sg-1"
    with pytest.raises(RuntimeError):
        isolate._tagged_quarantine_sg(_Ec2([]), "vpc-1")
    leaky = dict(clean_sg, IpPermissionsEgress=[{"IpProtocol": "-1"}])
    with pytest.raises(RuntimeError):
        isolate._tagged_quarantine_sg(_Ec2([leaky]), "vpc-1")
