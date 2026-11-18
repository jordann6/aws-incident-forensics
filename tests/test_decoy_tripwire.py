"""Decoy tripwire: key-to-instance routing, finding shape, burst dedupe."""

import importlib
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

KEY = "AKIAIOSFODNN7EXAMPLE"
INSTANCE = "i-0123456789abcdef0"


class _AlreadyExists(Exception):
    pass


class _NotFound(Exception):
    pass


@pytest.fixture
def tripwire(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws:states:us-east-1:111111111111:stateMachine:x")
    monkeypatch.setenv("ALERTS_TOPIC_ARN", "arn:aws:sns:us-east-1:111111111111:alerts")
    monkeypatch.setenv("DECOY_PARAM_PREFIX", "/incident-forensics/decoys")
    mod = importlib.reload(importlib.import_module("decoy_tripwire"))

    mod.ssm = mock.Mock()
    mod.ssm.exceptions.ParameterNotFound = _NotFound
    mod.ssm.get_parameter.side_effect = lambda Name: (
        {"Parameter": {"Value": INSTANCE}}
        if Name == f"/incident-forensics/decoys/{KEY}"
        else (_ for _ in ()).throw(_NotFound())
    )
    mod.sfn = mock.Mock()
    mod.sfn.exceptions.ExecutionAlreadyExists = _AlreadyExists
    mod.sfn.start_execution.return_value = {"executionArn": "arn:exec"}
    mod.sns = mock.Mock()
    return mod


def _event(key=KEY, name="GetCallerIdentity"):
    return {
        "account": "111111111111",
        "detail": {
            "eventName": name,
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2026-11-18T09:15:00Z",
            "eventID": "abc-123",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.7",
            "recipientAccountId": "111111111111",
            "userIdentity": {"type": "IAMUser", "accessKeyId": key},
        },
    }


def test_routes_key_to_its_instance_and_starts_runbook(tripwire):
    out = tripwire.handler(_event(), None)

    assert out["instance_id"] == INSTANCE
    call = tripwire.sfn.start_execution.call_args.kwargs
    assert call["name"] == f"decoy-{INSTANCE}-20261118"
    finding = json.loads(call["input"])
    assert finding["detail-type"] == "GuardDuty Finding"
    assert finding["detail"]["severity"] >= 7
    assert finding["detail"]["resource"]["instanceDetails"]["instanceId"] == INSTANCE
    assert finding["detail"]["accountId"] == "111111111111"
    tripwire.sns.publish.assert_called_once()


def test_finding_passes_extract_context_gate(tripwire, monkeypatch):
    """The synthetic finding must clear the runbook's own severity gate."""
    monkeypatch.delenv("TARGET_ROLES", raising=False)
    import target

    importlib.reload(target)
    extract = importlib.reload(importlib.import_module("extract_context"))
    tripwire.handler(_event(), None)
    finding = json.loads(tripwire.sfn.start_execution.call_args.kwargs["input"])

    ec2 = mock.Mock()
    ec2.describe_instances.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": INSTANCE, "VpcId": "vpc-1"}]}]
    }
    with mock.patch.object(extract.target, "client", return_value=ec2):
        ctx = extract.handler(finding, None)
    assert ctx["should_respond"] is True
    assert ctx["instance_id"] == INSTANCE


def test_burst_of_calls_is_one_execution(tripwire):
    tripwire.handler(_event(), None)
    tripwire.sns.publish.reset_mock()
    tripwire.sfn.start_execution.side_effect = _AlreadyExists()

    out = tripwire.handler(_event(name="ListBuckets"), None)

    assert out["started"] is None
    tripwire.sns.publish.assert_not_called()


def test_unmapped_key_alerts_but_does_not_act(tripwire):
    out = tripwire.handler(_event(key="AKIAI44QH8DHBEXAMPLE"), None)

    assert out["started"] is None
    tripwire.sfn.start_execution.assert_not_called()
    tripwire.sns.publish.assert_called_once()


def test_malformed_key_never_reaches_ssm(tripwire):
    tripwire.handler(_event(key="../../etc"), None)
    tripwire.ssm.get_parameter.assert_not_called()
