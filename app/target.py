"""AWS clients for the account the instance under investigation lives in.

Standalone, the pipeline acts in its own account and TARGET_ROLES is empty, so
these are plain clients. In a landing zone the pipeline runs in the security
account and each step assumes its own target role in the workload account, so
TARGET_ROLES maps account id -> that step's role ARN. An account with no
target role is refused outright: the pipeline never falls back to acting with
its own credentials on an account it was not granted.
"""

import json
import os

import boto3

_TARGET_ROLES = json.loads(os.environ.get("TARGET_ROLES") or "{}")


def landing_zone_mode():
    return bool(_TARGET_ROLES)


def has_target(account_id):
    return account_id in _TARGET_ROLES


def client(service, account_id=None):
    if not _TARGET_ROLES:
        return boto3.client(service)
    role_arn = _TARGET_ROLES.get(account_id)
    if not role_arn:
        raise PermissionError(f"no forensics target role for account {account_id}")
    creds = boto3.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName="incident-forensics"
    )["Credentials"]
    return boto3.client(
        service,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
