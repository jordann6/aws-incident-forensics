#!/usr/bin/env bash
# Confirm the pipeline actually did what it claims, from the last execution.
# Run after scripts/demo.sh has driven one execution to completion.
set -euo pipefail

cd "$(dirname "$0")/../terraform"

STATE_MACHINE_ARN="$(terraform output -raw state_machine_arn)"
INSTANCE_ID="$(terraform output -raw victim_instance_id)"
QUARANTINE_SG="$(terraform output -raw quarantine_sg_id)"
EVIDENCE_BUCKET="$(terraform output -raw evidence_bucket)"

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }
FAILED=0

echo "1. Last execution succeeded"
STATUS="$(aws stepfunctions list-executions \
  --state-machine-arn "$STATE_MACHINE_ARN" --max-results 1 \
  --query 'executions[0].status' --output text)"
[[ "$STATUS" == "SUCCEEDED" ]] && pass "status=$STATUS" || fail "status=$STATUS"

echo "2. Instance is on the quarantine security group"
SGS="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' --output text)"
[[ "$SGS" == *"$QUARANTINE_SG"* ]] && pass "sg=$SGS" || fail "sg=$SGS"

echo "3. Instance is tagged quarantined"
TAG="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].Tags[?Key=='forensics:status'].Value | [0]" --output text)"
[[ "$TAG" == "quarantined" ]] && pass "forensics:status=$TAG" || fail "forensics:status=$TAG"

echo "4. An encrypted evidence snapshot exists"
ENC="$(aws ec2 describe-snapshots --owner-ids self \
  --filters "Name=tag:forensics:instance,Values=$INSTANCE_ID" "Name=tag:forensics:stage,Values=evidence" \
  --query 'Snapshots[?Encrypted==`true`] | length(@)' --output text)"
[[ "$ENC" -ge 1 ]] && pass "encrypted evidence snapshots=$ENC" || fail "encrypted evidence snapshots=$ENC"

echo "5. Unencrypted source snapshots were cleaned up"
SRC="$(aws ec2 describe-snapshots --owner-ids self \
  --filters "Name=tag:forensics:instance,Values=$INSTANCE_ID" "Name=tag:forensics:stage,Values=source" \
  --query 'length(Snapshots)' --output text)"
[[ "$SRC" == "0" ]] && pass "source snapshots remaining=$SRC" || fail "source snapshots remaining=$SRC"

echo "6. The instance role carries the session-revocation policy"
ROLE="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text 2>/dev/null | awk -F/ '{print $NF}')"
if [[ -n "$ROLE" && "$ROLE" != "None" ]]; then
  aws iam get-role-policy --role-name "$ROLE" --policy-name ForensicsRevokeOldSessions >/dev/null 2>&1 \
    && pass "revocation policy attached to $ROLE" || fail "revocation policy missing on $ROLE"
else
  echo "  SKIP  instance has no role"
fi

echo "7. An evidence manifest landed in S3"
OBJS="$(aws s3api list-objects-v2 --bucket "$EVIDENCE_BUCKET" \
  --prefix "evidence/$INSTANCE_ID/" --query 'length(Contents)' --output text 2>/dev/null || echo 0)"
[[ "$OBJS" != "None" && "$OBJS" -ge 1 ]] && pass "evidence objects=$OBJS" || fail "evidence objects=$OBJS"

echo
[[ "$FAILED" == "0" ]] && echo "All checks passed." || { echo "Some checks failed."; exit 1; }
