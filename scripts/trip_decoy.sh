#!/usr/bin/env bash
# Play the attacker: use the decoy key the way an intruder would right after
# reading .aws/credentials off the victim, then time how long the tripwire takes
# to start the runbook and finish containment.
#
# Usage: scripts/trip_decoy.sh
#
# Nothing here touches a real credential. The decoy user has zero policies, so
# the only call that succeeds is sts:GetCallerIdentity, which needs none.
set -euo pipefail

cd "$(dirname "$0")/../terraform"

KEY_ID="$(terraform output -raw decoy_access_key_id)"
SECRET="$(terraform output -raw decoy_secret_access_key)"
INSTANCE_ID="$(terraform output -raw victim_instance_id)"
STATE_MACHINE_ARN="$(terraform output -raw state_machine_arn)"
REGION="$(terraform output -raw aws_region 2>/dev/null || aws configure get region || echo us-east-1)"

if [[ -z "$KEY_ID" || -z "$INSTANCE_ID" ]]; then
  echo "No decoy deployed. Apply with deploy_victim = true and deploy_decoy = true." >&2
  exit 1
fi

CREDS_FILE="$(mktemp)"
trap 'rm -f "$CREDS_FILE"' EXIT
printf '[attacker]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$KEY_ID" "$SECRET" > "$CREDS_FILE"

attacker() {
  AWS_SHARED_CREDENTIALS_FILE="$CREDS_FILE" AWS_CONFIG_FILE=/dev/null \
    aws --profile attacker --region "$REGION" "$@"
}

START=$(date +%s)
echo "[$(date -u +%H:%M:%S)] attacker: sts get-caller-identity"
attacker sts get-caller-identity --output json | jq -r '"  -> " + .Arn'
echo "[$(date -u +%H:%M:%S)] attacker: s3 ls (expected AccessDenied)"
attacker s3 ls 2>&1 | sed 's/^/  -> /' || true

NAME="decoy-${INSTANCE_ID}-$(date -u +%Y%m%d)"
EXEC_ARN="${STATE_MACHINE_ARN/:stateMachine:/:execution:}:${NAME}"
echo
echo "Waiting for runbook execution ${NAME} (CloudTrail to EventBridge is usually a few minutes)..."

until STATUS=$(aws stepfunctions describe-execution --execution-arn "$EXEC_ARN" \
    --query status --output text 2>/dev/null); do
  if (( $(date +%s) - START > 1200 )); then
    echo "No execution after 20 minutes. Check the trail logs management events (read and write)." >&2
    exit 1
  fi
  sleep 10
done
echo "[$(date -u +%H:%M:%S)] runbook started $(( $(date +%s) - START ))s after first decoy call"

while [[ "$STATUS" == "RUNNING" ]]; do
  sleep 10
  STATUS=$(aws stepfunctions describe-execution --execution-arn "$EXEC_ARN" --query status --output text)
done
echo "[$(date -u +%H:%M:%S)] runbook ${STATUS} $(( $(date +%s) - START ))s after first decoy call"
