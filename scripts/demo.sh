#!/usr/bin/env bash
# Inject a synthetic high-severity GuardDuty finding for the demo victim, shaped
# exactly like a real aws.guardduty EC2 finding. The EventBridge rule matches
# source forensics.demo the same way it matches aws.guardduty, so the pipeline
# runs end to end without needing real malicious traffic.
#
# Usage: scripts/demo.sh [instance-id]
#   instance-id defaults to the terraform output victim_instance_id
set -euo pipefail

cd "$(dirname "$0")/../terraform"

INSTANCE_ID="${1:-$(terraform output -raw victim_instance_id)}"

if [[ -z "$INSTANCE_ID" ]]; then
  echo "No instance id. Deploy with deploy_victim = true or pass one explicitly." >&2
  exit 1
fi

STATE_MACHINE_ARN="$(terraform output -raw state_machine_arn)"

echo "Injecting synthetic GuardDuty finding for ${INSTANCE_ID}..."

# The detail mirrors the GuardDuty finding schema: severity 8 (High), an EC2
# resource with instanceDetails.instanceId, and a credential-exfil finding type.
# Build the whole put-events payload as a file so the AWS CLI parses the JSON,
# rather than hand-escaping nested quotes in shell.
ENTRIES_FILE="$(mktemp)"
trap 'rm -f "$ENTRIES_FILE"' EXIT

DETAIL=$(cat <<JSON
{
  "schemaVersion": "2.0",
  "type": "UnauthorizedAccess:EC2/MetadataDNSRebind",
  "severity": 8,
  "resource": {
    "resourceType": "Instance",
    "instanceDetails": { "instanceId": "${INSTANCE_ID}" }
  },
  "service": { "action": { "actionType": "AWS_API_CALL" } }
}
JSON
)

# jq -Rs turns the detail document into a single JSON string value, which is the
# shape EventBridge expects for the Detail field.
jq -n --arg detail "$DETAIL" '
  [ { Source: "forensics.demo",
      DetailType: "GuardDuty Finding",
      Detail: $detail } ]' > "$ENTRIES_FILE"

aws events put-events --entries "file://${ENTRIES_FILE}"

echo
echo "Finding injected. Watch the state machine execution:"
echo "  aws stepfunctions list-executions --state-machine-arn ${STATE_MACHINE_ARN} --max-results 1"
