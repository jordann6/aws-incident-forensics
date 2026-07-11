data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # IAM path that scopes which roles the revocation Lambda may touch.
  # Only roles under /forensics-demo/ can ever receive the deny policy.
  demo_role_path = "/forensics-demo/"

  lambda_runtime = "python3.12"

  lambdas = {
    extract_context    = "Parse the finding, resolve the instance, decide if the pipeline should act"
    isolate_instance   = "Swap every ENI onto the quarantine security group and tag the instance"
    snapshot_evidence  = "Create source snapshots of every attached EBS volume"
    encrypt_snapshots  = "Copy completed snapshots re-encrypted with the forensics CMK"
    check_snapshots    = "Poll snapshot state for the Step Functions wait loop"
    revoke_credentials = "Attach a deny-all policy that revokes sessions issued before now"
    collect_evidence   = "Assemble the evidence bundle, write it to S3, delete unencrypted sources"
  }
}
