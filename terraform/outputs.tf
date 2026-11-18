output "state_machine_arn" {
  description = "Forensics Step Functions state machine"
  value       = module.runbook.arn
}

output "evidence_bucket" {
  description = "Bucket where evidence bundles land"
  value       = aws_s3_bucket.evidence.id
}

output "quarantine_sg_id" {
  description = "Security group used to isolate instances"
  value       = aws_security_group.quarantine.id
}

output "forensics_kms_arn" {
  description = "CMK used to re-encrypt snapshot copies and the evidence bucket"
  value       = aws_kms_key.forensics.arn
}

output "victim_instance_id" {
  description = "Demo victim instance id (empty when deploy_victim = false)"
  value       = var.deploy_victim ? aws_instance.victim[0].id : ""
}

output "event_bus_name" {
  description = "Event bus the demo script targets when injecting a synthetic finding"
  value       = "default"
}

output "decoy_access_key_id" {
  description = "Decoy access key id planted on the victim (empty when the decoy is off)"
  value       = local.decoy_enabled ? aws_iam_access_key.decoy[0].id : ""
}

output "decoy_secret_access_key" {
  description = "Decoy secret, only for scripts/trip_decoy.sh to play the attacker. Zero permissions."
  value       = local.decoy_enabled ? aws_iam_access_key.decoy[0].secret : ""
  sensitive   = true
}

output "aws_region" {
  description = "Region the pipeline and victim run in"
  value       = var.aws_region
}

output "decoy_user_name" {
  description = "Zero-permission IAM user that owns the decoy key"
  value       = local.decoy_enabled ? aws_iam_user.decoy[0].name : ""
}
