output "state_machine_arn" {
  description = "Forensics Step Functions state machine"
  value       = aws_sfn_state_machine.forensics.arn
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
