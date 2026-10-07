output "state_machine_arn" {
  value = module.runbook.arn
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "evidence_kms_key_arn" {
  value = aws_kms_key.evidence.arn
}

output "starter_function_name" {
  value = aws_lambda_function.starter.function_name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
