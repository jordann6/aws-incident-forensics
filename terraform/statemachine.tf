module "runbook" {
  source = "./modules/runbook"

  name             = var.project
  role_arn         = aws_iam_role.sfn.arn
  function_arns    = { for k, f in aws_lambda_function.this : k => f.arn }
  alerts_topic_arn = aws_sns_topic.alerts.arn
}

moved {
  from = aws_sfn_state_machine.forensics
  to   = module.runbook.aws_sfn_state_machine.this
}

moved {
  from = aws_cloudwatch_log_group.sfn
  to   = module.runbook.aws_cloudwatch_log_group.this
}
