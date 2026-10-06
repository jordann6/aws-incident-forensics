# One function and one role per step, as in the standalone project. Here a role
# can do exactly one thing in a workload account: assume its own target role
# there. The collect step also writes the manifest to the evidence bucket.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "step" {
  for_each = local.steps

  # Exact name the LZ target roles trust: <name>-<step-with-dashes>.
  name               = "${var.name}-${local.dash[each.key]}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "step_logs" {
  for_each = local.steps

  role       = aws_iam_role.step[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "step_assume_target" {
  for_each = local.steps

  name = "assume-workload-target"
  role = aws_iam_role.step[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeOwnTargetRoles"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = values(local.step_targets[each.key])
    }]
  })
}

resource "aws_iam_role_policy" "collect_evidence_bucket" {
  name = "write-evidence"
  role = aws_iam_role.step["collect_evidence"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = aws_kms_key.evidence.arn
      },
    ]
  })
}

data "archive_file" "step" {
  for_each = local.steps

  type        = "zip"
  output_path = "${path.module}/../../build/lz-${each.key}.zip"

  source {
    content  = file("${path.module}/../../app/${each.key}.py")
    filename = "${each.key}.py"
  }

  source {
    content  = file("${path.module}/../../app/target.py")
    filename = "target.py"
  }
}

resource "aws_lambda_function" "step" {
  #checkov:skip=CKV_AWS_116:Invoked synchronously by Step Functions, whose retries and catch handle failure.
  #checkov:skip=CKV_AWS_117:Calls only AWS APIs; no VPC resources to reach.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for this portfolio stack.
  #checkov:skip=CKV_AWS_173:Environment holds role ARNs and names only, no secrets.
  #checkov:skip=CKV_AWS_115:Concurrency is bounded by the state machine's executions.
  #checkov:skip=CKV_AWS_50:X-Ray is enabled on the state machine; per-function tracing adds little.
  for_each = local.steps

  function_name    = "${var.name}-${local.dash[each.key]}"
  description      = each.value
  role             = aws_iam_role.step[each.key].arn
  runtime          = "python3.12"
  handler          = "${each.key}.handler"
  filename         = data.archive_file.step[each.key].output_path
  source_code_hash = data.archive_file.step[each.key].output_base64sha256
  timeout          = 120
  memory_size      = 128

  environment {
    variables = {
      TARGET_ROLES               = jsonencode(local.step_targets[each.key])
      FORENSICS_KMS_ARN          = aws_kms_key.evidence.arn
      EVIDENCE_BUCKET            = aws_s3_bucket.evidence.id
      REVOCABLE_ROLE_PATH        = "/lz-compute/"
      SNAPSHOT_POLL_MAX_ATTEMPTS = tostring(var.snapshot_poll_max_attempts)
    }
  }
}

resource "aws_cloudwatch_log_group" "step" {
  #checkov:skip=CKV_AWS_158:Function logs carry no secrets; the default CloudWatch encryption applies.
  #checkov:skip=CKV_AWS_338:Fourteen days covers an investigation window; evidence itself lives in S3.
  for_each = local.steps

  name              = "/aws/lambda/${aws_lambda_function.step[each.key].function_name}"
  retention_in_days = 14
}

# --- the state machine ---------------------------------------------------------

data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.name}-statemachine"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

resource "aws_iam_role_policy" "sfn" {
  #checkov:skip=CKV_AWS_290:CloudWatch Logs delivery and X-Ray actions do not support resource-level scoping.
  #checkov:skip=CKV_AWS_355:Same: log delivery and X-Ray require Resource "*".
  name = "orchestrate"
  role = aws_iam_role.sfn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [for f in aws_lambda_function.step : f.arn]
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        # Vended log delivery and tracing, required for logging_configuration.
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
          "xray:PutTraceSegments", "xray:PutTelemetryRecords",
          "xray:GetSamplingRules", "xray:GetSamplingTargets",
        ]
        Resource = "*"
      },
    ]
  })
}

module "runbook" {
  source = "../modules/runbook"

  name             = var.name
  role_arn         = aws_iam_role.sfn.arn
  function_arns    = { for k, f in aws_lambda_function.step : k => f.arn }
  alerts_topic_arn = aws_sns_topic.alerts.arn

  depends_on = [aws_iam_role_policy.sfn]
}

# --- the starter: security-findings topic -> runbook ---------------------------

resource "aws_iam_role" "starter" {
  name               = "${var.name}-starter"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "starter_logs" {
  role       = aws_iam_role.starter.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "starter" {
  name = "start-runbook"
  role = aws_iam_role.starter.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = module.runbook.arn
    }]
  })
}

data "archive_file" "starter" {
  type        = "zip"
  source_file = "${path.module}/../../app/start_from_sns.py"
  output_path = "${path.module}/../../build/lz-start_from_sns.zip"
}

resource "aws_lambda_function" "starter" {
  #checkov:skip=CKV_AWS_116:SNS retries Lambda delivery; a failed start is visible in the function's errors.
  #checkov:skip=CKV_AWS_117:Calls only the Step Functions API; no VPC resources to reach.
  #checkov:skip=CKV_AWS_272:Code signing is out of scope for this portfolio stack.
  #checkov:skip=CKV_AWS_173:Environment holds the state machine ARN only.
  #checkov:skip=CKV_AWS_115:Finding volume is low; reserved concurrency would only add a failure mode.
  #checkov:skip=CKV_AWS_50:X-Ray is enabled on the state machine.
  function_name    = "${var.name}-starter"
  description      = "Start the forensics runbook for GuardDuty instance findings on the LZ findings topic"
  role             = aws_iam_role.starter.arn
  runtime          = "python3.12"
  handler          = "start_from_sns.handler"
  filename         = data.archive_file.starter.output_path
  source_code_hash = data.archive_file.starter.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      STATE_MACHINE_ARN = module.runbook.arn
    }
  }
}

resource "aws_cloudwatch_log_group" "starter" {
  #checkov:skip=CKV_AWS_158:Function logs carry no secrets; the default CloudWatch encryption applies.
  #checkov:skip=CKV_AWS_338:Fourteen days covers an investigation window.
  name              = "/aws/lambda/${aws_lambda_function.starter.function_name}"
  retention_in_days = 14
}

resource "aws_lambda_permission" "findings_topic" {
  statement_id  = "AllowSecurityFindingsTopic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.starter.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.findings_topic_arn
}

resource "aws_sns_topic_subscription" "findings" {
  topic_arn = var.findings_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.starter.arn

  depends_on = [aws_lambda_permission.findings_topic]
}
