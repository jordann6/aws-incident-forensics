# Decoy credential tripwire.
#
# A real access key on a user with zero policies is planted in .aws/credentials
# on the demo victim. Nothing legitimate ever uses it, so the first API call
# signed with it means the file was read off the box. EventBridge matches that
# call from CloudTrail and the tripwire Lambda starts the runbook against the
# instance the key was planted on.
#
# Two choices worth calling out:
#   - The user name looks like a real service account. AccessDenied messages
#     and sts:GetCallerIdentity both echo the user ARN back to the caller, so a
#     name or path containing "decoy" or "honey" tells the attacker it is a trap.
#   - One key per server. The SSM parameter maps key id -> instance id; that
#     mapping is what lets the alert name the box to isolate.

locals {
  decoy_enabled      = var.deploy_victim && var.deploy_decoy
  decoy_param_prefix = "/${var.project}/decoys"
}

resource "aws_iam_user" "decoy" {
  #checkov:skip=CKV_AWS_273:The decoy must be a long-lived IAM user key; that is what attackers expect to find in .aws/credentials. It holds zero permissions.
  count = local.decoy_enabled ? 1 : 0

  name          = var.decoy_user_name
  force_destroy = true
}

# No policy attachments, inline policies, or group memberships, on purpose.
# Every call except sts:GetCallerIdentity returns AccessDenied, and every call
# is still written to CloudTrail.
resource "aws_iam_access_key" "decoy" {
  count = local.decoy_enabled ? 1 : 0

  user = aws_iam_user.decoy[0].name
}

resource "aws_ssm_parameter" "decoy_map" {
  #checkov:skip=CKV2_AWS_34:Holds only an instance id, never the secret.
  count = local.decoy_enabled ? 1 : 0

  name        = "${local.decoy_param_prefix}/${aws_iam_access_key.decoy[0].id}"
  description = "Instance the decoy access key is planted on"
  type        = "String"
  value       = aws_instance.victim[0].id
}

# Read-only calls (GetCallerIdentity, List*, Describe*) are what an attacker
# tries first, and a rule in the plain ENABLED state never sees them. This
# state also needs a CloudTrail trail logging management events in the account.
resource "aws_cloudwatch_event_rule" "decoy_key_used" {
  count = local.decoy_enabled ? 1 : 0

  name        = "${var.project}-decoy-key-used"
  description = "Any API call signed with a planted decoy access key"
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        accessKeyId = [aws_iam_access_key.decoy[0].id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  rule = aws_cloudwatch_event_rule.decoy_key_used[0].name
  arn  = aws_lambda_function.decoy_tripwire[0].arn
}

resource "aws_lambda_permission" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.decoy_tripwire[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.decoy_key_used[0].arn
}

data "archive_file" "decoy_tripwire" {
  type        = "zip"
  output_path = "${path.module}/../build/decoy_tripwire.zip"

  source {
    content  = file("${path.module}/../app/decoy_tripwire.py")
    filename = "decoy_tripwire.py"
  }
}

resource "aws_lambda_function" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  function_name    = "${var.project}-decoy-tripwire"
  description      = "Map a decoy key's CloudTrail event to its instance and start the runbook"
  role             = aws_iam_role.decoy_tripwire[0].arn
  runtime          = local.lambda_runtime
  handler          = "decoy_tripwire.handler"
  filename         = data.archive_file.decoy_tripwire.output_path
  source_code_hash = data.archive_file.decoy_tripwire.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      STATE_MACHINE_ARN  = module.runbook.arn
      ALERTS_TOPIC_ARN   = aws_sns_topic.alerts.arn
      DECOY_PARAM_PREFIX = local.decoy_param_prefix
    }
  }
}

resource "aws_cloudwatch_log_group" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.decoy_tripwire[0].function_name}"
  retention_in_days = 14
}

resource "aws_iam_role" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  name = "${var.project}-decoy-tripwire"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "decoy_tripwire_logs" {
  count = local.decoy_enabled ? 1 : 0

  role       = aws_iam_role.decoy_tripwire[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "decoy_tripwire" {
  count = local.decoy_enabled ? 1 : 0

  name = "decoy-tripwire"
  role = aws_iam_role.decoy_tripwire[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter${local.decoy_param_prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["states:StartExecution"]
        Resource = module.runbook.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
    ]
  })
}
