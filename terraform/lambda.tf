data "archive_file" "lambda" {
  for_each = local.lambdas

  type        = "zip"
  source_file = "${path.module}/../app/${each.key}.py"
  output_path = "${path.module}/../build/${each.key}.zip"
}

resource "aws_lambda_function" "this" {
  for_each = local.lambdas

  function_name    = "${var.project}-${replace(each.key, "_", "-")}"
  description      = each.value
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = local.lambda_runtime
  handler          = "${each.key}.handler"
  filename         = data.archive_file.lambda[each.key].output_path
  source_code_hash = data.archive_file.lambda[each.key].output_base64sha256
  timeout          = 120
  memory_size      = 128

  environment {
    variables = {
      QUARANTINE_SG_ID  = aws_security_group.quarantine.id
      FORENSICS_KMS_ARN = aws_kms_key.forensics.arn
      EVIDENCE_BUCKET   = aws_s3_bucket.evidence.id
      DEMO_ROLE_PATH    = local.demo_role_path
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each = local.lambdas

  name              = "/aws/lambda/${aws_lambda_function.this[each.key].function_name}"
  retention_in_days = 14
}
