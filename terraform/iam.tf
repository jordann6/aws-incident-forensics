# One role per Lambda so each step of the pipeline carries only the
# permissions that step needs. The blast radius of any single function
# compromise is its own narrow slice.

resource "aws_iam_role" "lambda" {
  for_each = local.lambdas

  name = "${var.project}-${replace(each.key, "_", "-")}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  for_each = local.lambdas

  role       = aws_iam_role.lambda[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "extract_context" {
  name = "extract-context"
  role = aws_iam_role.lambda["extract_context"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances"]
      Resource = "*" # Describe* does not support resource-level scoping
    }]
  })
}

resource "aws_iam_role_policy" "isolate_instance" {
  name = "isolate-instance"
  role = aws_iam_role.lambda["isolate_instance"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:CreateTags",
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = local.region }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "snapshot_evidence" {
  name = "snapshot-evidence"
  role = aws_iam_role.lambda["snapshot_evidence"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeVolumes"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = local.region }
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "encrypt_snapshots" {
  name = "encrypt-snapshots"
  role = aws_iam_role.lambda["encrypt_snapshots"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeSnapshots"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CopySnapshot", "ec2:CreateTags"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:RequestedRegion" = local.region }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant",
        ]
        Resource = aws_kms_key.forensics.arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "check_snapshots" {
  name = "check-snapshots"
  role = aws_iam_role.lambda["check_snapshots"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeSnapshots"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "revoke_credentials" {
  name = "revoke-credentials"
  role = aws_iam_role.lambda["revoke_credentials"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # The only mutation this function can perform is attaching the revoke
      # policy to roles under the /forensics-demo/ path. It cannot touch any
      # other role in the account.
      Effect   = "Allow"
      Action   = ["iam:PutRolePolicy", "iam:GetRole"]
      Resource = "arn:aws:iam::${local.account_id}:role${local.demo_role_path}*"
    }]
  })
}

resource "aws_iam_role_policy" "collect_evidence" {
  name = "collect-evidence"
  role = aws_iam_role.lambda["collect_evidence"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:GetConsoleOutput",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:DeleteSnapshot"]
        Resource = "arn:aws:ec2:${local.region}::snapshot/*"
        Condition = {
          # Can only delete the pipeline's own unencrypted staging snapshots
          StringEquals = { "aws:ResourceTag/forensics:stage" = "source" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = aws_kms_key.forensics.arn
      },
    ]
  })
}

# Step Functions execution role: invoke the seven Lambdas, publish to SNS.
resource "aws_iam_role" "sfn" {
  name = "${var.project}-statemachine"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sfn" {
  name = "orchestrate"
  role = aws_iam_role.sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [for k, v in local.lambdas : aws_lambda_function.this[k].arn]
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
    ]
  })
}
