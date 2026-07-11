# Forensics CMK: a separate custody domain for evidence. Snapshot copies and
# the evidence bucket are encrypted with this key, so access to evidence is
# governed by this key policy, not by whatever encrypted the victim's volumes.
resource "aws_kms_key" "forensics" {
  description             = "Forensics evidence key: encrypted snapshot copies and the evidence bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "PipelineUse"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.lambda["encrypt_snapshots"].arn,
            aws_iam_role.lambda["collect_evidence"].arn,
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
      {
        # CopySnapshot with a CMK needs a grant so EBS can use the key on
        # the pipeline's behalf. Grants are constrained to AWS resources.
        Sid    = "PipelineGrants"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda["encrypt_snapshots"].arn
        }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
        ]
        Resource = "*"
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "forensics" {
  name          = "alias/${var.project}-evidence"
  target_key_id = aws_kms_key.forensics.key_id
}
