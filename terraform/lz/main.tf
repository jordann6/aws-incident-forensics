# The forensics runbook as a landing zone control. It runs in the security
# account, starts from the LZ's security-findings topic, and acts on a workload
# account only through that account's per-step target roles. The pipeline holds
# no EC2 or IAM permissions of its own in any workload account.

locals {
  account_id = data.aws_caller_identity.current.account_id

  steps = {
    extract_context    = "Parse the finding, resolve the instance, decide if the pipeline should act"
    isolate_instance   = "Swap every ENI onto the VPC's quarantine group and tag the instance"
    snapshot_evidence  = "Create source snapshots of every attached EBS volume"
    encrypt_snapshots  = "Copy completed snapshots re-encrypted with the forensics CMK"
    check_snapshots    = "Poll snapshot state for the Step Functions wait loop"
    revoke_credentials = "Attach a deny-all policy that revokes sessions issued before now"
    collect_evidence   = "Assemble the evidence bundle, write it to S3, delete unencrypted sources"
  }

  dash = { for k in keys(local.steps) : k => replace(k, "_", "-") }

  # Per step: account id -> that step's target role in the account.
  step_targets = {
    for k in keys(local.steps) : k => {
      for acct, roles in var.target_role_arns : acct => roles[local.dash[k]]
    }
  }

  encrypt_target_arns = values(local.step_targets["encrypt_snapshots"])
}

# --- evidence custody: key and bucket ------------------------------------------

data "aws_iam_policy_document" "evidence_key" {
  #checkov:skip=CKV_AWS_356:KMS key policies scope by principal/condition; Resource "*" means "this key".
  #checkov:skip=CKV_AWS_111:The root kms:* statement is the standard key-admin anchor so the key is never orphaned.
  #checkov:skip=CKV_AWS_109:Use is limited to named pipeline roles and conditioned workload target roles.
  statement {
    sid       = "AccountRootAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # The evidence writer in this account.
  statement {
    sid       = "EvidenceWriter"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.step["collect_evidence"].arn]
    }
  }

  # The snapshot copy runs in the workload account (CopySnapshot keeps the copy
  # where the source is), so the encrypt step's target role there uses this key.
  # Account root plus a PrincipalArn condition keeps the policy valid even if a
  # target role is recreated.
  dynamic "statement" {
    for_each = length(local.encrypt_target_arns) == 0 ? [] : [1]
    content {
      sid = "WorkloadSnapshotCopy"
      actions = [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = [for acct in keys(var.target_role_arns) : "arn:aws:iam::${acct}:root"]
      }
      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = local.encrypt_target_arns
      }
    }
  }

  dynamic "statement" {
    for_each = length(local.encrypt_target_arns) == 0 ? [] : [1]
    content {
      sid       = "WorkloadSnapshotCopyGrants"
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = [for acct in keys(var.target_role_arns) : "arn:aws:iam::${acct}:root"]
      }
      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = local.encrypt_target_arns
      }
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "Forensics evidence: encrypted snapshot copies and the evidence bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.evidence_key.json
}

# The LZ target role matches this alias (kms:ResourceAliases), so keep it fixed.
resource "aws_kms_alias" "evidence" {
  name          = "alias/${var.name}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_144:Single-region evidence store; cross-region replication is out of scope.
  #checkov:skip=CKV_AWS_18:Access logging would need a second bucket; CloudTrail data events cover reads if enabled.
  #checkov:skip=CKV2_AWS_62:No consumer for object-created events.
  bucket = "${var.name}-evidence-${local.account_id}"
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyUnencryptedWrites"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      },
    ]
  })
}

# --- runbook notices -----------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
