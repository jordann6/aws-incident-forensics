# The response runbook, encoded as state, shared by the standalone root and the
# landing zone root. The order is deliberate:
#   1. ExtractContext  - understand the finding, decide whether to act
#   2. Isolate         - contain first, so a live attacker loses the host
#   3. Snapshot        - capture evidence from the now-frozen volumes
#   4. Encrypt (+wait) - re-encrypt copies into the forensics custody domain
#   5. Revoke          - kill credentials the host may have leaked
#   6. Collect         - bundle the evidence, delete unencrypted sources
# Isolation runs before evidence capture on purpose: stopping ongoing damage
# outranks a few seconds of forensic completeness.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "name" {
  type = string
}

variable "role_arn" {
  description = "Step Functions execution role (invoke the step functions, publish alerts)"
  type        = string
}

variable "function_arns" {
  description = "Lambda ARN per step: extract_context, isolate_instance, snapshot_evidence, encrypt_snapshots, check_snapshots, revoke_credentials, collect_evidence"
  type        = map(string)
}

variable "alerts_topic_arn" {
  type = string
}

resource "aws_cloudwatch_log_group" "this" {
  #checkov:skip=CKV_AWS_158:Execution logs carry no secrets; the default CloudWatch encryption applies.
  #checkov:skip=CKV_AWS_338:Fourteen days covers an investigation window; evidence itself lives in S3.
  name              = "/aws/vendedlogs/states/${var.name}"
  retention_in_days = 14
}

resource "aws_sfn_state_machine" "this" {
  name     = var.name
  role_arn = var.role_arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.this.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  definition = jsonencode({
    Comment = "GuardDuty-triggered EC2 isolation, evidence capture, and credential revocation"
    StartAt = "ExtractContext"
    States = {
      ExtractContext = {
        Type       = "Task"
        Resource   = var.function_arns["extract_context"]
        ResultPath = "$.context"
        Next       = "ShouldRespond"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 3 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      ShouldRespond = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.context.should_respond"
          BooleanEquals = true
          Next          = "IsolateInstance"
        }]
        Default = "NoActionNeeded"
      }

      NoActionNeeded = {
        Type = "Succeed"
      }

      IsolateInstance = {
        Type       = "Task"
        Resource   = var.function_arns["isolate_instance"]
        InputPath  = "$.context"
        ResultPath = "$.isolation"
        Next       = "SnapshotEvidence"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      SnapshotEvidence = {
        Type       = "Task"
        Resource   = var.function_arns["snapshot_evidence"]
        InputPath  = "$.context"
        ResultPath = "$.snapshots"
        Next       = "EncryptSnapshots"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      # Copy each source snapshot re-encrypted with the forensics CMK. Returns
      # the copy ids we then poll for completion.
      EncryptSnapshots = {
        Type       = "Task"
        Resource   = var.function_arns["encrypt_snapshots"]
        InputPath  = "$.snapshots"
        ResultPath = "$.encrypted"
        Next       = "WaitForSnapshots"
        Retry = [
          # CopySnapshot needs completed sources; wait up to ~15 min for them.
          { ErrorEquals = ["SnapshotNotReady"], MaxAttempts = 45, IntervalSeconds = 20, BackoffRate = 1 },
          { ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 },
        ]
        Catch = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      WaitForSnapshots = {
        Type    = "Wait"
        Seconds = 15
        Next    = "CheckSnapshots"
      }

      CheckSnapshots = {
        Type       = "Task"
        Resource   = var.function_arns["check_snapshots"]
        InputPath  = "$.encrypted"
        ResultPath = "$.encrypted"
        Next       = "SnapshotsComplete"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 3, IntervalSeconds = 10 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      # Poll loop: the copies are done when every one reports completed. A
      # bounded attempt counter (enforced in check_snapshots) trips the
      # TooManyAttempts error rather than looping forever.
      SnapshotsComplete = {
        Type = "Choice"
        Choices = [
          {
            Variable      = "$.encrypted.all_complete"
            BooleanEquals = true
            Next          = "RevokeCredentials"
          },
          {
            Variable      = "$.encrypted.exhausted"
            BooleanEquals = true
            Next          = "NotifyFailure"
          },
        ]
        Default = "WaitForSnapshots"
      }

      RevokeCredentials = {
        Type       = "Task"
        Resource   = var.function_arns["revoke_credentials"]
        InputPath  = "$.context"
        ResultPath = "$.revocation"
        Next       = "CollectEvidence"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "CollectEvidence" }]
      }

      CollectEvidence = {
        Type       = "Task"
        Resource   = var.function_arns["collect_evidence"]
        ResultPath = "$.evidence"
        Next       = "NotifySuccess"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      NotifySuccess = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = var.alerts_topic_arn
          "Subject.$" = "States.Format('[CONTAINED] {} isolated and captured', $.context.instance_id)"
          "Message.$" = "States.JsonToString($)"
        }
        End = true
      }

      # Static subject on purpose: this state is reachable from ExtractContext's
      # own catch, before $.context exists, so it must not reference it. The
      # full state (including the instance id when present) rides in the body.
      NotifyFailure = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = var.alerts_topic_arn
          Subject     = "[FAILED] aws-incident-forensics pipeline error"
          "Message.$" = "States.JsonToString($)"
        }
        Next = "FailState"
      }

      FailState = {
        Type  = "Fail"
        Error = "ForensicsPipelineFailed"
      }
    }
  })
}

output "arn" {
  value = aws_sfn_state_machine.this.arn
}
