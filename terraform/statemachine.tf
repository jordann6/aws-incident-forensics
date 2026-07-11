resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${var.project}"
  retention_in_days = 14
}

# The response runbook, encoded as state. The order is deliberate:
#   1. ExtractContext  - understand the finding, decide whether to act
#   2. Isolate         - contain first, so a live attacker loses the host
#   3. Snapshot        - capture evidence from the now-frozen volumes
#   4. Encrypt (+wait) - re-encrypt copies into the forensics custody domain
#   5. Revoke          - kill credentials the host may have leaked
#   6. Collect         - bundle the evidence, delete unencrypted sources
# Isolation runs before evidence capture on purpose: stopping ongoing damage
# outranks a few seconds of forensic completeness.
resource "aws_sfn_state_machine" "forensics" {
  name     = var.project
  role_arn = aws_iam_role.sfn.arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
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
        Resource   = aws_lambda_function.this["extract_context"].arn
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
        Resource   = aws_lambda_function.this["isolate_instance"].arn
        InputPath  = "$.context"
        ResultPath = "$.isolation"
        Next       = "SnapshotEvidence"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      SnapshotEvidence = {
        Type       = "Task"
        Resource   = aws_lambda_function.this["snapshot_evidence"].arn
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
        Resource   = aws_lambda_function.this["encrypt_snapshots"].arn
        InputPath  = "$.snapshots"
        ResultPath = "$.encrypted"
        Next       = "WaitForSnapshots"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      WaitForSnapshots = {
        Type    = "Wait"
        Seconds = 15
        Next    = "CheckSnapshots"
      }

      CheckSnapshots = {
        Type       = "Task"
        Resource   = aws_lambda_function.this["check_snapshots"].arn
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
        Resource   = aws_lambda_function.this["revoke_credentials"].arn
        InputPath  = "$.context"
        ResultPath = "$.revocation"
        Next       = "CollectEvidence"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "CollectEvidence" }]
      }

      CollectEvidence = {
        Type       = "Task"
        Resource   = aws_lambda_function.this["collect_evidence"].arn
        ResultPath = "$.evidence"
        Next       = "NotifySuccess"
        Retry      = [{ ErrorEquals = ["States.ALL"], MaxAttempts = 2, IntervalSeconds = 5 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "NotifyFailure" }]
      }

      NotifySuccess = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = aws_sns_topic.alerts.arn
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
          TopicArn    = aws_sns_topic.alerts.arn
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
