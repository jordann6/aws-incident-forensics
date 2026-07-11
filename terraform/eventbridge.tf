# Two sources match deliberately:
#   aws.guardduty     - real and sample GuardDuty findings
#   forensics.demo    - synthetic findings injected by scripts/demo.sh, shaped
#                       exactly like the real event so the pipeline cannot
#                       tell the difference (real findings on demand would
#                       require actual malicious traffic)
resource "aws_cloudwatch_event_rule" "guardduty_ec2_high" {
  name        = "${var.project}-guardduty-ec2-high"
  description = "High-severity GuardDuty findings against EC2 instances"

  event_pattern = jsonencode({
    source      = ["aws.guardduty", "forensics.demo"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.severity_threshold] }]
      resource = {
        resourceType = ["Instance"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "start_forensics" {
  rule     = aws_cloudwatch_event_rule.guardduty_ec2_high.name
  arn      = aws_sfn_state_machine.forensics.arn
  role_arn = aws_iam_role.eventbridge_invoke.arn
}

resource "aws_iam_role" "eventbridge_invoke" {
  name = "${var.project}-eventbridge-invoke"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_invoke" {
  name = "start-state-machine"
  role = aws_iam_role.eventbridge_invoke.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.forensics.arn
    }]
  })
}
