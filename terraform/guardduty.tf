# One detector per region per account. If GuardDuty is already enabled,
# set create_guardduty_detector = false; findings from the existing detector
# flow through the same EventBridge rule either way.
resource "aws_guardduty_detector" "this" {
  count = var.create_guardduty_detector ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
