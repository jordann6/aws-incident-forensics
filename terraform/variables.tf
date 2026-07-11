variable "aws_region" {
  description = "Region for the forensics pipeline and the demo victim"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for every resource"
  type        = string
  default     = "incident-forensics"
}

variable "alert_email" {
  description = "Email address subscribed to the forensics SNS topic"
  type        = string
}

variable "create_guardduty_detector" {
  description = "Create a GuardDuty detector. Set false if the account already has one (one detector per region per account)."
  type        = bool
  default     = true
}

variable "deploy_victim" {
  description = "Deploy the t3.micro demo victim instance and its /forensics-demo/ role"
  type        = bool
  default     = true
}

variable "severity_threshold" {
  description = "Minimum GuardDuty finding severity that triggers the pipeline (7 = High)"
  type        = number
  default     = 7
}

variable "snapshot_poll_max_attempts" {
  description = "Maximum poll cycles (15s each) to wait for snapshots to complete before failing the branch"
  type        = number
  default     = 40
}
