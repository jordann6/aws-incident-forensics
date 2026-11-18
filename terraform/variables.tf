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

variable "deploy_decoy" {
  description = "Plant a decoy access key on the demo victim and alarm on any use of it (needs deploy_victim and a CloudTrail trail logging management events)"
  type        = bool
  default     = true
}

variable "decoy_user_name" {
  description = "Name of the zero-permission decoy IAM user. Keep it believable: AccessDenied errors echo the user ARN to the caller."
  type        = string
  default     = "svc-prod-backup"
}

variable "decoy_profile_name" {
  description = "Profile name the decoy key is written under in .aws/credentials"
  type        = string
  default     = "prod-backup"
}

variable "demo_subnet_cidr" {
  description = "CIDR for the throwaway victim subnet, created only when the default VPC has no subnets"
  type        = string
  default     = "172.31.240.0/24"
}
