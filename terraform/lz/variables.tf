# Every value without a default comes from the gitignored lz.tfvars.json that
# the landing zone writes (scripts/export-incident-inputs.py in aws-landing-zone).

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Name prefix; the LZ target roles trust <name>-<step> by exact ARN"
  type        = string
  default     = "incident-forensics-lz"
}

variable "deploy_role_arn" {
  description = "Security-account role Terraform deploys through"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/OrganizationAccountAccessRole$", var.deploy_role_arn))
    error_message = "Expected the security account's OrganizationAccountAccessRole."
  }
}

variable "target_role_arns" {
  description = "Workload account id -> { step -> target role ARN } (from the LZ incident/ root)"
  type        = map(map(string))
}

variable "findings_topic_arn" {
  description = "LZ security-findings topic (observability root) the starter subscribes to"
  type        = string
}

variable "alert_email" {
  description = "Optional email for [CONTAINED] / [FAILED] runbook notices"
  type        = string
  default     = null
}

variable "snapshot_poll_max_attempts" {
  type    = number
  default = 40
}
