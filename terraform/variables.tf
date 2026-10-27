variable "aws_region" {
  description = "The target AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. prod, staging, dev)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project identifier prefix for resource naming"
  type        = string
  default     = "soar-engine"
}

variable "dry_run_mode" {
  description = "If true, simulates containment actions without modifying live AWS resources"
  type        = bool
  default     = false
}

variable "enable_slack_notifications" {
  description = "Flag to enable Slack incident alerting"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Incoming Webhook URL for Slack SecOps channel alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "evidence_retention_days" {
  description = "Number of days to retain forensic evidence reports in S3 before expiration"
  type        = number
  default     = 365
}
