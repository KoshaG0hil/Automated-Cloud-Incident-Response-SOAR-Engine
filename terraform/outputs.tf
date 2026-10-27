output "lambda_function_arn" {
  description = "ARN of the SOAR Dispatcher Lambda function"
  value       = aws_lambda_function.soar_engine.arn
}

output "lambda_function_name" {
  description = "Name of the SOAR Dispatcher Lambda function"
  value       = aws_lambda_function.soar_engine.function_name
}

output "state_machine_arn" {
  description = "ARN of the Step Functions SOAR State Machine"
  value       = aws_sfn_state_machine.soar_state_machine.arn
}

output "evidence_vault_s3_bucket" {
  description = "Name of the S3 forensic evidence vault bucket"
  value       = aws_s3_bucket.evidence_vault.id
}

output "sns_alerts_topic_arn" {
  description = "ARN of the SNS topic for SecOps containment alerts"
  value       = aws_sns_topic.soar_alerts.arn
}

output "guardduty_eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule filtering GuardDuty findings"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "securityhub_eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule filtering Security Hub findings"
  value       = aws_cloudwatch_event_rule.securityhub_findings.arn
}
