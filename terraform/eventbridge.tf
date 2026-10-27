# ------------------------------------------------------------------------------
# EventBridge Rule 1: High & Critical Amazon GuardDuty Findings
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.name_prefix}-guardduty-rule"
  description = "Captures GuardDuty security findings with Severity >= 7.0 for automated containment"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7.0] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_target_sfn" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "TriggerSoarStepFunction"
  arn       = aws_sfn_state_machine.soar_state_machine.arn
  role_arn  = aws_iam_role.eventbridge_sfn_role.arn
}

# ------------------------------------------------------------------------------
# EventBridge Rule 2: High & Critical AWS Security Hub Findings
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  name        = "${local.name_prefix}-securityhub-rule"
  description = "Captures AWS Security Hub High and Critical findings for automated containment"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_target_sfn" {
  rule      = aws_cloudwatch_event_rule.securityhub_findings.name
  target_id = "TriggerSoarStepFunctionSecHub"
  arn       = aws_sfn_state_machine.soar_state_machine.arn
  role_arn  = aws_iam_role.eventbridge_sfn_role.arn
}

# ------------------------------------------------------------------------------
# EventBridge Role to Start Step Function Executions
# ------------------------------------------------------------------------------
resource "aws_iam_role" "eventbridge_sfn_role" {
  name = "${local.name_prefix}-eventbridge-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "eventbridge_sfn_policy" {
  name        = "${local.name_prefix}-eventbridge-sfn-policy"
  description = "Permits EventBridge rules to start execution of the SOAR State Machine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["states:StartExecution"]
        Resource = aws_sfn_state_machine.soar_state_machine.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eventbridge_sfn_attach" {
  role       = aws_iam_role.eventbridge_sfn_role.name
  policy_arn = aws_iam_policy.eventbridge_sfn_policy.arn
}
