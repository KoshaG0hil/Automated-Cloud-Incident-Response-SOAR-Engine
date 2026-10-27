# ------------------------------------------------------------------------------
# IAM Execution Role for SOAR Lambda Function
# ------------------------------------------------------------------------------
resource "aws_iam_role" "soar_lambda_role" {
  name = "${local.name_prefix}-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# Fine-Grained Least-Privilege Containment Policy
# ------------------------------------------------------------------------------
resource "aws_iam_policy" "soar_containment_policy" {
  name        = "${local.name_prefix}-containment-permissions"
  description = "Scoped permissions required for automated IAM, EC2, and S3 containment runbooks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      },
      # IAM Containment
      {
        Sid    = "IAMQuarantineActions"
        Effect = "Allow"
        Action = [
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:TagUser"
        ]
        Resource = "*"
      },
      # EC2 Quarantine & Forensics
      {
        Sid    = "EC2IsolationActions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      # S3 Lockdown & Public Access Block
      {
        Sid    = "S3LockdownActions"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:PutBucketTagging"
        ]
        Resource = "*"
      },
      # Evidence Vault Storage
      {
        Sid    = "EvidenceVaultAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.evidence_vault.arn}/*"
      },
      # SNS Notification Dispatch
      {
        Sid    = "SNSAlertDispatch"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.soar_alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "soar_lambda_attach" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.soar_containment_policy.arn
}

# ------------------------------------------------------------------------------
# IAM Execution Role for AWS Step Functions
# ------------------------------------------------------------------------------
resource "aws_iam_role" "soar_sfn_role" {
  name = "${local.name_prefix}-sfn-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "soar_sfn_policy" {
  name        = "${local.name_prefix}-sfn-policy"
  description = "Allows Step Functions to invoke the SOAR Lambda dispatcher and write CloudWatch logs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.soar_engine.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "soar_sfn_attach" {
  role       = aws_iam_role.soar_sfn_role.name
  policy_arn = aws_iam_policy.soar_sfn_policy.arn
}
