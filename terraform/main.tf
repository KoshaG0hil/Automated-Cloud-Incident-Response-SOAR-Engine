terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Automated-Cloud-Incident-Response-SOAR-Engine"
      ManagedBy   = "Terraform"
      Environment = var.environment
      Repository  = "https://github.com/KoshaG0hil/Automated-Cloud-Incident-Response-SOAR-Engine"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
}

# ------------------------------------------------------------------------------
# Amazon SNS Incident Alert Topic
# ------------------------------------------------------------------------------
resource "aws_sns_topic" "soar_alerts" {
  name              = "${local.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

# ------------------------------------------------------------------------------
# CloudWatch Log Group for Lambda
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.name_prefix}-dispatcher"
  retention_in_days = 90
}

# ------------------------------------------------------------------------------
# Lambda Deployment Archive
# ------------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/soar_lambda_payload.zip"
}

# ------------------------------------------------------------------------------
# SOAR Orchestrator Lambda Function
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "soar_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${local.name_prefix}-dispatcher"
  role             = aws_iam_role.soar_lambda_role.arn
  handler          = "lambda_handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 180
  memory_size      = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SOAR_DRY_RUN       = tostring(var.dry_run_mode)
      EVIDENCE_S3_BUCKET = aws_s3_bucket.evidence_vault.id
      SNS_TOPIC_ARN      = aws_sns_topic.soar_alerts.arn
      SLACK_WEBHOOK_URL  = var.slack_webhook_url
      ENVIRONMENT        = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.soar_lambda_attach
  ]
}

# ------------------------------------------------------------------------------
# AWS Step Functions SOAR State Machine
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "sfn_logs" {
  name              = "/aws/vendedlogs/states/${local.name_prefix}-orchestrator"
  retention_in_days = 90
}

resource "aws_sfn_state_machine" "soar_state_machine" {
  name     = "${local.name_prefix}-orchestrator"
  role_arn = aws_iam_role.soar_sfn_role.arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn_logs.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  definition = jsonencode({
    Comment = "AWS Cloud Incident Response & Threat Hunting SOAR State Machine",
    StartAt = "InvokeSoarLambda",
    States = {
      InvokeSoarLambda = {
        Type       = "Task",
        Resource   = "arn:aws:states:::lambda:invoke",
        OutputPath = "$.Payload",
        Parameters = {
          "Payload.$"    = "$",
          "FunctionName" = aws_lambda_function.soar_engine.arn
        },
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"],
            IntervalSeconds = 2,
            MaxAttempts     = 3,
            BackoffRate     = 2.0
          }
        ],
        Catch = [
          {
            ErrorEquals = ["States.ALL"],
            Next        = "IncidentExecutionFailed"
          }
        ],
        Next = "IncidentSuccessfullyProcessed"
      },
      IncidentSuccessfullyProcessed = {
        Type = "Succeed"
      },
      IncidentExecutionFailed = {
        Type  = "Fail",
        Cause = "SOAR Orchestration execution failed during containment runbook execution.",
        Error = "SoarContainmentError"
      }
    }
  })
}
