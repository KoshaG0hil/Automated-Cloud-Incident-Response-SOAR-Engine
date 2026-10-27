# ------------------------------------------------------------------------------
# Tamper-Evident S3 Forensic Evidence Vault Bucket
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "evidence_vault" {
  bucket        = "${local.name_prefix}-evidence-vault-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "evidence_vault_versioning" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault_encryption" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault_pab" {
  bucket = aws_s3_bucket.evidence_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence_vault_lifecycle" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    id     = "archive-and-expire-evidence"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "evidence_vault_tls_only" {
  bucket = aws_s3_bucket.evidence_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence_vault.arn,
          "${aws_s3_bucket.evidence_vault.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
