# Customer-managed KMS key for audit logs
#
# Encrypts CloudTrail logs, AWS Config deliveries, and the CloudTrail
# CloudWatch Logs group with a key this account controls, so reading
# them requires both storage and KMS permissions. Rotated automatically.
#
# ARNs are built with the current partition, so the same code works in
# commercial Regions ("aws") and GovCloud ("aws-us-gov").

data "aws_partition" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "baseline-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"

  # Built by hand, not from the log group resource: the log group needs
  # this key first, so referencing it here would create a cycle.
  cloudtrail_log_group_name = "/aws/cloudtrail/${local.trail_name}"
  cloudtrail_log_group_arn  = "arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:${local.cloudtrail_log_group_name}"
}

# SC-12, SC-13: a customer-managed key with automatic yearly rotation.
resource "aws_kms_key" "audit_logs" {
  description             = "Encrypts CloudTrail, AWS Config, and CloudWatch Logs audit data"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncryptLogs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*" }
        }
      },
      {
        Sid       = "AllowCloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
      },
      {
        Sid       = "AllowConfigEncryptDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "AllowCloudWatchLogsEncryptCloudTrail"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = local.cloudtrail_log_group_arn }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "audit_logs" {
  name          = "alias/audit-logs"
  target_key_id = aws_kms_key.audit_logs.key_id
}