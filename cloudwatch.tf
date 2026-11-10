# CloudWatch Logs for CloudTrail
#
# Streams CloudTrail events into CloudWatch Logs so metric filters and
# alarms can act on them within minutes. The copy in the evidence
# bucket stays the long-term record; this is the real-time copy.

# AU-6, AU-11, SC-28: keep CloudTrail events searchable for a year,
# encrypted with the audit log key.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.cloudtrail_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit_logs.arn
}

# AC-6: the role CloudTrail assumes to deliver events. Only the
# baseline trail can assume it.
resource "aws_iam_role" "cloudtrail_logs" {
  name = "cloudtrail-cloudwatch-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    }]
  })
}

# AC-6: write to this one log group and nothing else.
resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "write-cloudtrail-log-group"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"
    }]
  })
}
