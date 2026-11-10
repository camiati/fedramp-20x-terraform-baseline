# Alerting on CloudTrail events
#
# Metric filters watch the CloudTrail log group (cloudwatch.tf) for the
# 14 events in the CIS AWS Foundations Benchmark monitoring section.
# Each match raises an alarm that publishes to an encrypted SNS topic.
#
# No subscriptions are defined here. Who gets paged (email, chat, or an
# incident tool) is a deployment decision and isn't kept in public code.

# SC-12, SC-13: a separate key for alerts, so the CloudWatch alarm
# service never gets access to the audit log key.
resource "aws_kms_key" "alerts" {
  description             = "Encrypts the security alerts SNS topic"
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
        Sid       = "AllowCloudWatchPublishEncrypted"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/security-alerts"
  target_key_id = aws_kms_key.alerts.key_id
}

# SI-4, SC-28: an encrypted topic that receives every security alarm.
resource "aws_sns_topic" "alerts" {
  name              = "security-alerts"
  kms_master_key_id = aws_kms_key.alerts.arn
}

# AC-6: only this account's CloudWatch alarms can publish to the topic.
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:cloudwatch:${var.region}:${local.account_id}:alarm:*" }
      }
    }]
  })
}

locals {
  # CIS AWS Foundations Benchmark, monitoring section.
  cis_alarms = {
    root-account-usage = {
      description = "The root account was used."
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    unauthorized-api-calls = {
      description = "An API call was denied for lack of permission."
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }
    console-signin-without-mfa = {
      description = "An IAM user signed in to the console without MFA."
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
    console-signin-failures = {
      description = "A console sign-in failed."
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    iam-policy-changes = {
      description = "An IAM policy was created, changed, attached, or deleted."
      pattern     = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    }
    cloudtrail-changes = {
      description = "A CloudTrail trail was created, changed, stopped, or deleted."
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    config-changes = {
      description = "AWS Config recording or delivery was changed or stopped."
      pattern     = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    kms-key-disable-or-deletion = {
      description = "A customer-managed KMS key was disabled or scheduled for deletion."
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    s3-bucket-policy-changes = {
      description = "An S3 bucket's ACL, policy, CORS, lifecycle, or replication was changed."
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    security-group-changes = {
      description = "A security group or its rules were changed."
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    network-acl-changes = {
      description = "A network ACL or its entries were changed."
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    network-gateway-changes = {
      description = "An internet or customer gateway was changed."
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    route-table-changes = {
      description = "A route table or route was changed."
      pattern     = "{ ($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }"
    }
    vpc-changes = {
      description = "A VPC or VPC peering connection was changed."
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    }
  }
}

# AU-6, SI-4: count each matching CloudTrail event.
resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.cis_alarms

  name           = each.key
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = "CISBenchmark"
    value     = "1"
  }
}

# AU-6, SI-4, IR-4: alarm on any match within 5 minutes.
resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_alarms

  alarm_name          = each.key
  alarm_description   = each.value.description
  namespace           = "CISBenchmark"
  metric_name         = aws_cloudwatch_log_metric_filter.cis[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
