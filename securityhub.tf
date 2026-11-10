# Security Hub CSPM
#
# Checks the account's resources against the NIST SP 800-53 Rev. 5
# standard and collects findings from other services, such as
# GuardDuty, in one place. The checks run on AWS Config data, so
# Config must be recording first.

# CA-7, SI-4: turn on Security Hub as the central place for findings.
# Only the standard chosen below is enabled, not the AWS defaults.
resource "aws_securityhub_account" "baseline" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

# CA-2, CA-7, CM-6: continuously assess resource configuration against
# the NIST SP 800-53 Rev. 5 standard.
resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:${local.partition}:securityhub:${var.region}::standards/nist-800-53/v/5.0.0"

  depends_on = [
    aws_securityhub_account.baseline,
    aws_config_configuration_recorder_status.baseline,
  ]
}
