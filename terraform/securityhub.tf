# =============================================================================
# SECURITYHUB.TF - Central findings dashboard and compliance scoring
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# AWS Security Hub is the 'single pane of glass' for security findings. It
# does not generate findings on its own - instead it automatically collects
# and normalizes findings from GuardDuty (guardduty.tf), AWS Config
# (config.tf), Amazon Inspector, and other AWS services into one common
# format, then runs its own automated Security Standards checks on top of
# that (things like 'is S3 block public access turned on account-wide?').
#
# WHY A REAL COMPANY USES THIS:
# - Without Security Hub, an analyst has to log into GuardDuty, Config, and
#   several other consoles separately to get the full security picture.
#   Security Hub aggregates all of it, assigns each account a compliance
#   score, and lets findings be routed to ticketing/SOAR tools.
# - The AWS Foundational Security Best Practices (FSBP) standard we enable
#   below is AWS's own opinionated baseline of ~200 automated checks and is
#   commonly the very first standard turned on in any AWS security program.
#
# HOW IT IMPROVES SECURITY:
# Every GuardDuty finding and every non-compliant AWS Config rule from this
# project automatically shows up in Security Hub within minutes, without
# any extra integration work - Security Hub does this natively once enabled.
#
# COMMON MISTAKES TO AVOID:
# - Enabling Security Hub but never enabling any standard - you get an
#   aggregation dashboard but no automated best-practice checks.
# - Not triaging or suppressing findings that are 'accepted risk' for a
#   given account - Security Hub findings pile up quickly and lose value if
#   nobody ever marks them Resolved/Suppressed.
# - Assuming Security Hub replaces GuardDuty/Config - it is a downstream
#   aggregator, not a replacement for the services that generate findings.
#
# BEST PRACTICES APPLIED HERE:
# - Security Hub is enabled account-wide, then explicitly subscribed to the
#   AWS Foundational Security Best Practices standard so compliance checks
#   start running immediately after apply.
# =============================================================================

data "aws_region" "current" {}

# Turns on Security Hub for this account/region. Must exist before we can
# subscribe to any standard below.
resource "aws_securityhub_account" "main" {}

# Subscribes the account to AWS's own curated set of ~200 automated
# security checks (S3 public access, IAM password policy, EBS encryption,
# root account usage, and more). This is the standard most companies turn
# on first because AWS maintains and updates it directly.
resource "aws_securityhub_standards_subscription" "afsbp" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}
