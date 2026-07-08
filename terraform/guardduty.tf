# =============================================================================
# GUARDDUTY.TF - Continuous, intelligence-driven threat detection
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# Amazon GuardDuty is a managed threat-detection service. Once turned on, it
# continuously analyzes CloudTrail management events, VPC DNS query logs,
# and (optionally) S3 data events and EKS audit logs, comparing them against
# AWS threat-intelligence feeds and machine-learning models. It does NOT
# require you to write any detection rules yourself - AWS maintains them.
#
# WHY A REAL COMPANY USES THIS:
# - It catches things a human reviewing logs would likely miss: a compromised
#   IAM credential being used from an unusual country, an EC2 instance
#   suddenly querying a known cryptomining domain, or a port scan against
#   the account's public IP ranges.
# - It requires almost no maintenance - there is no rule-writing or log
#   parsing to build, which is why it is one of the first services turned
#   on in almost every AWS security program.
#
# HOW IT IMPROVES SECURITY:
# GuardDuty findings feed directly into Security Hub (enabled in
# securityhub.tf), giving the security team one place to triage every
# threat signal across the account instead of checking multiple consoles.
#
# COMMON MISTAKES TO AVOID:
# - Enabling GuardDuty but never assigning anyone to review its findings -
#   detection without a response process provides little real protection.
# - Forgetting that GuardDuty has a 30-day free trial and then bills based
#   on the volume of CloudTrail events / DNS logs / VPC Flow Logs analyzed.
#   For a low-traffic demo/portfolio account this cost is typically only a
#   few cents to a few dollars a month, but it is not permanently free,
#   unlike some other services in this project.
# - Ignoring low/medium severity findings - some attacks (like slow,
#   deliberate reconnaissance) only ever generate lower-severity findings.
#
# BEST PRACTICES APPLIED HERE:
# - A single regional detector is enabled with 15-minute finding publish
#   frequency (the most frequent option), so alerts reach Security Hub /
#   SNS as fast as possible instead of waiting up to 6 hours.
# =============================================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  # How often GuardDuty exports findings to CloudWatch Events / Security
  # Hub. FIFTEEN_MINUTES is the fastest option, which matters a lot during
  # an active incident. The other choices are ONE_HOUR and SIX_HOURS.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name = "${var.project_name}-guardduty-detector"
  }
}

# -----------------------------------------------------------------------------
# Optional add-on protection plans (NOT enabled by default here to keep
# costs minimal and predictable for a portfolio/demo account). In a real
# enterprise environment, a Security Engineer would typically turn these
# on as the account matures:
#
# resource "aws_guardduty_detector_feature" "s3_protection" {
#   detector_id = aws_guardduty_detector.main.id
#   name        = "S3_DATA_EVENTS"
#   status      = "ENABLED"
# }
#
# resource "aws_guardduty_detector_feature" "malware_protection" {
#   detector_id = aws_guardduty_detector.main.id
#   name        = "EBS_MALWARE_PROTECTION"
#   status      = "ENABLED"
# }
# -----------------------------------------------------------------------------
