# =============================================================================
# SNS.TF - Where security alarms actually notify a human
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# Every alarm we build in cloudwatch.tf needs somewhere to send its alert.
# This file creates an SNS (Simple Notification Service) topic - think of it
# as a megaphone that CloudWatch Alarms can 'shout' into - and subscribes
# your email address to that topic, so every alarm becomes an email in
# your inbox.
#
# WHY A REAL COMPANY USES THIS:
# - Detection is worthless if nobody finds out about it. SNS is the
#   standard AWS-native way to turn a CloudWatch Alarm into a real-time
#   notification - email today, and easily extended to SMS, a Slack
#   channel (via Chatbot), or a ticketing system (via Lambda) later.
# - Centralizing all security alerts into one topic makes it easy to add
#   or remove subscribers (a whole on-call team, a Slack webhook, etc.)
#   without touching every individual alarm.
#
# COMMON MISTAKES TO AVOID:
# - Forgetting that SNS email subscriptions require manual confirmation -
#   AWS sends a confirmation link to the address, and no emails are
#   delivered until that link is clicked. Terraform cannot click that link
#   for you.
# - Leaving the topic's access policy wide open (`Principal: "*"`),
#   which would let any AWS account publish fake alerts into your topic.
#
# BEST PRACTICES APPLIED HERE:
# - The topic policy only allows CloudWatch Alarms FROM THIS AWS ACCOUNT
#   to publish - nothing else, and nobody else.
# - Uses SNS's own AWS-managed encryption key (`alias/aws/sns`) so
#   messages are encrypted at rest with zero extra cost or key management
#   overhead - a good default for notification content that is not itself
#   highly sensitive (the alarms describe an event, they don't carry
#   secrets).
# =============================================================================

resource "aws_sns_topic" "security_alerts" {
  name = "${var.project_name}-security-alerts"

  # Encrypts messages at rest using SNS's free, AWS-managed key. There is
  # no need for a customer-managed KMS key here (that would add ~$1/month
  # for very little extra benefit on notification metadata).
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${var.project_name}-security-alerts"
  }
}

# Subscribes your email address to the topic. IMPORTANT: AWS will email
# this address a confirmation link after `terraform apply` runs - no
# alerts are delivered until that link is clicked. This is an AWS safety
# feature to stop people from being signed up for notifications without
# their consent, and it cannot be automated away.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -----------------------------------------------------------------------------
# Topic access policy: explicitly states WHO may publish to this topic.
# Without this, CloudWatch Alarms cannot deliver to the topic at all.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "security_alerts_topic_policy" {
  statement {
    sid    = "AllowCloudWatchAlarmsToPublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts_topic_policy.json
}
