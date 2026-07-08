# =============================================================================
# CLOUDWATCH.TF - Turning raw CloudTrail logs into real-time alarms
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# Stage 3 sent CloudTrail logs to S3 for durable, long-term storage. S3 is
# great for storage but is not designed for real-time searching or
# alerting. This file ALSO streams the same CloudTrail events into a
# CloudWatch Logs group, where we can define 'Metric Filters' - small
# search patterns that turn matching log lines into a number (a metric) -
# and then put a CloudWatch Alarm on that number. When the alarm fires, it
# publishes to the SNS topic from sns.tf, which emails you.
#
# WHY A REAL COMPANY USES THIS:
# - This is the exact same pattern recommended by the CIS AWS Foundations
#   Benchmark for account-level security monitoring, and is one of the
#   most commonly asked-about patterns in cloud security interviews.
# - It turns 'someone would have to go looking for this in the logs' into
#   'I get an email within minutes of this happening'.
#
# HOW IT IMPROVES SECURITY:
# Each metric filter below maps to one of this project's alert scenarios:
# root account usage, failed console logins, IAM policy changes, security
# group changes, CloudTrail being stopped/modified, and unauthorized API
# calls - see docs/cloudwatch.md for the full detect/investigate/remediate
# walkthrough of each one.
#
# COMMON MISTAKES TO AVOID:
# - Setting log retention to 'Never expire', which slowly increases cost
#   forever. We set an explicit retention period instead.
# - Writing a metric filter pattern that is too broad (matching far more
#   than intended) or too narrow (missing real matches) - the patterns
#   below are adapted from AWS's own published CIS benchmark guidance.
# - Forgetting `treat_missing_data = "notBreaching"` on security alarms -
#   without it, an alarm can flip to INSUFFICIENT_DATA and stop alerting
#   simply because no matching events occurred (which is the GOOD outcome).
#
# BEST PRACTICES APPLIED HERE:
# - 90-day CloudWatch Logs retention balances investigation usefulness
#   against storage cost (S3, via CloudTrail, still keeps the full history
#   indefinitely per the versioned bucket in cloudtrail.tf).
# =============================================================================

# -----------------------------------------------------------------------------
# CloudWatch Log Group that receives a live copy of every CloudTrail event.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 90

  tags = {
    Name = "${var.project_name}-cloudtrail-log-group"
  }
}

# CloudTrail needs its own IAM role (separate from config_role/
# ec2_instance_role in iam.tf) to be allowed to write into the log group
# above. This role can ONLY create log streams and put log events into
# this one specific log group - nothing else.
data "aws_iam_policy_document" "cloudtrail_cloudwatch_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name               = "${var.project_name}-cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_assume.json
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "${var.project_name}-cloudtrail-cloudwatch-delivery"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_permissions.json
}

# -----------------------------------------------------------------------------
# Metric filters: each one searches incoming log events for a pattern and
# increments a custom metric by 1 every time it matches. All six metrics
# below live in a single custom namespace so they are easy to find in the
# CloudWatch console and on the dashboard.
# -----------------------------------------------------------------------------
locals {
  metrics_namespace = "${var.project_name}/security"
}

# Scenario: root account usage.
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\") }"

  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = local.metrics_namespace
    value     = "1"
    default_value = "0"
  }
}

# Scenario: multiple failed AWS console login attempts.
resource "aws_cloudwatch_log_metric_filter" "failed_console_logins" {
  name           = "failed-console-logins"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"

  metric_transformation {
    name          = "FailedConsoleLoginCount"
    namespace     = local.metrics_namespace
    value         = "1"
    default_value = "0"
  }
}

# Scenario: IAM policy changes.
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  name           = "iam-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"DeleteGroupPolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"DeletePolicyVersion\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachGroupPolicy\") || ($.eventName = \"DetachGroupPolicy\") }"

  metric_transformation {
    name          = "IAMPolicyChangeCount"
    namespace     = local.metrics_namespace
    value         = "1"
    default_value = "0"
  }
}

# Scenario: security group changes.
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "security-group-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"

  metric_transformation {
    name          = "SecurityGroupChangeCount"
    namespace     = local.metrics_namespace
    value         = "1"
    default_value = "0"
  }
}

# Scenario: CloudTrail itself stopped or modified - watching the watchman.
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "cloudtrail-stopped-or-modified"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") }"

  metric_transformation {
    name          = "CloudTrailChangeCount"
    namespace     = local.metrics_namespace
    value         = "1"
    default_value = "0"
  }
}

# Scenario: unauthorized API calls (AccessDenied / UnauthorizedOperation).
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name          = "UnauthorizedApiCallCount"
    namespace     = local.metrics_namespace
    value         = "1"
    default_value = "0"
  }
}

# -----------------------------------------------------------------------------
# One CloudWatch Alarm per metric filter above. Each fires as soon as ONE
# matching event occurs within a 5-minute window, and notifies the SNS
# topic from sns.tf. `treat_missing_data = \"notBreaching\"` means periods
# with zero matching events (the normal, healthy state) never trigger or
# confuse the alarm.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.project_name}-root-account-usage"
  alarm_description   = "Fires when the AWS account root user is used for any action."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.root_usage.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "failed_console_logins" {
  alarm_name          = "${var.project_name}-failed-console-logins"
  alarm_description   = "Fires when there are 3 or more failed console login attempts in 5 minutes."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.failed_console_logins.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  alarm_name          = "${var.project_name}-iam-policy-changes"
  alarm_description   = "Fires when any IAM policy is created, changed, attached, or detached."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_changes.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "${var.project_name}-security-group-changes"
  alarm_description   = "Fires when any security group rule is added, removed, created, or deleted."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.security_group_changes.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "${var.project_name}-cloudtrail-stopped-or-modified"
  alarm_description   = "Fires when CloudTrail logging is stopped, the trail is deleted, or the trail is modified."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.cloudtrail_changes.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = "${var.project_name}-unauthorized-api-calls"
  alarm_description   = "Fires when AWS API calls are denied due to insufficient permissions."
  namespace           = local.metrics_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_api_calls.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
# -----------------------------------------------------------------------------
# CloudWatch Dashboard: a single at-a-glance view of all six security
# metrics, so a SOC analyst can see the account's alert history without
# opening six separate metric pages.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "${var.project_name}-security-monitoring"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Root Account Usage"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "RootAccountUsageCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Failed Console Logins"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "FailedConsoleLoginCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "IAM Policy Changes"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "IAMPolicyChangeCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Security Group Changes"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "SecurityGroupChangeCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "CloudTrail Stopped or Modified"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "CloudTrailChangeCount"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Unauthorized API Calls"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.metrics_namespace, "UnauthorizedApiCallCount"]
          ]
        }
      }
    ]
  })
}
