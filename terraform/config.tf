# =============================================================================
# CONFIG.TF - Continuous configuration compliance monitoring
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# AWS Config takes a constant inventory of every supported resource in the
# account (S3 buckets, security groups, IAM policies, etc.), records every
# configuration change over time, and evaluates each resource against rules
# you choose. This file turns Config on (the 'recorder'), tells it where to
# store its history (the 'delivery channel' -> an S3 bucket), and attaches
# a set of AWS-managed compliance rules relevant to this project's threat
# scenarios (public buckets, unencrypted storage, overly open IAM/security
# groups, and whether CloudTrail is still enabled).
#
# WHY A REAL COMPANY USES THIS:
# - Cloud environments change constantly. Config answers 'what changed, when
#   and by whom' and 'are we compliant right now', which manual spreadsheet
#   audits cannot keep up with.
# - Many compliance frameworks (PCI-DSS, NIST 800-53, CIS Benchmarks)
#   explicitly require continuous configuration monitoring, and Config's
#   conformance packs map directly to those frameworks.
#
# HOW IT IMPROVES SECURITY:
# Config doesn't just detect a bad state once - it re-evaluates resources
# whenever they change, and can (in a later stage) trigger an SNS alert or
# automatic remediation the moment a resource drifts out of compliance.
#
# COMMON MISTAKES TO AVOID:
# - Turning on the recorder but never actually attaching any rules - Config
#   will happily record history forever without ever telling you about a
#   problem.
# - Forgetting `include_global_resource_types = true`, which means IAM
#   (a global service) is silently excluded from monitoring.
# - Not restricting the Config S3 bucket the same way as the CloudTrail
#   bucket - configuration history is just as sensitive as activity logs.
#
# BEST PRACTICES APPLIED HERE:
# - The recorder watches ALL supported resource types, not a hand-picked
#   subset, so nothing is accidentally left unmonitored.
# - The S3 bucket reuses the same public-access-block / HTTPS-only pattern
#   established for CloudTrail in cloudtrail.tf.
# =============================================================================

# -----------------------------------------------------------------------------
# S3 bucket that stores AWS Config's configuration history and snapshots.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "config_logs" {
  bucket = "${var.project_name}-config-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-config-logs"
  }
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# We use Amazon S3-managed keys (SSE-S3) here rather than the CloudTrail
# KMS key. Sharing one KMS key across two unrelated services would mean
# widening that key's trust boundary; creating a second customer-managed
# key would add another small monthly cost. SSE-S3 still encrypts every
# object at rest and is a reasonable, Free-Tier-friendly choice for
# configuration history (as opposed to CloudTrail's audit logs, which we
# deliberately protect with a dedicated customer-managed key).
resource "aws_s3_bucket_server_side_encryption_configuration" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_bucket_policy" {

  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config_logs.arn, "${aws_s3_bucket.config_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

# -----------------------------------------------------------------------------
# The Configuration Recorder: turns on continuous resource inventory and
# change tracking, using the 'config_role' IAM role created in iam.tf.
# -----------------------------------------------------------------------------
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    # Records every resource type AWS Config supports, instead of a
    # hand-picked list that could accidentally miss something important.
    all_supported = true
    # Without this, global resources like IAM users/roles/policies would
    # NOT be recorded at all - a very common beginner mistake.
    include_global_resource_types = true
  }
}

# Where Config delivers configuration snapshots and history files.
resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.id

  depends_on = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.config_logs]
}

# The recorder is created in a 'stopped' state by default - this resource
# is what actually switches it on. It must come after the delivery channel
# exists, or AWS rejects the start request.
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# -----------------------------------------------------------------------------
# AWS-managed Config Rules.
# Each rule below maps directly to one of this project's threat scenarios
# (see docs/incident-response.md). Using AWS-managed rules (source owner
# = 'AWS') means we don't have to write or maintain any custom Lambda
# evaluation logic ourselves.
# -----------------------------------------------------------------------------

# Scenario: public S3 bucket (read access).
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# Scenario: public S3 bucket (write access) - arguably even more dangerous,
# since anyone on the internet could upload or overwrite objects.
resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name = "s3-bucket-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# Scenario: unencrypted resource - flags any S3 bucket without default
# server-side encryption enabled.
resource "aws_config_config_rule" "s3_bucket_encryption_enabled" {
  name = "s3-bucket-server-side-encryption-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# Scenario: overly permissive IAM policy - flags any IAM policy whose
# statements grant '*' admin-style access.
resource "aws_config_config_rule" "iam_policy_no_admin_access" {
  name = "iam-policy-no-statements-with-admin-access"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# Scenario: security group open to the internet - flags any security
# group that allows unrestricted inbound SSH (0.0.0.0/0 on port 22).
resource "aws_config_config_rule" "restricted_ssh" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# Sanity check: confirms CloudTrail (built in Stage 3) stays enabled,
# multi-region, and is actively logging - i.e. Config watches the
# platform's own logging foundation for drift.
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}
