# =============================================================================
# KMS.TF - Encryption key used to protect CloudTrail log files
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# CloudTrail records every API call made in our AWS account (who did what,
# when, and from where). Those log files are extremely sensitive - if an
# attacker could read or tamper with them, they could hide their tracks.
# This file creates a KMS "Customer Managed Key" (CMK) that is used to
# encrypt those log files at rest in S3, and it defines EXACTLY who is
# allowed to use that key.
#
# WHY A REAL COMPANY USES THIS:
# - Compliance frameworks (PCI-DSS, HIPAA, SOC 2, FedRAMP) require audit
#   logs to be encrypted with a key the customer controls, not just AWS's
#   default encryption.
# - A customer-managed key lets the Security team revoke access, rotate
#   the key, and produce a full audit trail of every encrypt/decrypt call
#   (KMS itself is logged by CloudTrail too).
#
# COMMON MISTAKES THIS AVOIDS:
# - Using SSE-S3 (Amazon-managed encryption) for logs, which means you
#   cannot control or restrict who can decrypt them.
# - Writing a KMS key policy that is too permissive (e.g. "Principal *"),
#   which would let any authenticated AWS principal use the key.
# - Forgetting that CloudTrail needs explicit permission in the KEY POLICY
#   (not just an IAM policy) before it can encrypt logs - KMS key policies
#   are the ultimate source of truth for who can use a key.
# =============================================================================

# These two data sources look up information about the AWS account we are
# deploying into. We need the account ID and partition ("aws", "aws-us-gov",
# etc.) to write an accurate key policy below.
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# -----------------------------------------------------------------------------
# The KMS key policy document.
# A key policy is REQUIRED for every KMS key (unlike IAM policies, which are
# optional attachments). Think of it as the master permission list that sits
# directly on the key itself.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "cloudtrail_kms" {

  # Statement 1: Always give the AWS account (root) full permissions on the
  # key. Without this, it is possible to permanently lock EVERYONE (including
  # admins) out of the key, because IAM policies alone are not enough for KMS.
  # This is the #1 recommended safety net from AWS's own documentation.
  statement {
    sid    = "EnableRootAccountFullAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Statement 2: Allow the CloudTrail service itself to check the key exists.
  statement {
    sid    = "AllowCloudTrailToDescribeKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  # Statement 3: Allow CloudTrail to encrypt (GenerateDataKey) log files, but
  # ONLY when the request is coming from a CloudTrail trail that belongs to
  # THIS account. The condition prevents a trail in a different AWS account
  # from ever being able to use our key to encrypt its own logs.
  statement {
    sid    = "AllowCloudTrailToEncryptLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  # Statement 4: Allow people/roles IN OUR ACCOUNT to decrypt the logs so
  # they can actually be investigated (e.g. Security Hub, Athena, or a human
  # analyst reading a log file from S3). Without this, encrypted logs would
  # be permanently unreadable - a very common beginner mistake.
  statement {
    sid    = "AllowAccountToDecryptLogs"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }
}

# -----------------------------------------------------------------------------
# The actual KMS key resource.
# -----------------------------------------------------------------------------
resource "aws_kms_key" "cloudtrail" {
  description = "Customer-managed key used to encrypt CloudTrail log files for ${var.project_name}"

  # If someone deletes this key by mistake, AWS waits this many days before
  # permanently destroying it, giving us time to cancel the deletion.
  # 7 is the minimum allowed; enterprises often use 30.
  deletion_window_in_days = 7

  # Automatically rotates the underlying cryptographic material every year
  # without changing the key's ARN/ID - a security best practice that costs
  # nothing extra and requires no application changes.
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.cloudtrail_kms.json

  tags = {
    Name = "${var.project_name}-cloudtrail-key"
  }
}

# A friendly, human-readable alias so we (and other AWS services) can refer
# to "alias/meridian-security-platform-cloudtrail" instead of a long key ARN.
resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}
