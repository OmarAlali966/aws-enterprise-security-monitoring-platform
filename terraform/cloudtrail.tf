# =============================================================================
# CLOUDTRAIL.TF - Account activity logging (the security camera for AWS)
# =============================================================================
# WHAT THIS FILE DOES (in plain English):
# CloudTrail records every API call in the account: who made it, from what
# IP address, what service/action was called, and whether it succeeded.
# This file creates:
#   1. An S3 bucket to store those log files (encrypted + versioned).
#   2. A bucket policy that lets ONLY the CloudTrail service write to it.
#   3. A CloudTrail 'trail' resource that turns logging on, across ALL
#      AWS regions, with tamper-evidence (log file validation) enabled.
#
# WHY A REAL COMPANY USES THIS:
# - It is the primary evidence source for security investigations, breach
#   forensics, and compliance audits (PCI-DSS, SOC 2, HIPAA all require it).
# - GuardDuty, Security Hub, and AWS Config (built in later stages) all
#   depend on CloudTrail being enabled - it is the foundation of the whole
#   monitoring platform.
# - Multi-region trails catch attackers who deliberately operate in a
#   region the security team doesn't normally look at.
#
# COMMON MISTAKES THIS AVOIDS:
# - Enabling CloudTrail in only one region (attackers often pick unused
#   regions specifically to avoid detection).
# - Leaving the log bucket public or writable by anyone other than
#   CloudTrail itself.
# - Not enabling log file validation, which means there's no cryptographic
#   proof the logs weren't altered after the fact.
# - Not encrypting logs with a customer-managed KMS key (see kms.tf).
# =============================================================================

# -----------------------------------------------------------------------------
# S3 bucket that will hold every CloudTrail log file.
# We append the AWS account ID because S3 bucket names must be globally
# unique across ALL of AWS, not just our account.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  # In a real production account you would likely also set force_destroy
  # = false (the default) so logs can never be bulk-deleted by a Terraform
  # mistake. We leave the secure default in place here.

  tags = {
    Name = "${var.project_name}-cloudtrail-logs"
  }
}

# Versioning protects against accidental overwrite/delete of a log file -
# if an attacker (or a script) deletes an object, the old version is kept.
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Every object written to this bucket is automatically encrypted with our
# CloudTrail KMS key (see kms.tf) - not just Amazon's default S3 encryption.
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

# Belt-and-suspenders: block every possible path to making this bucket
# public, even if someone later adds a public ACL or bucket policy by
# mistake. This is an AWS best practice for every bucket, not just this one.
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# Bucket policy: the S3-side permission that actually allows CloudTrail to
# write into the bucket, and denies any request that isn't sent over HTTPS.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {

  # Allow CloudTrail to check the bucket's ACL before it starts writing.
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  # Allow CloudTrail to write log files, but only for trails in our own
  # account, and only if the object is delivered with 'bucket-owner-full-
  # control' - this stops CloudTrail (or anyone impersonating it) from
  # writing objects we would not fully own/control.
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Deny ANY request (from anyone, including admins) that is not sent over
  # HTTPS. This protects log data from being intercepted in transit.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn, "${aws_s3_bucket.cloudtrail_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# -----------------------------------------------------------------------------
# The CloudTrail trail itself.
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id

  # Records activity from every AWS region, not just us-east-1. Required so
  # we don't miss activity in a region we don't normally use.
  is_multi_region_trail = true

  # Captures account-wide services like IAM, which are technically
  # 'global' rather than tied to one region.
  include_global_service_events = true

  # Adds a SHA-256 digest file every hour so we can cryptographically prove
  # the log files have not been tampered with after CloudTrail wrote them.
  enable_log_file_validation = true

  # Encrypt every log file with our own KMS key instead of the AWS default.
  kms_key_id = aws_kms_key.cloudtrail.arn

  # Management events = control-plane actions (creating/deleting resources,
  # changing IAM policies, etc.) - the most important events for a security
  # monitoring platform. We log both successful AND failed attempts, since
  # failed attempts (e.g. repeated AccessDenied calls) are often the first
  # sign of an attacker probing the account.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  # The trail must not be created until the bucket policy exists, otherwise
  # CloudTrail will reject the trail because it cannot yet write to the
  # bucket. Terraform usually infers this from the references above, but we
  # state it explicitly for clarity.
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name = "${var.project_name}-trail"
  }
}
