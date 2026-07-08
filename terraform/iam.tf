# ---------------------------------------------------------------------------
# IAM Foundations
# ---------------------------------------------------------------------------
# This file defines the identity and access management structure for the
# account: the account-wide password policy, four IAM groups used to
# separate duties (Administrators, Security, Developers, ReadOnly), the
# least-privilege policies attached to each group, service roles that let
# AWS services act on our behalf, and a handful of example IAM users used
# to demonstrate the group structure in this portfolio project.
#
# Note on real enterprise practice: most companies today use AWS IAM
# Identity Center (formerly AWS SSO) backed by a central identity provider
# instead of creating individual IAM users by hand. Long-lived IAM users are
# increasingly treated as a legacy pattern reserved for service accounts or
# break-glass emergency access. This project uses IAM users directly to keep
# the lab self-contained and free-tier friendly; docs/iam.md explains where
# a real company would do this differently.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Account Password Policy
# ---------------------------------------------------------------------------
# Applies to every IAM user who signs in with a password. A weak or absent
# password policy is one of the most common findings in real security
# audits, and it is also one of the first checks in Security Hub's CIS AWS
# Foundations Benchmark standard.
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24

  # Common mistake: setting max_password_age without allowing users to
  # change their own password. If users cannot change their password, an
  # expiring policy just locks people out and forces an admin to manually
  # reset every account.
}

# ---------------------------------------------------------------------------
# IAM Groups
# ---------------------------------------------------------------------------
# Groups let us attach a policy once and have it apply to every user placed
# in that group, instead of attaching policies to individual users one at a
# time. This is how real companies scale access management: a handful of
# groups, not hundreds of per-user policies.
resource "aws_iam_group" "administrators" {
  name = "Administrators"
}

resource "aws_iam_group" "security" {
  name = "Security"
}

resource "aws_iam_group" "developers" {
  name = "Developers"
}

resource "aws_iam_group" "read_only" {
  name = "ReadOnly"
}

# ---------------------------------------------------------------------------
# Administrators Group
# ---------------------------------------------------------------------------
# Full access, reserved for a very small number of trusted operators. In a
# real company this group would typically have two or three members at
# most, and every login would require hardware MFA.
resource "aws_iam_group_policy_attachment" "administrators_access" {
  group      = aws_iam_group.administrators.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------------------------
# Require MFA For Sensitive Actions
# ---------------------------------------------------------------------------
# Attached to Administrators, Security, and Developers. Allows a short list
# of actions needed to sign in and set up MFA, but denies almost everything
# else unless the caller has already authenticated with a second factor.
# This is a very common enterprise control pattern documented by AWS.
data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid    = "AllowViewAccountInfo"
    effect = "Allow"
    actions = [
      "iam:GetAccountPasswordPolicy",
      "iam:ListVirtualMFADevices",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowManageOwnMFA"
    effect = "Allow"
    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:DeactivateMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:ListMFADevices",
    ]
    # Note the $${...} escaping below. In Terraform, "${" normally starts an
    # interpolation expression. Since we want the literal text
    # "${aws:username}" to appear in the IAM policy JSON (a variable the IAM
    # service itself resolves at request time, not Terraform), we have to
    # escape it as "$${aws:username}". Forgetting this escape is a common
    # mistake that either breaks the plan or silently produces the wrong
    # policy.
    resources = [
      "arn:aws:iam::*:mfa/$${aws:username}",
      "arn:aws:iam::*:user/$${aws:username}",
    ]
  }

  statement {
    sid    = "DenyAllExceptListedUnlessMFAed"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "require_mfa" {
  name        = "RequireMFAForSensitiveActions"
  description = "Denies most actions unless the caller has authenticated with MFA."
  policy      = data.aws_iam_policy_document.require_mfa.json
}

resource "aws_iam_group_policy_attachment" "administrators_require_mfa" {
  group      = aws_iam_group.administrators.name
  policy_arn = aws_iam_policy.require_mfa.arn
}

resource "aws_iam_group_policy_attachment" "security_require_mfa" {
  group      = aws_iam_group.security.name
  policy_arn = aws_iam_policy.require_mfa.arn
}

resource "aws_iam_group_policy_attachment" "developers_require_mfa" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.require_mfa.arn
}

# ---------------------------------------------------------------------------
# Security Group
# ---------------------------------------------------------------------------
# Represents the security/SOC function: broad read access to logs and
# findings across CloudTrail, GuardDuty, Security Hub, and Config, plus just
# enough write access to triage findings - without full administrative
# rights over the rest of the account.
data "aws_iam_policy_document" "security_team" {
  statement {
    sid    = "ReadOnlySecurityFindings"
    effect = "Allow"
    actions = [
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:DescribeTrails",
      "guardduty:Get*",
      "guardduty:List*",
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
      "config:Get*",
      "config:Describe*",
      "config:List*",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
      "logs:Get*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "sns:List*",
      "sns:Get*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "TriageSecurityFindings"
    effect = "Allow"
    actions = [
      "securityhub:BatchUpdateFindings",
      "guardduty:UpdateFindingsFeedback",
      "guardduty:ArchiveFindings",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "security_team" {
  name        = "SecurityTeamLeastPrivilege"
  description = "Read access to security tooling plus finding triage, without full account admin rights."
  policy      = data.aws_iam_policy_document.security_team.json
}

resource "aws_iam_group_policy_attachment" "security_least_privilege" {
  group      = aws_iam_group.security.name
  policy_arn = aws_iam_policy.security_team.arn
}

# ---------------------------------------------------------------------------
# Developers Group
# ---------------------------------------------------------------------------
# Developers get access to the services needed for day-to-day feature work -
# scoped storage, logs for debugging, basic compute visibility - and are
# explicitly denied the ability to touch IAM, CloudTrail, GuardDuty,
# Security Hub, or Config. This prevents a compromised or careless developer
# credential from disabling logging or detection, which is one of the first
# things a real attacker tries after gaining a foothold.
data "aws_iam_policy_document" "developers" {
  statement {
    sid    = "ProjectS3Access"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.project_name}-*",
      "arn:aws:s3:::${var.project_name}-*/*",
    ]
  }

  statement {
    sid    = "BasicComputeVisibility"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "logs:Get*",
      "logs:Describe*",
      "logs:FilterLogEvents",
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenySecurityToolingChanges"
    effect = "Deny"
    actions = [
      "iam:*",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "guardduty:DeleteDetector",
      "guardduty:UpdateDetector",
      "securityhub:DisableSecurityHub",
      "config:StopConfigurationRecorder",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developers" {
  name        = "DevelopersLeastPrivilege"
  description = "Scoped access to project resources for development work, with explicit denies on security tooling."
  policy      = data.aws_iam_policy_document.developers.json
}

resource "aws_iam_group_policy_attachment" "developers_least_privilege" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developers.arn
}

# ---------------------------------------------------------------------------
# ReadOnly Group
# ---------------------------------------------------------------------------
# For auditors, new hires during onboarding, or stakeholders who need
# visibility without any ability to make changes. Uses the AWS managed
# ReadOnlyAccess policy, which is broad but strictly non-mutating.
resource "aws_iam_group_policy_attachment" "read_only_access" {
  group      = aws_iam_group.read_only.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ---------------------------------------------------------------------------
# Service Role: AWS Config
# ---------------------------------------------------------------------------
# AWS Config needs permission to read the configuration of resources across
# the account and write results to our S3 bucket. Rather than using a
# personal IAM user's credentials, the Config service assumes this role
# directly - the standard pattern for letting an AWS service act on your
# behalf without ever handling long-lived credentials.
data "aws_iam_policy_document" "config_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_role" {
  name               = "${var.project_name}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role.json
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ---------------------------------------------------------------------------
# Service Role: EC2 (for SSM / CloudWatch Agent)
# ---------------------------------------------------------------------------
# Any EC2 instance in this project assumes this role via an instance profile
# instead of having AWS credentials stored on the instance itself. Storing
# access keys on an EC2 instance is a classic mistake: if the instance is
# compromised, the attacker gets standing credentials that outlive the
# instance. Instance roles issue short-lived, automatically rotated
# credentials instead.
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_instance_role" {
  name               = "${var.project_name}-ec2-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_managed" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_agent" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.project_name}-ec2-instance-profile"
  role = aws_iam_role.ec2_instance_role.name
}

# ---------------------------------------------------------------------------
# Example Demo IAM Users
# ---------------------------------------------------------------------------
# These users exist purely to demonstrate the group structure above for this
# portfolio project. No access keys or console passwords are created here on
# purpose - generating real credentials inside shared, committed
# infrastructure code is a common and serious mistake. To actually log in as
# one of these users, create a console password manually through the AWS
# Console or CLI after applying this configuration, and enable MFA on it
# immediately.
resource "aws_iam_user" "demo_admin" {
  name = "demo-admin"
}

resource "aws_iam_user_group_membership" "demo_admin_membership" {
  user   = aws_iam_user.demo_admin.name
  groups = [aws_iam_group.administrators.name]
}

resource "aws_iam_user" "demo_security_analyst" {
  name = "demo-security-analyst"
}

resource "aws_iam_user_group_membership" "demo_security_membership" {
  user   = aws_iam_user.demo_security_analyst.name
  groups = [aws_iam_group.security.name]
}

resource "aws_iam_user" "demo_developer" {
  name = "demo-developer"
}

resource "aws_iam_user_group_membership" "demo_developer_membership" {
  user   = aws_iam_user.demo_developer.name
  groups = [aws_iam_group.developers.name]
}

resource "aws_iam_user" "demo_auditor" {
  name = "demo-auditor"
}

resource "aws_iam_user_group_membership" "demo_auditor_membership" {
  user   = aws_iam_user.demo_auditor.name
  groups = [aws_iam_group.read_only.name]
}
