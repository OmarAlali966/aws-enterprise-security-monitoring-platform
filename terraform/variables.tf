# ---------------------------------------------------------------------------
# Input Variables
# ---------------------------------------------------------------------------
# Variables let this configuration be reused and changed without editing the
# actual resource code. Instead of hardcoding "us-east-1" or a project name
# in ten different files, we define it once here and reference it everywhere
# with var.aws_region, var.project_name, and so on.
#
# This also means the same codebase could be reused for a second environment
# just by changing the values passed in, not the underlying logic - which is
# exactly why real teams use variables instead of hardcoded values.
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region where all resources will be created."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used to prefix and tag resources so they are easy to identify in the AWS console and in billing reports."
  type        = string
  default     = "meridian-security-platform"
}

variable "environment" {
  description = "Environment name (for example dev or prod). Used in tags and naming to keep resources organized as the project grows."
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address that receives security alert notifications from SNS. AWS will send a subscription confirmation email the first time this is applied - it must be clicked before alerts will arrive."
  type        = string
  # No default on purpose. This keeps even a placeholder email out of the
  # code that gets committed to GitHub. Set the real value in a local
  # terraform.tfvars file, which is excluded from version control by
  # .gitignore.
}

variable "enable_config_recorder" {
  description = "Whether to enable the AWS Config configuration recorder. Kept as a variable so it can be switched off quickly to avoid charges once you are done experimenting."
  type        = bool
  default     = true
}
