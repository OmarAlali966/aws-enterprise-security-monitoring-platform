# ---------------------------------------------------------------------------
# Terraform + AWS Provider Configuration
# ---------------------------------------------------------------------------
# This file tells Terraform two things:
#   1. Which version of Terraform and which "providers" (plugins that talk to
#      a cloud vendors API) this project needs.
#   2. How to connect to AWS specifically - in this case, which region to
#      build resources in.
#
# Keeping this in its own file (instead of mixing it into other files) is a
# common convention in real Terraform projects. It makes it obvious where to
# look if you ever need to upgrade a provider version or change region.
# ---------------------------------------------------------------------------

terraform {
  # required_version pins the Terraform CLI version range this project is
  # tested against. This prevents someone running a much older or newer
  # version of Terraform from hitting unexpected behavior.
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # A "~>" version constraint means "use this major/minor version, but
      # allow patch updates." That gives us bug fixes without accidentally
      # pulling in breaking changes.
      version = "~> 5.0"
    }
  }

  # In a real company, this is where a "backend" block would go, telling
  # Terraform to store its state file remotely (for example, in an S3 bucket
  # with a DynamoDB lock table) instead of on a single laptop. State is left
  # local here so this project stays simple and free-tier friendly, but the
  # commented example below shows how a team would typically configure it.
  #
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "aws-enterprise-security-monitoring-platform/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

# The "provider" block configures the AWS plugin itself: which region to
# create resources in, and which credentials to use (Terraform will read
# credentials from your AWS CLI configuration / environment variables - they
# are never written into this file).
provider "aws" {
  region = var.aws_region

  # default_tags automatically attaches these tags to every resource this
  # provider creates, without having to repeat them in every single resource
  # block. Tagging everything consistently is a real-world best practice -
  # it is how companies track cost, ownership, and environment (dev/prod).
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
