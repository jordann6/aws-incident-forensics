terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  backend "s3" {
    bucket       = "tf-backend-jord-projs"
    key          = "aws-incident-forensics/lz.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}

# Deploys into the landing zone's security account (the GuardDuty and Security
# Hub delegated admin), through the role exported from the LZ incident/ root.
provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.deploy_role_arn
  }

  default_tags {
    tags = {
      Project     = "aws-incident-forensics"
      Environment = "platform"
      Owner       = "jordan"
      ManagedBy   = "terraform"
      CostCenter  = "cc-0001"
    }
  }
}

data "aws_caller_identity" "current" {}
