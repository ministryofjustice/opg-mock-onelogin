terraform {

  backend "s3" {
    bucket         = "opg.terraform.state"
    key            = "opg-mock-onelogin/terraform.tfstate"
    encrypt        = true
    region         = "eu-west-1"
    role_arn       = "arn:aws:iam::311462405659:role/shared-ci"
    dynamodb_table = "remote_lock"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.40.0"
    }
    github = {
      source  = "integrations/github"
      version = "4.11.0"
    }
  }
  required_version = ">= 1.5.7"
}

provider "github" {
  token        = var.github_token
  organization = "ministryofjustice"
}

locals {
  sandbox = "995199299616"
}

provider "aws" {
  alias = "sandbox"

  assume_role {
    role_arn     = "arn:aws:iam::${local.sandbox}:role/${var.DEFAULT_ROLE}"
    session_name = "terraform-session"
  }
}


variable "github_token" {
}

variable "aws_access_key_id" {
}

variable "aws_secret_access_key" {
}

variable "DEFAULT_ROLE" {
  default = "shared-ci"
}


data "aws_caller_identity" "current" {
  provider = aws.sandbox
}