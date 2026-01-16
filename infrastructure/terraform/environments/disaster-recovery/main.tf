terraform {
  required_version = ">= 1.6.0"
  backend "s3" {}
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region
}

provider "aws" {
  alias  = "backup"
  region = var.backup_region
}

module "primary_vpc" {
  source = "../../modules/vpc"
  providers = { aws = aws.primary }
  name   = "apollo-dr-primary"
  cidr   = "10.50.0.0/16"
}

module "backup_vpc" {
  source = "../../modules/vpc"
  providers = { aws = aws.backup }
  name   = "apollo-dr-backup"
  cidr   = "10.60.0.0/16"
}
