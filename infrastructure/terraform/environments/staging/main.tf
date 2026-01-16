terraform {
  required_version = ">= 1.6.0"
  backend "s3" {}
}

provider "aws" {
  region = var.region
}

module "vpc" {
  source = "../../modules/vpc"
  name   = "apollo-staging"
  cidr   = "10.30.0.0/16"
}

module "kubernetes" {
  source       = "../../modules/kubernetes"
  cluster_name = "apollo-staging"
  subnet_ids   = module.vpc.private_subnets
}
