terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    helm = { source = "hashicorp/helm", version = "~> 2.11" }
  }
  backend "s3" {}
}

provider "aws" {
  region = var.region
}

module "vpc" {
  source = "../../modules/vpc"
  name   = "apollo-dev"
  cidr   = "10.20.0.0/16"
}

module "kubernetes" {
  source            = "../../modules/kubernetes"
  cluster_name      = "apollo-dev"
  subnet_ids        = module.vpc.private_subnets
  node_instance_type = "t3a.large"
}

module "monitoring" {
  source                 = "../../modules/monitoring"
  cluster_name           = module.kubernetes.cluster_name
  grafana_admin_password = var.grafana_admin_password
}
