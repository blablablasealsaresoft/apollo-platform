terraform {
  required_version = ">= 1.6.0"
  backend "s3" {}
}

provider "aws" {
  region = var.region
}

module "vpc" {
  source = "../../modules/vpc"
  name   = "apollo-prod"
  cidr   = "10.10.0.0/16"
  az_count = 4
}

module "kubernetes" {
  source       = "../../modules/kubernetes"
  cluster_name = "apollo-prod"
  subnet_ids   = module.vpc.private_subnets
  node_instance_type = "m6i.2xlarge"
}

module "monitoring" {
  source                 = "../../modules/monitoring"
  cluster_name           = module.kubernetes.cluster_name
  grafana_admin_password = var.grafana_admin_password
}
