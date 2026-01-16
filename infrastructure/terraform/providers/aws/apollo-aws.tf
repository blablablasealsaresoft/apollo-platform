provider "aws" {
  region              = var.region
  allowed_account_ids = var.allowed_account_ids
  default_tags {
    tags = {
      Project = "Apollo"
      Owner   = "Threat-Intel"
    }
  }
}

variable "region" { type = string }
variable "allowed_account_ids" { type = list(string) }
