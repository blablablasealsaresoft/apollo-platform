provider "google" {
  project = var.project
  region  = var.region
}

variable "project" { type = string }
variable "region" { type = string }
