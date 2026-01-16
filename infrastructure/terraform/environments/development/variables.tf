variable "region" {
  type    = string
  default = "us-east-1"
}

variable "grafana_admin_password" {
  type      = string
  sensitive = true
}
