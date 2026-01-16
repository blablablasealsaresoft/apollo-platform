provider "kubernetes" {
  config_path = var.kubeconfig
}

variable "kubeconfig" {
  type = string
}
