variable "cluster_name" { type = string }
variable "grafana_admin_password" { type = string }

resource "helm_release" "prometheus" {
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = "monitoring"
  create_namespace = true
  values = [
    yamlencode({
      grafana = {
        adminPassword = var.grafana_admin_password
        dashboardsConfigMaps = { apollo = "apollo-dashboards" }
      }
    })
  ]
}
