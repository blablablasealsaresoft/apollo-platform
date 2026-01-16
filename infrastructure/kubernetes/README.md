# Apollo Kubernetes Manifests

The manifests under `infrastructure/kubernetes` compose the minimum viable cluster install used by CI and Terraform modules.  They are split into folders that match typical GitOps repositories so teams can apply them piecemeal or via Kustomize overlays.

```
base/
  namespaces/        # Logical separation of workloads (system, intelligence, surveillance)
  deployments/       # Stateful/stateless components for APIs, databases, and tooling
  services/          # ClusterIP/LoadBalancer definitions
  configmaps/        # Runtime configuration files
  secrets/           # Kubernetes secrets & sealed secrets templates
  ingress/           # External routing via envoy/nginx
  network-policies/  # Zero-trust defaults per namespace
  rbac/              # ServiceAccounts, Roles, and Bindings
  persistent-volumes/# StorageClasses + PVCs
  monitoring/        # ServiceMonitor, PrometheusRule, etc.
```

Each YAML file is safe to apply as-is in non-production clusters.  Replace placeholder secrets, hostnames, and storage classes before production rollouts.
