# Deployment Tools

Handy scripts for shipping Apollo releases outside of CI.

- `release_builder.py` – Packages versioned artifacts (backend, frontend, manifests) into a single tarball and generates checksums.
- `cluster_deploy.sh` – Applies k8s manifests to a target cluster + monitors rollouts.
- `helm_values/` – Sample values for helm-based installs (staging/prod).

Use when performing hotfixes or air-gapped deployments.
