# Apollo Platform Infrastructure

This directory packages everything needed to bootstrap and operate the Apollo investigation platform.  It covers:

- **Databases** – production-ready container stack for PostgreSQL, Timescale, Neo4j, Redis, Elasticsearch, MongoDB, and supporting tooling.
- **Docker** – reusable base images, dev/prod compose bundles, and container runtime configs.
- **Kubernetes** – declarative manifests for namespaces, deployments, services, networking, and secrets powering cloud clusters.
- **CI/CD** – opinionated pipelines for GitHub Actions, GitLab CI, Jenkins plus shared scripts.
- **Monitoring** – Prometheus/Alertmanager, Grafana, ELK, Jaeger, and custom exporters with dashboards and alert rules.
- **Security** – PKI automation, Vault/secret policies, compliance/audit templates, and vulnerability scanning baselines.
- **Terraform** – multi-cloud infrastructure-as-code with reusable modules and environment overlays.

Each subdirectory ships with self-documented templates so teams can customize without starting from scratch.  The defaults are safe for local use but highlight where to plug in production secrets, resource sizes, and organization-specific policies.
