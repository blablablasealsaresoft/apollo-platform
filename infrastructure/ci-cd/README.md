# Apollo CI/CD Playbooks

This folder curates pipeline templates that keep the Apollo platform continuously tested, scanned, and deployable across GitHub Actions, GitLab CI, and Jenkins.

- **github-actions** – Multi-job workflows covering lint → build → test → scan → deploy gates.  Use these as drop-in `.github/workflows` definitions.
- **gitlab-ci** – A composable `include`-driven pipeline for users that rely on GitLab runners.
- **jenkins** – Declarative pipelines and shared-library patterns for self-hosted orchestration.
- **scripts** – Shell helpers referenced by every system to standardize docker/image builds, smoke tests, and compliance checks.

All workflows are environment-aware (dev/staging/prod) and publish SBOM plus security scan artifacts to satisfy traceability requirements in the OneCoin casework.
