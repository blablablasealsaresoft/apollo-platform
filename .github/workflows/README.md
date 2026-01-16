# Apollo Platform CI/CD Workflows

This document describes all GitHub Actions workflows used in the Apollo Platform for continuous integration, continuous deployment, and infrastructure management.

## Overview

```
Workflows
├── CI (Continuous Integration)
│   ├── ci-main.yml          # Main CI pipeline for all branches
│   └── ci-merge.yml         # Pre-merge validation for PRs
│
├── CD (Continuous Deployment)
│   ├── cd-deploy.yml        # Combined deployment workflow
│   ├── deploy-staging.yml   # Staging-specific deployment
│   └── deploy-production.yml # Production deployment with approvals
│
├── Security
│   └── security-scan.yml    # Comprehensive security scanning
│
├── Infrastructure
│   ├── terraform-plan.yml   # Infrastructure planning
│   ├── terraform-apply.yml  # Infrastructure changes
│   └── database-migrations.yml # Database management
│
├── Release
│   └── release.yml          # Release creation and publishing
│
└── Reusable
    └── reusable-build.yml   # Shared build workflow
```

## Workflow Descriptions

### CI Workflows

#### ci-main.yml
**Trigger:** Push to agent*, feature/*, bugfix/* branches; PRs to master/main
**Purpose:** Core CI pipeline with linting, testing, and building

Jobs:
- `lint` - ESLint, Pylint, Prettier, TypeScript checks
- `unit-tests` - Unit tests with coverage reporting
- `integration-tests` - Integration tests with service dependencies
- `security-scan` - npm audit, Snyk, Semgrep, TruffleHog
- `build` - Docker image building for all services
- `report` - Test result aggregation and PR comments

#### ci-merge.yml
**Trigger:** PRs to master/main (opened, synchronize, reopened, ready_for_review)
**Purpose:** Comprehensive pre-merge validation

Jobs:
- `full-test-suite` - Complete test execution
- `e2e-tests` - Playwright end-to-end tests
- `load-tests` - k6 performance tests
- `security-audit` - Deep security analysis
- `code-quality` - SonarCloud analysis
- `approval-required` - Manual approval gate

### CD Workflows

#### deploy-staging.yml
**Trigger:** Push to master/main; manual dispatch
**Purpose:** Automated staging deployment

Features:
- Pre-deployment validation
- Parallel service image builds
- Database migrations
- Rolling deployment
- Health checks and smoke tests
- Automatic rollback on failure
- Slack notifications

#### deploy-production.yml
**Trigger:** Release published; manual dispatch
**Purpose:** Production deployment with safeguards

Features:
- Version validation
- Staging verification check
- Manual approval required
- Pre-deployment backup
- Database migrations
- Canary deployment (10% traffic)
- Extended monitoring (5 minutes)
- Automatic rollback on failure
- Slack and Teams notifications

### Security Workflow

#### security-scan.yml
**Trigger:** Push to master/main; PRs; Daily at 3 AM UTC; manual
**Purpose:** Comprehensive security scanning

Jobs:
- `sast` - Static analysis (Semgrep, Bandit, ESLint, CodeQL)
- `dependency-scan` - npm audit, Snyk, Safety, pip-audit
- `container-scan` - Trivy, Grype, Hadolint
- `secret-scan` - Gitleaks, TruffleHog, detect-secrets
- `iac-scan` - Checkov, tfsec, Kubesec
- `dast-prep` - Dynamic analysis setup
- `report` - Consolidated security report

### Infrastructure Workflows

#### terraform-plan.yml
**Trigger:** PRs with infrastructure changes; manual dispatch
**Purpose:** Preview infrastructure changes

Features:
- Terraform validation and formatting
- Security scanning (tfsec, Checkov)
- Plan generation for staging and production
- Cost estimation with Infracost
- PR comments with plan output

#### terraform-apply.yml
**Trigger:** Manual dispatch only
**Purpose:** Apply infrastructure changes

Features:
- Input validation
- State backup before apply
- Environment-specific approval gates
- Artifact-based plan application
- Post-apply verification
- Audit logging

#### database-migrations.yml
**Trigger:** Manual dispatch only
**Purpose:** Database schema management

Actions:
- `migrate` - Apply pending migrations
- `rollback` - Rollback migrations
- `status` - Check migration status
- `seed` - Seed test data (staging only)

Features:
- Dry-run mode
- Pre-migration backup
- Environment protection
- Slack notifications

### Release Workflow

#### release.yml
**Trigger:** Version tags (v*.*.*); manual dispatch
**Purpose:** Create and publish releases

Features:
- Version validation
- Full test suite
- Multi-platform image builds
- Image signing with Cosign
- Changelog generation
- GitHub release creation
- Slack notifications

## Required Secrets

### GitHub Secrets

| Secret | Description | Required For |
|--------|-------------|--------------|
| `GITHUB_TOKEN` | Auto-provided | All workflows |
| `SNYK_TOKEN` | Snyk API token | Security scanning |
| `SONAR_TOKEN` | SonarCloud token | Code quality |
| `CODECOV_TOKEN` | Codecov token | Coverage reports |
| `INFRACOST_API_KEY` | Infracost API key | Cost estimation |
| `GITLEAKS_LICENSE` | Gitleaks license | Secret scanning |

### AWS Secrets

| Secret | Description | Required For |
|--------|-------------|--------------|
| `AWS_ACCESS_KEY_ID` | AWS access key | Backups, S3 |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | Backups, S3 |
| `AWS_REGION` | AWS region | All AWS operations |
| `AWS_ROLE_STAGING` | IAM role for staging | Terraform |
| `AWS_ROLE_PRODUCTION` | IAM role for production | Terraform |

### Kubernetes Secrets

| Secret | Description | Required For |
|--------|-------------|--------------|
| `KUBE_CONFIG_STAGING` | Base64 kubeconfig | Staging deployment |
| `KUBE_CONFIG_PRODUCTION` | Base64 kubeconfig | Production deployment |

### Terraform Secrets

| Secret | Description | Required For |
|--------|-------------|--------------|
| `TF_STATE_BUCKET` | S3 bucket for state | Terraform |
| `TF_LOCK_TABLE` | DynamoDB table for locking | Terraform |

### Notification Secrets

| Secret | Description | Required For |
|--------|-------------|--------------|
| `SLACK_WEBHOOK` | General Slack webhook | Notifications |
| `SLACK_WEBHOOK_STAGING` | Staging channel webhook | Staging deploys |
| `SLACK_WEBHOOK_PRODUCTION` | Production channel webhook | Production deploys |
| `SLACK_WEBHOOK_SECURITY` | Security channel webhook | Security alerts |
| `SLACK_WEBHOOK_INFRASTRUCTURE` | Infra channel webhook | Terraform |
| `SLACK_WEBHOOK_DATABASE` | Database channel webhook | Migrations |
| `SLACK_WEBHOOK_RELEASES` | Release channel webhook | Releases |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams webhook | Production deploys |

## Environment Configuration

### Environments

| Environment | Protection Rules | Reviewers |
|-------------|------------------|-----------|
| `staging` | None | - |
| `production` | Required reviewers | DevOps team |
| `production-approval` | Required reviewers, wait timer | DevOps lead, Engineering manager |
| `terraform-staging` | None | - |
| `terraform-production` | Required reviewers | DevOps team |
| `database-staging` | None | - |
| `database-production-approval` | Required reviewers | DBA, DevOps lead |
| `merge-approval` | Required reviewers | Engineering lead |

### Environment Variables

Set these in repository settings or environment configuration:

```
NODE_VERSION=18.x
PYTHON_VERSION=3.11
TF_VERSION=1.6.0
```

## Usage Examples

### Manual Staging Deployment
```bash
gh workflow run deploy-staging.yml
```

### Production Deployment
```bash
gh workflow run deploy-production.yml \
  -f version=v1.2.3 \
  -f skip_staging_check=false
```

### Rollback Production
```bash
gh workflow run deploy-production.yml \
  -f version=v1.2.3 \
  -f rollback_version=v1.2.2
```

### Run Security Scan
```bash
gh workflow run security-scan.yml \
  -f scan_type=full
```

### Apply Terraform
```bash
gh workflow run terraform-apply.yml \
  -f environment=staging \
  -f auto_approve=true
```

### Database Migration
```bash
gh workflow run database-migrations.yml \
  -f environment=staging \
  -f action=migrate \
  -f dry_run=true
```

### Create Release
```bash
git tag v1.2.3
git push origin v1.2.3
# Or manually:
gh workflow run release.yml \
  -f version=1.2.3 \
  -f prerelease=false
```

## Workflow Dependencies

```
ci-main.yml
    └── ci-merge.yml (requires ci-main checks)
            └── deploy-staging.yml (on merge to main)
                    └── deploy-production.yml (manual trigger)

security-scan.yml (independent, scheduled)

terraform-plan.yml (on infrastructure PRs)
    └── terraform-apply.yml (manual trigger)

database-migrations.yml (independent, manual)

release.yml (on version tags)
    └── deploy-production.yml (automatic prompt)
```

## Troubleshooting

### Common Issues

**Build fails with "npm ci" error:**
- Check package-lock.json is committed
- Verify Node.js version matches package.json engines

**Kubernetes deployment fails:**
- Verify KUBE_CONFIG secret is valid and not expired
- Check namespace exists
- Verify image pull secrets

**Terraform plan fails:**
- Check AWS credentials are valid
- Verify state bucket exists and is accessible
- Check for syntax errors with `terraform validate`

**Security scan false positives:**
- Add exceptions in `.semgrepignore` or `.gitleaks.toml`
- Document exceptions in PR comments

### Debug Mode

Enable debug logging:
```bash
gh workflow run <workflow>.yml --ref main
# In Actions UI, re-run with debug logging enabled
```

Or set repository secret:
```
ACTIONS_STEP_DEBUG=true
```

## Contributing

When modifying workflows:

1. Test changes in a feature branch first
2. Use `workflow_dispatch` for manual testing
3. Add new secrets to this documentation
4. Update environment protection rules as needed
5. Keep workflows DRY using reusable workflows
