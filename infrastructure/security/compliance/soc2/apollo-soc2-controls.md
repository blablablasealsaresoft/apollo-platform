# Apollo SOC 2 Control Matrix

| Trust Service | Control ID | Description | Evidence |
|---------------|------------|-------------|----------|
| Security | SEC-01 | RBAC enforced through Kubernetes + Vault policies | RBAC manifests, Vault policy exports |
| Availability | AV-02 | 99.5% uptime with automated failover in Terraform modules | Prometheus uptime reports |
| Confidentiality | CONF-05 | Secrets encrypted at rest using SealedSecrets and KMS | Key rotation logs |
| Processing Integrity | PI-03 | CI/CD gates enforce tests + code reviews | GitHub Actions logs |
| Privacy | PRIV-02 | Data minimization strategies documented in GDPR PIA | GDPR docs |
