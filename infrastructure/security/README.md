# Apollo Security Toolkit

Security artifacts that back the Apollo incident response mission.  Every file is either a policy, automation script, or template that can be fed into CI/CD to enforce secure defaults.

- `certificates/` – PKI automation to generate the CA/server/client certs used inside clusters.
- `secrets-management/` – Vault policies, SealedSecret templates, and ExternalSecrets resources.
- `network-security/` – Firewall, VPN, and zero-trust policies that define perimeters.
- `compliance/` – Narrative control evidence for SOC 2, ISO 27001, GDPR, and law-enforcement cooperation.
- `vulnerability-scanning/` – Configurations for container, dependency, SAST, and DAST tooling.

Use these templates as a baseline; update owners, ticketing references, and compliance IDs to match your organization before audits.
