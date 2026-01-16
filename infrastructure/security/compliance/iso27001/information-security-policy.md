# Information Security Policy

1. **Purpose** – Protect all Apollo investigative data (case files, biometric telemetry, blockchain evidence) from unauthorized access or alteration.
2. **Scope** – Applies to every employee, contractor, and automated agent interacting with Apollo systems in any environment.
3. **Policy**
   - Enforce least privilege via RBAC and network policies.
   - Encrypt sensitive data in transit (TLS 1.2+) and at rest (EBS/LUKS/KMS).
   - Monitor and log every administrative action; retain audit logs 7 years.
   - Patch critical vulnerabilities within 24 hours.
4. **Compliance** – Reviewed quarterly by the Security Steering Committee; deviations require a documented risk acceptance signed by the CISO.
