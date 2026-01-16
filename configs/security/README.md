# Apollo Platform Security Configuration

Comprehensive security configurations for the Apollo Platform law enforcement investigation system. This directory contains all security-related configurations implementing defense-in-depth, zero trust, and CJIS compliance.

## Directory Structure

```
configs/security/
├── authentication/          # Authentication mechanisms
│   ├── jwt-config.yaml           # JWT token configuration
│   ├── oauth-providers.yaml      # OAuth/SAML provider settings
│   ├── mfa-config.yaml           # Multi-factor authentication
│   ├── password-policy.yaml      # Password requirements
│   └── session-management.yaml   # Session handling
│
├── authorization/          # Access control
│   ├── rbac-roles.yaml           # Role definitions
│   ├── rbac-permissions.yaml     # Permission definitions
│   ├── resource-policies.yaml    # Resource-based policies
│   └── access-control-lists.yaml # Fine-grained ACLs
│
├── encryption/            # Encryption and key management
│   ├── encryption-config.yaml    # Encryption settings
│   ├── key-management.yaml       # Key lifecycle management
│   ├── tls-config.yaml           # TLS/SSL configuration
│   └── certificate-management.yaml # Certificate handling
│
├── compliance/           # Regulatory compliance
│   ├── cjis-compliance.yaml      # FBI CJIS Security Policy
│   ├── gdpr-compliance.yaml      # GDPR/LED compliance
│   ├── ccpa-compliance.yaml      # California privacy law
│   ├── soc2-compliance.yaml      # SOC 2 controls
│   └── iso27001-compliance.yaml  # ISO 27001 ISMS
│
├── audit-logging/        # Comprehensive audit trails
│   ├── audit-rules.yaml          # Audit event definitions
│   ├── log-retention.yaml        # Retention policies
│   ├── compliance-reporting.yaml # Compliance reports
│   └── alert-rules.yaml          # Security alerts
│
├── network/             # Network security
│   ├── firewall-rules.yaml       # Firewall configuration
│   ├── rate-limiting.yaml        # API rate limits
│   ├── ip-whitelist.yaml         # IP allowlists
│   └── ddos-protection.yaml      # DDoS mitigation
│
├── incident-response/   # Security incident handling
│   ├── response-plan.yaml        # IR procedures
│   ├── escalation-chain.yaml     # Escalation paths
│   ├── automated-actions.yaml    # Automated responses
│   └── forensics-procedures.yaml # Digital forensics
│
└── README.md           # This file
```

## Security Principles

### 1. Defense in Depth
Multiple layers of security controls:
- Network perimeter security (firewalls, IDS/IPS)
- Application security (authentication, authorization)
- Data security (encryption at rest and in transit)
- Monitoring and detection (SIEM, audit logging)

### 2. Zero Trust Architecture
Never trust, always verify:
- Strong authentication (MFA required)
- Least privilege access (RBAC)
- Micro-segmentation (network isolation)
- Continuous verification (session management)

### 3. Principle of Least Privilege
Users and systems receive minimum required access:
- Role-based access control (RBAC)
- Just-in-time access
- Regular access reviews
- Automatic privilege expiration

### 4. Compliance First
Built for law enforcement requirements:
- CJIS Security Policy v5.9.1
- GDPR/LED (Law Enforcement Directive)
- SOC 2 Type II
- ISO 27001
- NIST Cybersecurity Framework

## Key Features

### Authentication
- **Multi-Factor Authentication**: Required for all users
  - TOTP (Time-based OTP)
  - Hardware security keys (FIDO2/WebAuthn)
  - Biometric authentication
  - SMS/Email OTP (fallback)

- **Advanced Authentication**: CJIS-compliant
  - 16+ character passwords
  - 90-day password rotation
  - Hardware token support
  - Risk-based authentication

- **Session Management**: Secure session handling
  - 12-hour session timeout
  - IP binding
  - Device fingerprinting
  - Concurrent session limits

### Authorization
- **Role-Based Access Control**: Hierarchical roles
  - Admin, Senior Investigator, Investigator
  - Intelligence Analyst, Forensic Specialist
  - Red Team Operator, Compliance Officer
  - Supervisor, Analyst, Viewer, Guest

- **Fine-Grained Permissions**: 100+ permission types
  - Investigation management
  - Intelligence operations (OSINT, GEOINT, SIGINT)
  - Evidence handling
  - Red team operations
  - System administration

- **Dynamic Policies**: Context-aware access
  - Time-based restrictions
  - Location-based access
  - Risk-based decisions
  - Classification-based controls

### Encryption
- **Data at Rest**: AES-256-GCM encryption
  - Database encryption (PostgreSQL, Neo4j, MongoDB)
  - File system encryption (dm-crypt)
  - Evidence encryption with digital signatures
  - Hardware Security Module (HSM) integration

- **Data in Transit**: TLS 1.3
  - Perfect Forward Secrecy (PFS)
  - Strong cipher suites only
  - Certificate pinning
  - Mutual TLS (mTLS)

- **Key Management**: Comprehensive lifecycle
  - Automatic key rotation
  - Key hierarchy (Master KEK → KEK → DEK)
  - Hardware key storage (HSM/KMS)
  - Secure key backup and recovery

### Audit Logging
- **Comprehensive Logging**: All security events
  - Authentication events
  - Authorization decisions
  - Data access and modifications
  - System operations
  - Security incidents

- **Tamper Protection**: Log integrity
  - Digital signatures
  - Blockchain anchoring
  - Write-once storage
  - Tamper detection

- **Long-Term Retention**: Compliance-driven
  - Active investigations: 7 years
  - Closed investigations: 20 years
  - Security events: Indefinite
  - Encrypted archival

### Compliance
- **CJIS Security Policy**: FBI requirements
  - Advanced authentication
  - Personnel screening
  - Physical security
  - Audit logging
  - Incident response

- **GDPR/LED**: Data protection
  - Law enforcement exemptions
  - Data minimization
  - Privacy by design
  - Data subject rights (limited)

- **SOC 2 Type II**: Trust services
  - Security
  - Availability
  - Processing integrity
  - Confidentiality
  - Privacy

### Incident Response
- **Automated Response**: Immediate action
  - Account lockout on brute force
  - IP blocking on attacks
  - System isolation on compromise
  - Evidence preservation

- **Escalation Chain**: Defined paths
  - Level 1: Security Team (15 minutes)
  - Level 2: Security Manager (30 minutes)
  - Level 3: CISO (Immediate)
  - Level 4: Executive Team

- **Forensics Ready**: Investigation support
  - Digital forensics tools
  - Chain of custody
  - Evidence collection
  - Timeline analysis

## Configuration Management

### Environment Variables
All sensitive values use environment variables:
```yaml
# Example from jwt-config.yaml
jwt:
  access_token:
    secret: ${JWT_SECRET}  # Set via environment
```

Required environment variables documented in each config file.

### Configuration Validation
Validate configurations before deployment:
```bash
# Validate YAML syntax
yamllint configs/security/**/*.yaml

# Validate against schema (if available)
./scripts/validate-security-config.sh

# Test configurations
./scripts/test-security-config.sh
```

### Deployment
Deploy configurations by environment:
```bash
# Development
export ENVIRONMENT=development
./scripts/deploy-security-config.sh

# Production
export ENVIRONMENT=production
./scripts/deploy-security-config.sh
```

## Security Monitoring

### Real-Time Alerts
Critical events trigger immediate alerts:
- Unauthorized access attempts
- Privilege escalation
- Data exfiltration
- Malware detection
- Evidence tampering

### Metrics and Dashboards
Key security metrics tracked:
- Failed authentication attempts
- Access denials
- Policy violations
- Security incidents
- Compliance status

### SIEM Integration
Security events forwarded to SIEM:
- Elasticsearch for indexing
- Kibana for visualization
- Wazuh for correlation
- Custom dashboards

## Compliance Auditing

### Self-Assessment
Regular internal audits:
- Quarterly access reviews
- Monthly security metrics
- Weekly log analysis
- Daily health checks

### External Audits
Third-party assessments:
- Annual SOC 2 audit
- Triennial ISO 27001 certification
- CJIS compliance review
- Penetration testing

### Documentation
Maintained compliance documentation:
- Security policies
- Procedures and standards
- Risk assessments
- Incident reports
- Training records

## Testing and Validation

### Security Testing
Regular security testing:
- Weekly vulnerability scans
- Monthly penetration tests
- Quarterly red team exercises
- Annual security assessments

### Incident Response Testing
IR plan validation:
- Quarterly tabletop exercises
- Biannual simulations
- Annual full-scale tests

### Compliance Testing
Verify compliance controls:
- Monthly control testing
- Quarterly compliance reviews
- Annual external audits

## Getting Started

### 1. Initial Setup
```bash
# Clone repository
git clone <repo-url>

# Set environment variables
cp .env.example .env
# Edit .env with your values

# Validate configurations
./scripts/validate-security-config.sh
```

### 2. Deploy Configurations
```bash
# Deploy to development
./scripts/deploy-security-config.sh development

# Deploy to production (requires approval)
./scripts/deploy-security-config.sh production
```

### 3. Verify Deployment
```bash
# Check configuration status
./scripts/check-security-status.sh

# Run security tests
./scripts/test-security-controls.sh
```

## Support and Contacts

### Security Team
- **Email**: security@apollo-platform.gov
- **Hotline**: +1-XXX-XXX-XXXX (24/7)
- **Slack**: #security-team

### Incident Reporting
- **Emergency**: +1-XXX-XXX-XXXX
- **Email**: incidents@apollo-platform.gov
- **Portal**: https://apollo-platform.gov/security/report

### CISO
- **Name**: [CISO Name]
- **Email**: ciso@apollo-platform.gov
- **Mobile**: +1-XXX-XXX-XXXX

## Additional Resources

### Documentation
- [Security Architecture](../../docs/security/architecture.md)
- [Threat Model](../../docs/security/threat-model.md)
- [Security Procedures](../../docs/security/procedures.md)
- [Compliance Guides](../../docs/compliance/)

### Training
- Security Awareness Training (Required Annual)
- CJIS Security Policy Training (Required Annual)
- Incident Response Training (Quarterly)
- Role-Specific Security Training

### Tools
- Security Dashboard: https://apollo-platform.gov/security
- Incident Management: https://apollo-platform.gov/incidents
- Compliance Portal: https://apollo-platform.gov/compliance
- Audit Logs: https://apollo-platform.gov/audit

## Version History

- **v1.0.0** (2026-01-14): Initial security configuration
  - CJIS Security Policy v5.9.1 compliance
  - GDPR/LED compliance
  - SOC 2 Type II controls
  - ISO 27001 alignment

## License

Classified - Law Enforcement Use Only

Copyright (c) 2026 Apollo Platform
All rights reserved.

Unauthorized access, use, or distribution is strictly prohibited and may result in criminal prosecution.
