# Secrets Management Guide

This document describes how to securely manage secrets (passwords, API keys, certificates) for the Apollo platform.

## Overview

**CRITICAL**: Never commit secrets to version control. Always use environment variables or a secrets management solution.

## Secret Categories

### 1. Database Credentials
- PostgreSQL passwords
- Redis passwords
- Neo4j passwords
- Elasticsearch credentials
- TimescaleDB passwords

### 2. Service Credentials
- RabbitMQ credentials
- SMTP credentials
- OAuth client secrets

### 3. API Keys
- OSINT API keys (Shodan, VirusTotal, etc.)
- Blockchain API keys (Etherscan, etc.)
- Social media API keys
- Geolocation API keys

### 4. Application Secrets
- JWT signing secrets
- Session secrets
- Encryption keys

## Environment Variables

All secrets should be provided via environment variables. The platform enforces this in production mode.

### Required in Production

```bash
# Database
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
NEO4J_PASSWORD=<strong-password>

# Message Queue
RABBITMQ_USER=<username>
RABBITMQ_PASSWORD=<strong-password>

# Security
SECRET_KEY=<minimum-64-character-random-string>
JWT_SECRET=<minimum-64-character-random-string>
SESSION_SECRET=<minimum-32-character-random-string>

# CORS (must be explicit in production)
CORS_ORIGINS=https://app.yourdomain.com,https://admin.yourdomain.com
ALLOWED_HOSTS=api.yourdomain.com,*.yourdomain.com
```

## Secrets Management Solutions

### Option 1: HashiCorp Vault (Recommended for Production)

1. Install Vault:
```bash
# Kubernetes
helm install vault hashicorp/vault

# Docker
docker run -d --cap-add=IPC_LOCK -e 'VAULT_LOCAL_CONFIG={"backend": {"file": {"path": "/vault/file"}}, "default_lease_ttl": "168h", "max_lease_ttl": "720h"}' vault server
```

2. Store secrets:
```bash
vault kv put secret/apollo/database \
    postgres_password="<password>" \
    redis_password="<password>"

vault kv put secret/apollo/api-keys \
    shodan_api_key="<key>" \
    virustotal_api_key="<key>"
```

3. Access in application:
```python
import hvac

client = hvac.Client(url='http://vault:8200', token=os.environ['VAULT_TOKEN'])
secret = client.secrets.kv.read_secret_version(path='apollo/database')
db_password = secret['data']['data']['postgres_password']
```

### Option 2: AWS Secrets Manager

1. Create secret:
```bash
aws secretsmanager create-secret \
    --name apollo/database \
    --secret-string '{"postgres_password":"<password>","redis_password":"<password>"}'
```

2. Access in application:
```python
import boto3
import json

client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='apollo/database')
secrets = json.loads(response['SecretString'])
```

### Option 3: Kubernetes Secrets

1. Create secrets:
```bash
kubectl create secret generic apollo-database \
    --from-literal=postgres-password='<password>' \
    --from-literal=redis-password='<password>'

kubectl create secret generic apollo-api-keys \
    --from-literal=shodan-key='<key>' \
    --from-literal=virustotal-key='<key>'
```

2. Use in deployment:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: apollo-api
spec:
  template:
    spec:
      containers:
      - name: api
        envFrom:
        - secretRef:
            name: apollo-database
        - secretRef:
            name: apollo-api-keys
```

### Option 4: Docker Secrets (Swarm Mode)

1. Create secrets:
```bash
echo "your-password" | docker secret create db_password -
echo "your-api-key" | docker secret create shodan_key -
```

2. Use in compose:
```yaml
services:
  api:
    secrets:
      - db_password
      - shodan_key

secrets:
  db_password:
    external: true
  shodan_key:
    external: true
```

## Password Requirements

All passwords in production must meet these requirements:

- Minimum 12 characters
- Contains uppercase letters
- Contains lowercase letters
- Contains numbers
- Contains special characters
- Not a common password or dictionary word

## Secret Rotation

Implement regular secret rotation:

1. **Database passwords**: Every 90 days
2. **API keys**: Every 180 days
3. **JWT secrets**: Every 30 days (coordinate with session management)
4. **Service account credentials**: Every 90 days

## Security Checklist

Before deploying to production, verify:

- [ ] No secrets in source code
- [ ] No secrets in Docker images
- [ ] No secrets in CI/CD logs
- [ ] All required environment variables set
- [ ] Secret rotation schedule defined
- [ ] Access to secrets is audited
- [ ] Secrets are encrypted at rest
- [ ] Secrets are encrypted in transit
- [ ] Development secrets differ from production
- [ ] `.env` files are in `.gitignore`

## Audit and Monitoring

1. Enable audit logging for secrets access
2. Set up alerts for:
   - Failed authentication attempts
   - Unusual secrets access patterns
   - Missing required secrets at startup
3. Review access logs regularly

## Emergency Procedures

### Compromised Secret Response

1. **Immediately rotate** the compromised secret
2. **Audit** all access to the secret
3. **Review** systems that had access
4. **Notify** security team
5. **Document** the incident
6. **Update** rotation procedures if needed

### Secret Recovery

1. Secrets should be backed up in a separate secure location
2. Recovery procedures should be documented and tested
3. Access to backups should be strictly limited

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
