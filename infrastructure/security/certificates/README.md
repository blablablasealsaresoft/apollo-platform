# PKI Automation

The `scripts/` directory contains portable helpers to bootstrap a mini certificate authority for lab or air-gapped deployments.  Certificates are NOT committed; only configs.  Generated materials should reside in `certificates/ca|server|client` which remain gitignored.

Usage example:
```
./scripts/generate-ca.sh apollo-ca
./scripts/generate-server-cert.sh apollo-gateway apollo.local
./scripts/generate-client-cert.sh ruja-agent
```

All scripts emit PEM files and Kubernetes Secrets ready for `kubectl apply`.
