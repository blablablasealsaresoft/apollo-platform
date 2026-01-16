# Apollo Platform - Production Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Security Configuration](#security-configuration)
4. [Database Setup](#database-setup)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Monitoring Setup](#monitoring-setup)
7. [Post-Deployment Validation](#post-deployment-validation)
8. [Rollback Procedures](#rollback-procedures)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements
- **Kubernetes Cluster:**
  - Minimum 5 worker nodes
  - 16 CPU cores per node
  - 64GB RAM per node
  - 500GB SSD storage per node

- **Database Server:**
  - PostgreSQL 15+
  - 32 CPU cores
  - 128GB RAM
  - 2TB NVMe SSD (RAID 10)

- **Cache Server:**
  - Redis 7+
  - 16 CPU cores
  - 64GB RAM
  - 500GB SSD

- **Storage:**
  - S3-compatible object storage (MinIO or AWS S3)
  - 10TB minimum capacity
  - High IOPS capability

### Software Requirements
- Kubernetes 1.28+
- Helm 3.12+
- kubectl 1.28+
- Docker 24+
- Terraform 1.5+ (for infrastructure provisioning)
- AWS CLI or equivalent cloud provider CLI

### Access Requirements
- Kubernetes cluster admin access
- Container registry credentials (GitHub Container Registry)
- SSL/TLS certificates
- DNS management access
- Cloud provider credentials

---

## Infrastructure Setup

### 1. Provision Kubernetes Cluster

#### Using AWS EKS:
```bash
# Create EKS cluster
eksctl create cluster \
  --name apollo-production \
  --version 1.28 \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type m5.4xlarge \
  --nodes 5 \
  --nodes-min 3 \
  --nodes-max 10 \
  --managed
```

#### Using Azure AKS:
```bash
# Create AKS cluster
az aks create \
  --resource-group apollo-production \
  --name apollo-cluster \
  --kubernetes-version 1.28.0 \
  --node-count 5 \
  --node-vm-size Standard_D16s_v3 \
  --enable-cluster-autoscaler \
  --min-count 3 \
  --max-count 10
```

#### Using Google GKE:
```bash
# Create GKE cluster
gcloud container clusters create apollo-production \
  --cluster-version 1.28 \
  --zone us-central1-a \
  --num-nodes 5 \
  --machine-type n1-standard-16 \
  --enable-autoscaling \
  --min-nodes 3 \
  --max-nodes 10
```

### 2. Configure kubectl
```bash
# Get cluster credentials
kubectl config use-context apollo-production

# Verify connection
kubectl cluster-info
kubectl get nodes
```

### 3. Create Namespaces
```bash
kubectl apply -f infrastructure/kubernetes/namespace.yaml
```

---

## Security Configuration

### 1. SSL/TLS Certificates

#### Using Let's Encrypt:
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f infrastructure/kubernetes/cert-manager/cluster-issuer.yaml
```

#### Using existing certificates:
```bash
# Create TLS secret
kubectl create secret tls apollo-tls \
  --cert=path/to/cert.crt \
  --key=path/to/cert.key \
  --namespace=apollo-production
```

### 2. Create Secrets

#### Database credentials:
```bash
kubectl create secret generic apollo-db-secret \
  --from-literal=host=apollo-postgres.example.com \
  --from-literal=port=5432 \
  --from-literal=database=apollo_production \
  --from-literal=username=apollo_user \
  --from-literal=password='SECURE_PASSWORD_HERE' \
  --namespace=apollo-production
```

#### JWT secret:
```bash
# Generate strong JWT secret
JWT_SECRET=$(openssl rand -base64 64)

kubectl create secret generic apollo-jwt-secret \
  --from-literal=secret="$JWT_SECRET" \
  --namespace=apollo-production
```

#### API keys and external services:
```bash
kubectl create secret generic apollo-api-keys \
  --from-literal=openai-api-key='sk-...' \
  --from-literal=aws-access-key-id='AKIA...' \
  --from-literal=aws-secret-access-key='...' \
  --from-literal=blockchain-api-key='...' \
  --namespace=apollo-production
```

### 3. Configure RBAC
```bash
kubectl apply -f infrastructure/kubernetes/rbac.yaml
```

### 4. Network Policies
```bash
kubectl apply -f infrastructure/kubernetes/network-policies.yaml
```

---

## Database Setup

### 1. PostgreSQL Installation

#### Using Kubernetes:
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami

helm install apollo-postgres bitnami/postgresql \
  --namespace apollo-production \
  --set auth.username=apollo_user \
  --set auth.password=SECURE_PASSWORD \
  --set auth.database=apollo_production \
  --set primary.persistence.size=2Ti \
  --set primary.resources.requests.memory=64Gi \
  --set primary.resources.requests.cpu=16 \
  --set metrics.enabled=true
```

#### Using external managed database (recommended for production):
Configure connection details in secrets (see Security Configuration above).

### 2. Run Database Migrations
```bash
# Create temporary migration pod
kubectl run migration-pod \
  --image=ghcr.io/apollo-platform/apollo-migration:latest \
  --namespace=apollo-production \
  --env="DATABASE_URL=postgresql://apollo_user:PASSWORD@apollo-postgres:5432/apollo_production" \
  --restart=Never \
  --command -- npm run migrate:production

# Wait for completion
kubectl wait --for=condition=complete pod/migration-pod --namespace=apollo-production --timeout=300s

# Check logs
kubectl logs migration-pod --namespace=apollo-production

# Delete migration pod
kubectl delete pod migration-pod --namespace=apollo-production
```

### 3. Seed Initial Data
```bash
kubectl run seed-pod \
  --image=ghcr.io/apollo-platform/apollo-seed:latest \
  --namespace=apollo-production \
  --env="DATABASE_URL=postgresql://apollo_user:PASSWORD@apollo-postgres:5432/apollo_production" \
  --restart=Never \
  --command -- npm run seed:production
```

### 4. Setup Redis
```bash
helm install apollo-redis bitnami/redis \
  --namespace apollo-production \
  --set architecture=standalone \
  --set auth.enabled=true \
  --set auth.password=REDIS_PASSWORD \
  --set master.persistence.size=100Gi \
  --set master.resources.requests.memory=32Gi \
  --set master.resources.requests.cpu=8
```

### 5. Setup Elasticsearch
```bash
helm repo add elastic https://helm.elastic.co

helm install apollo-elasticsearch elastic/elasticsearch \
  --namespace apollo-production \
  --set replicas=3 \
  --set volumeClaimTemplate.resources.requests.storage=500Gi \
  --set resources.requests.memory=32Gi \
  --set resources.requests.cpu=8
```

### 6. Setup RabbitMQ
```bash
helm install apollo-rabbitmq bitnami/rabbitmq \
  --namespace apollo-production \
  --set auth.username=admin \
  --set auth.password=RABBITMQ_PASSWORD \
  --set persistence.size=100Gi \
  --set resources.requests.memory=16Gi \
  --set resources.requests.cpu=4
```

---

## Kubernetes Deployment

### 1. Apply ConfigMaps
```bash
kubectl apply -f infrastructure/kubernetes/configmap.yaml
```

### 2. Deploy Services

#### Deploy all services:
```bash
# Deploy authentication service
kubectl apply -f infrastructure/kubernetes/authentication-service.yaml

# Deploy investigation service
kubectl apply -f infrastructure/kubernetes/investigation-service.yaml

# Deploy intelligence fusion service
kubectl apply -f infrastructure/kubernetes/intelligence-fusion-service.yaml

# Deploy search service
kubectl apply -f infrastructure/kubernetes/search-service.yaml

# Deploy notification service
kubectl apply -f infrastructure/kubernetes/notification-service.yaml

# Deploy analytics service
kubectl apply -f infrastructure/kubernetes/analytics-service.yaml

# Deploy file storage service
kubectl apply -f infrastructure/kubernetes/file-storage-service.yaml

# Deploy reporting service
kubectl apply -f infrastructure/kubernetes/reporting-service.yaml

# Deploy frontend
kubectl apply -f infrastructure/kubernetes/frontend.yaml
```

#### Or deploy all at once:
```bash
kubectl apply -f infrastructure/kubernetes/ --namespace=apollo-production
```

### 3. Verify Deployments
```bash
# Check pod status
kubectl get pods --namespace=apollo-production

# Check services
kubectl get services --namespace=apollo-production

# Check deployments
kubectl get deployments --namespace=apollo-production

# View logs
kubectl logs -f deployment/apollo-authentication --namespace=apollo-production
```

### 4. Setup Ingress
```bash
# Install NGINX Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# Apply ingress configuration
kubectl apply -f infrastructure/kubernetes/ingress.yaml
```

---

## Monitoring Setup

### 1. Install Prometheus
```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.retention=30d \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=500Gi
```

### 2. Configure Prometheus
```bash
kubectl apply -f infrastructure/monitoring/prometheus/prometheus-config.yaml
kubectl apply -f infrastructure/monitoring/prometheus/alert-rules.yaml
```

### 3. Install Grafana
```bash
# Grafana is included with kube-prometheus-stack
# Get Grafana password
kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode

# Port forward to access Grafana
kubectl port-forward --namespace monitoring svc/prometheus-grafana 3000:80
```

### 4. Import Dashboards
```bash
# Import Apollo Platform dashboards
kubectl apply -f infrastructure/monitoring/grafana/dashboards/
```

### 5. Setup Alertmanager
```bash
kubectl apply -f infrastructure/monitoring/prometheus/alertmanager-config.yaml
```

---

## Post-Deployment Validation

### 1. Health Checks
```bash
# Check all pods are running
kubectl get pods --namespace=apollo-production --field-selector=status.phase=Running

# Check service endpoints
kubectl get endpoints --namespace=apollo-production

# Test service health
curl https://apollo-platform.com/api/health
curl https://apollo-platform.com/api/authentication/health
curl https://apollo-platform.com/api/investigation/health
```

### 2. Run Smoke Tests
```bash
npm run test:smoke:production
```

### 3. Performance Tests
```bash
# Run load test
k6 run testing/performance-tests/load-tests/production-smoke-test.js
```

### 4. Security Validation
```bash
# Run security scan
npm run security:scan:production
```

---

## Rollback Procedures

### Quick Rollback
```bash
# Rollback specific deployment
kubectl rollout undo deployment/apollo-authentication --namespace=apollo-production

# Rollback to specific revision
kubectl rollout undo deployment/apollo-authentication --to-revision=2 --namespace=apollo-production

# Check rollout status
kubectl rollout status deployment/apollo-authentication --namespace=apollo-production
```

### Full System Rollback
```bash
# Rollback all deployments
for deployment in $(kubectl get deployments --namespace=apollo-production -o name); do
  kubectl rollout undo $deployment --namespace=apollo-production
done
```

### Database Rollback
```bash
# Restore from backup
kubectl run restore-pod \
  --image=postgres:15 \
  --namespace=apollo-production \
  --env="PGPASSWORD=PASSWORD" \
  --restart=Never \
  --command -- psql -h apollo-postgres -U apollo_user -d apollo_production < /backups/backup-TIMESTAMP.sql
```

---

## Troubleshooting

### Pod Not Starting
```bash
# Describe pod
kubectl describe pod POD_NAME --namespace=apollo-production

# Check logs
kubectl logs POD_NAME --namespace=apollo-production --previous

# Check events
kubectl get events --namespace=apollo-production --sort-by='.lastTimestamp'
```

### Service Unavailable
```bash
# Check service
kubectl describe service SERVICE_NAME --namespace=apollo-production

# Check endpoints
kubectl get endpoints SERVICE_NAME --namespace=apollo-production

# Port forward for debugging
kubectl port-forward svc/SERVICE_NAME 8080:80 --namespace=apollo-production
```

### Database Connection Issues
```bash
# Test database connection
kubectl run -it --rm debug-pod --image=postgres:15 --namespace=apollo-production --restart=Never -- psql -h apollo-postgres -U apollo_user -d apollo_production
```

### High Resource Usage
```bash
# Check resource usage
kubectl top pods --namespace=apollo-production
kubectl top nodes

# Describe HPA
kubectl describe hpa --namespace=apollo-production
```

---

## Support

For deployment support:
- Email: devops@apollo-platform.com
- Slack: #apollo-deployments
- On-call: +1-XXX-XXX-XXXX

## Related Documentation
- [Security Guidelines](./SECURITY_GUIDELINES.md)
- [Operations Manual](./OPERATIONS_MANUAL.md)
- [Disaster Recovery Plan](./DISASTER_RECOVERY.md)
- [Scaling Guidelines](./SCALING_GUIDELINES.md)
