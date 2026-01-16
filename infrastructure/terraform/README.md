# Apollo Terraform

Composable IaC modules that stand up the full Apollo platform (VPC networking, managed Kubernetes, data planes, monitoring, and security tooling) across AWS/Azure/GCP plus on-prem overlays.

## Layout
- `modules/` – opinionated Terraform modules (vpc, kubernetes, monitoring, etc.).
- `environments/` – environment-specific stacks that wire modules together.
- `providers/` – helper files defining remote state, provider blocks, and shared variables per cloud.
- `scripts/` – wrappers to initialize, plan, apply, and run drift/compliance checks.

Each environment uses a standard workflow:
```
cd infrastructure/terraform/environments/development
terraform init -backend-config=backend.hcl
terraform plan -var-file=dev.tfvars
terraform apply
```
