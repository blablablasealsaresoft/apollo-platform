# Apollo Docker Assets

Reusable Dockerfiles and compose bundles for local dev and hardened production images.

- `base-images/` – curated base layers with security patches baked in.
- `configs/` – runtime config such as hardened nginx or redis settings consumed by compose/k8s deployments.
- `development/` – compose stack tuned for contributors (live reload, lightweight resources).
- `production/` – reference compose for air-gapped or edge deployments when Kubernetes is unavailable.

The primary repo-level `docker-compose*.yml` files reference these assets, so keep versions synchronized when updating packages.
