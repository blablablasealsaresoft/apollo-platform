# Cyberspike Villager Operations

1. **Mission Profile** – define target set in `config/mission-*.yaml`.
2. **Model Routing** – configure weights in `ai-models/model-router.ts`.
3. **C2 Bridge** – run `c2-server/bridge.py` to connect implants.
4. **Driver Layer** – drop device/vehicle drivers into `drivers/` (see `drivers/edge_device_driver.py`).

```
make start-mission mission=crypto
```
