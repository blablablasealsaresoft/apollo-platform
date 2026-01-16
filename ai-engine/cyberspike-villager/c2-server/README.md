# Cyberspike C2 Bridge

Reference implementation for bridging AI agents and external C2 frameworks (Sliver/Havoc/Mythic).

- `bridge.py` – Asyncio-based relay that translates protobuf beacons into Apollo's gRPC control plane.
- `server_config.yaml` – Listener + key material placeholders.

Run locally:
```bash
python bridge.py --config server_config.yaml
```
