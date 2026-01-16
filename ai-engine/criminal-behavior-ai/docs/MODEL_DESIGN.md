# Criminal Behavior AI - Model Design

## Feature Groups
- **Financial Metrics**: transaction velocity, crypto mixer usage, asset dispersion.
- **Communication Signals**: encrypted channels, burner device turnover, geographic hops.
- **Network Position**: graph centrality from Neo4j intelligence graph.

## Architecture
- Gradient boosted decision tree (XGBoost) for baseline scoring.
- Temporal attention layer for sequential behaviors (implemented in `training/sequential_model.py`).
- Calibration step ensures scores map to risk tiers (green/yellow/red).

## Outputs
```json
{
  "risk_score": 0.82,
  "tier": "red",
  "top_factors": [
    "High crypto outflows",
    "Association with Ignatova node",
    "Recent burner SIM purchase"
  ]
}
```
