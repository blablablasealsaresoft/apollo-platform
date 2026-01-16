# Analytics Utilities

Quick scripts for slicing Apollo telemetry and investigation data.

- `investigation_report.py` – Summarizes investigations from PostgreSQL or CSV export.
- `timeseries_compare.py` – Overlay blockchain tx vs surveillance hits for situational awareness.
- `dashboards/` – Contains starter JSON dashboards for Grafana/Metabase drops.

Run with `python tools/analytics/investigation_report.py --input data/investigations.csv`.
