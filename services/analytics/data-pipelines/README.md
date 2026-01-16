# Analytics Data Pipelines

Defines ETL specs for investigations:
- `ingest` → pulls blockchain + surveillance feeds
- `normalize` → converts into common schema
- `publish` → writes to PostgreSQL + TimescaleDB

See `pipelines.yaml` for a ready-to-run Airflow DAG skeleton.
