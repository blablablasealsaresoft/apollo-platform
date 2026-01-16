# Infrastructure Deception Toolkit

This package creates believable decoy assets (honey creds, bogus hosts, lure documents) that can be fed into reconnaissance surfaces to detect unauthorized access.

## Modules

- `decoy_manager.py` – Generates synthetic credentials/infrastructure metadata and exports them as JSON for quick ingestion into SIEM, DNS, or Git repositories.
- `lure_generator.py` – Builds minimal lure documents (Markdown) with embedded tracking pixels or unique strings per target.

## Usage

```bash
python redteam/deception/infrastructure-deception/decoy_manager.py --count 5 --output decoys.json
python redteam/deception/infrastructure-deception/lure_generator.py --target "Ruja Asset Seizure" --out lures/
```

All decoys are tagged with operation IDs so the audit logger can correlate triggers back to authorization records.
