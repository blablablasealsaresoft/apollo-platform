# Apollo AI Tools

Operator utilities for working with investigation-focused AI assistants.

## Contents
- `prompt_linter.py` – Quick quality/lint pass for prompt files; enforces mission-specific guardrails.
- `embedding_builder.py` – Generates sentence embeddings for case files and produces JSONL for vector DB ingestion.
- `chat_session_template.yaml` – Template capturing metadata (mission, sensitivity, controls) for reproducible AI runs.

## Usage
```
python tools/ai-tools/prompt_linter.py prompts/ignatova.txt
python tools/ai-tools/embedding_builder.py --input data/intel_reports --output vector-data/ignatova.jsonl
```
