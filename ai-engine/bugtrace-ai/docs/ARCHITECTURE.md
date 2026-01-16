# BugTrace-AI Architecture

BugTrace-AI combines LLM-assisted reasoning with deterministic scanners. Core layers:

1. **Intake Layer** (`src/index.ts`)
   - Normalizes CLI/API requests.
   - Routes to orchestrator with authorization metadata.
2. **AI Orchestrator** (`src/core/orchestrator.ts`)
   - Chooses best model (Gemini/Claude/OpenAI) based on risk profile.
   - Applies safety policies before prompting.
3. **Analyzers** (`src/analyzers/*`)
   - URL/Code/DOM/JWT modules with AST + AI review.
4. **Reconnaissance** (`src/reconnaissance/*`)
   - JS/asset scanners, passive subdomain discovery.
5. **Payload Forge** (`src/payload/*`)
   - Deterministic payload builders with AI refinement for DOM-XSS + SSTI.
6. **Reporting** (`src/utils/report-generator.ts`)
   - MITRE ATT&CK mapping, JSON/Markdown export.

Data flow:
```
request -> validation -> orchestrator -> analyzer/payload modules -> report
```

Prompts + model configs live under `models/` to keep audit trails.
