# Cyberspike Villager API Documentation

## REST API (FastAPI - Port 37695)

### Overview

Villager provides a task-based REST API for autonomous operations. Submit high-level objectives in natural language, and AI handles the rest.

### Base URL

```
http://localhost:37695
```

---

## Endpoints

### 1. Submit Task

Submit a task for AI autonomous execution.

**Endpoint:** `POST /task`

**Request Body:**

```json
{
  "abstract": "High-level objective",
  "description": "Detailed requirements",
  "verification": "Success criteria",
  "authorization": "WARRANT-2026-001",
  "mission": "cryptocurrency-crime",
  "priority": "HIGH"
}
```

**Response:**

```json
{
  "task_id": "uuid",
  "status": "processing",
  "message": "Task submitted successfully. AI is planning execution."
}
```

**Example:**

```bash
curl -X POST http://localhost:37695/task \
  -H "Content-Type: application/json" \
  -d '{
    "abstract": "Investigate suspect-exchange.com for evidence",
    "description": "Complete security assessment and evidence collection",
    "verification": "User database and transaction logs extracted",
    "authorization": "WARRANT-2026-001",
    "mission": "cryptocurrency-crime",
    "priority": "HIGH"
  }'
```

---

### 2. Get Task Status

Get current status and progress of a task.

**Endpoint:** `GET /task/{task_id}/status`

**Response:**

```json
{
  "id": "task-uuid",
  "abstract": "Investigate suspect-exchange.com",
  "status": "IN_PROGRESS",
  "progress": 65,
  "created_at": "2026-01-14T10:00:00Z",
  "subtasks": [
    {
      "id": "subtask-1",
      "action": "reconnaissance",
      "status": "COMPLETED",
      "tools": ["bbot", "subhunterx"]
    },
    {
      "id": "subtask-2",
      "action": "vulnerability-analysis",
      "status": "IN_PROGRESS",
      "tools": ["bugtrace-ai"]
    }
  ]
}
```

**Example:**

```bash
curl http://localhost:37695/task/task-uuid/status
```

---

### 3. Get Task Dependency Tree

Get task relationship graph for visualization.

**Endpoint:** `GET /task/{task_id}/tree`

**Response:**

```json
{
  "task_id": "task-uuid",
  "abstract": "Investigate suspect-exchange.com",
  "status": "IN_PROGRESS",
  "subtasks": [
    {
      "id": "subtask-1",
      "action": "reconnaissance",
      "status": "COMPLETED",
      "dependencies": []
    },
    {
      "id": "subtask-2",
      "action": "vulnerability-analysis",
      "status": "IN_PROGRESS",
      "dependencies": ["subtask-1"]
    }
  ],
  "dependencies": {
    "nodes": [...],
    "edges": [...]
  }
}
```

---

### 4. List All Tasks

Get overview of all tasks.

**Endpoint:** `GET /tasks`

**Response:**

```json
{
  "total": 5,
  "tasks": [
    {
      "id": "task-1",
      "abstract": "Investigation 1",
      "status": "COMPLETED"
    },
    {
      "id": "task-2",
      "abstract": "Investigation 2",
      "status": "IN_PROGRESS"
    }
  ]
}
```

---

### 5. Get Task Context

Get detailed execution context and logs.

**Endpoint:** `GET /task/{task_id}/context`

**Response:**

```json
{
  "task_id": "task-uuid",
  "context": {
    "abstract": "...",
    "description": "...",
    "authorization": "WARRANT-2026-001",
    "mission": "cryptocurrency-crime"
  },
  "logs": [
    "AI planning reconnaissance",
    "Executing BBOT scan",
    "Subdomains discovered: 47"
  ],
  "evidence": [
    {
      "id": "evidence-1",
      "type": "database_extract",
      "hash": "sha256..."
    }
  ]
}
```

---

### 6. Cancel Task

Cancel a running task.

**Endpoint:** `DELETE /task/{task_id}`

**Response:**

```json
{
  "message": "Task cancelled successfully"
}
```

---

### 7. Health Check

Check system health.

**Endpoint:** `GET /health`

**Response:**

```json
{
  "status": "healthy",
  "ai_models": "operational",
  "mcp_tools": "operational",
  "active_tasks": 3
}
```

---

## TypeScript SDK

### Installation

```bash
npm install @apollo/cyberspike-villager
```

### Usage

```typescript
import { AIC2Controller, CryptoCrimeHunter } from '@apollo/cyberspike-villager';

// Natural language operation
const aiController = new AIC2Controller();

const result = await aiController.executeNaturalLanguageCommand({
  command: "Investigate suspect-exchange.com for evidence",
  authorization: "WARRANT-2026-001",
  mission: "cryptocurrency-crime",
  preserveEvidence: true
});

console.log(result.success);
console.log(result.evidence);

// Specialized module
const cryptoHunter = new CryptoCrimeHunter();

const investigation = await cryptoHunter.investigate(
  "suspect-exchange.com",
  "WARRANT-2026-001",
  "full"
);

console.log(investigation.wallets);
console.log(investigation.operators);
```

---

## Mission-Specific APIs

### Crypto Crime Investigation

```typescript
import { CryptoCrimeHunter } from '@apollo/cyberspike-villager';

const hunter = new CryptoCrimeHunter();

// Full investigation
const results = await hunter.investigate(
  "suspect-exchange.com",
  "WARRANT-2026-001",
  "full"
);

// Transaction tracing
const transactions = await hunter.traceTransactions(
  "wallet-address",
  "bitcoin",
  "WARRANT-2026-001",
  5  // depth
);

// Vulnerability analysis
const vulns = await hunter.findVulnerabilities("target.com");
```

### Predator Hunting

```typescript
import { PredatorTracker } from '@apollo/cyberspike-villager';

const tracker = new PredatorTracker();

const results = await tracker.hunt({
  target: {
    username: "suspect_user",
    platform: "suspicious-site.com",
    authorization: "EMERGENCY-WARRANT-2026-001"
  },
  priority: "CRITICAL"
});

// Check urgent actions
if (results.urgentActions.length > 0) {
  console.log("⚠️  Immediate action required:");
  results.urgentActions.forEach(action => console.log(action));
}
```

---

## WebSocket API (Real-time Updates)

Connect to WebSocket for real-time task updates.

**Endpoint:** `ws://localhost:37695/ws`

**Events:**

- `task-created` - New task submitted
- `task-progress` - Task progress update
- `task-completed` - Task finished
- `evidence-collected` - New evidence
- `defense-detected` - Defense mechanism detected
- `adaptation-made` - AI adapted tactics

**Example:**

```typescript
const ws = new WebSocket('ws://localhost:37695/ws');

ws.on('task-progress', (data) => {
  console.log(`Task ${data.task_id}: ${data.progress}%`);
});

ws.on('evidence-collected', (data) => {
  console.log(`Evidence: ${data.type} - ${data.hash}`);
});
```

---

## Authentication

All requests require authorization token:

```bash
curl -X POST http://localhost:37695/task \
  -H "Authorization: Bearer WARRANT-2026-001" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

---

## Rate Limiting

- 100 requests per minute per IP
- 10 concurrent tasks per authorization

---

## Error Handling

**Error Response:**

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {}
}
```

**Error Codes:**

- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Task Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

---

## Examples

See `/examples/` directory for complete examples:

- `autonomous-investigation.ts` - Full autonomous investigation
- `crypto-exchange-compromise.ts` - Crypto crime investigation
- `predator-platform-access.ts` - Predator hunting
- `multi-stage-operation.ts` - Complex multi-phase operation
