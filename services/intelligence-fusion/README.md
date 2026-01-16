# Intelligence Fusion Service

Multi-source intelligence correlation and analysis engine for the Apollo platform.

## Overview

The Intelligence Fusion Service aggregates, correlates, and analyzes data from multiple intelligence sources including:

- **OSINT** - Open Source Intelligence (social media, news, public records)
- **SIGINT** - Signals Intelligence (communications metadata)
- **GEOINT** - Geospatial Intelligence (locations, movement patterns)
- **FININT** - Financial Intelligence (transactions, accounts)
- **Blockchain** - Cryptocurrency wallet and transaction analysis
- **Breach Data** - Compromised credential databases
- **SOCMINT** - Social Media Intelligence (platform presence)

## Features

### Entity Resolution
- Fuzzy name matching with configurable thresholds
- Email and phone normalization
- ID matching (passport, SSN, etc.)
- Biometric matching integration
- Confidence scoring for matches

### Correlation Engine
- Link entities across disparate sources
- Identify relationships and connection types
- Calculate relationship strength
- Temporal correlation analysis
- Attribute overlap detection

### Graph Analysis (Neo4j Integration)
- Network visualization
- Community detection (label propagation)
- Centrality metrics (degree, betweenness, closeness, eigenvector)
- Shortest path finding
- Link prediction

### Timeline Builder
- Chronological event ordering
- Event clustering and gap detection
- Activity pattern detection
- Anomaly identification

### Risk Assessment
- Multi-factor risk scoring
- Behavioral pattern analysis
- Geographic risk factors
- Known threat indicators
- Automated recommendations

## API Endpoints

### Main Fusion
```
POST /api/v1/fusion/fuse
POST /api/v1/fusion/analyze
```

### Correlation
```
POST /api/v1/fusion/correlate
```

### Entity Resolution
```
POST /api/v1/fusion/resolve
```

### Graph Operations
```
GET  /api/v1/fusion/graph/:entityId
GET  /api/v1/fusion/graph/:entityId/path/:targetId
GET  /api/v1/fusion/graph/:entityId/predictions
POST /api/v1/fusion/graph/hydrate
GET  /api/v1/fusion/graph/export
DELETE /api/v1/fusion/graph
```

### Timeline
```
GET  /api/v1/fusion/timeline/:targetId
POST /api/v1/fusion/timeline/build
```

### Risk Assessment
```
POST /api/v1/fusion/assess-risk
```

## Quick Start

### Installation
```bash
npm install
```

### Development
```bash
npm run dev
```

### Production Build
```bash
npm run build
npm start
```

### Docker
```bash
docker build -t apollo/intelligence-fusion .
docker run -p 3008:3008 apollo/intelligence-fusion
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| FUSION_SERVICE_PORT | Service port | 3008 |
| NEO4J_URI | Neo4j connection URI | bolt://localhost:7687 |
| NEO4J_USER | Neo4j username | neo4j |
| NEO4J_PASSWORD | Neo4j password | password |
| NODE_ENV | Environment | development |

## Example Usage

### Run Full Fusion
```bash
curl -X POST http://localhost:3008/api/v1/fusion/fuse \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example@email.com",
    "sources": [
      {
        "sourceType": "breach",
        "data": {
          "email": "example@email.com",
          "name": "John Doe",
          "breach": "LinkedIn 2021"
        }
      },
      {
        "sourceType": "blockchain",
        "data": {
          "wallet": "0x1234567890abcdef",
          "owner_email": "example@email.com",
          "transactions": 150
        }
      }
    ],
    "options": {
      "deepAnalysis": true,
      "includeTimeline": true,
      "includeRiskAssessment": true
    }
  }'
```

### Assess Risk
```bash
curl -X POST http://localhost:3008/api/v1/fusion/assess-risk \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example@email.com",
    "sources": [
      {
        "sourceType": "breach",
        "data": {
          "email": "example@email.com",
          "breach": "Collection #1"
        }
      }
    ]
  }'
```

### Get Entity Graph
```bash
curl http://localhost:3008/api/v1/fusion/graph/entity_abc123?maxDepth=2
```

## Architecture

```
intelligence-fusion/
├── src/
│   ├── algorithms/
│   │   └── fusion_engine.ts     # Core fusion algorithms
│   ├── controllers/
│   │   └── fusion.controller.ts # API request handlers
│   ├── processors/
│   │   └── ingest.processor.ts  # Data ingestion & normalization
│   ├── services/
│   │   └── graph.service.ts     # Neo4j graph operations
│   ├── routes/
│   │   └── fusion.routes.ts     # API route definitions
│   ├── middleware/
│   │   └── error.middleware.ts  # Error handling
│   └── index.ts                 # Service entry point
├── package.json
├── tsconfig.json
└── Dockerfile
```

## Source Type Weights

| Source Type | Reliability |
|-------------|-------------|
| Blockchain  | 0.95 |
| SIGINT      | 0.90 |
| FININT      | 0.90 |
| GEOINT      | 0.85 |
| Breach      | 0.85 |
| Sherlock    | 0.80 |
| SOCMINT     | 0.75 |
| OSINT       | 0.70 |
| HUMINT      | 0.65 |

## Risk Categories

| Score Range | Category |
|-------------|----------|
| 90-100      | CRITICAL |
| 75-89       | HIGH     |
| 50-74       | MEDIUM   |
| 25-49       | LOW      |
| 0-24        | MINIMAL  |

## License

MIT
