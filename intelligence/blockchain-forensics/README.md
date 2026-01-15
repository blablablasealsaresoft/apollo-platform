# Apollo Blockchain Forensics Platform

Advanced blockchain analysis and cryptocurrency tracking for elite-level investigations. Built specifically for tracking the $4 billion OneCoin fraud and identifying Ruja Ignatova's cryptocurrency wallets.

## Overview

The Apollo Blockchain Forensics Platform provides comprehensive tools for:

- **OneCoin Tracking**: Track OneCoin fund movements, identify Ruja Ignatova wallets, detect money laundering paths
- **Wallet Clustering**: Group addresses controlled by the same entity using advanced heuristics
- **Transaction Tracing**: Multi-hop transaction tracing across blockchains
- **Exchange Surveillance**: Monitor 50+ exchanges for deposit/withdrawal tracking
- **AML Scoring**: Calculate risk scores (0-100) for compliance
- **Real-time Monitoring**: Watch list with instant alerts

## Features

### 1. OneCoin Investigation Suite

#### Ruja Ignatova Wallet Identification
```python
from blockchain_forensics.onecoin import RujaWalletIdentifier

identifier = RujaWalletIdentifier(db, api, graph)
wallets = await identifier.identify_ruja_wallets(min_confidence=0.7)

for wallet in wallets:
    print(f"Address: {wallet['address']}")
    print(f"Confidence: {wallet['confidence']:.2%}")
    print(f"Total Value: ${wallet['total_value']:,.2f}")
```

#### Fund Flow Tracking
```python
from blockchain_forensics.onecoin import FundFlowAnalyzer

analyzer = FundFlowAnalyzer(db, api, graph)
flows = await analyzer.trace_fund_flow(
    source_address="1RujaWalletAddress...",
    max_hops=10
)

# Analyze patterns
analysis = await analyzer.analyze_flow_patterns(flows)
print(f"Total flows: {analysis['total_flows']}")
print(f"Total amount: ${analysis['total_amount_usd']:,.2f}")
```

#### OneCoin Tracker
```python
from blockchain_forensics.onecoin import OneCoinTracker

tracker = OneCoinTracker(db, api, graph)
result = await tracker.track_address(
    address="1SuspectAddress...",
    blockchain="btc",
    depth=5
)

print(f"OneCoin Confidence: {result['onecoin_confidence']:.2%}")
print(f"Suspicious Patterns: {result['suspicious_patterns']}")
print(f"Exchange Deposits: {len(result['exchange_deposits'])}")
```

### 2. Wallet Clustering

Group addresses likely controlled by the same entity:

```python
from blockchain_forensics.clustering import WalletClusteringEngine

engine = WalletClusteringEngine(db, api, graph)

# Cluster addresses
clusters = await engine.cluster_addresses(
    addresses=["1Address1...", "1Address2...", ...],
    blockchain="btc",
    min_confidence=0.7
)

for cluster in clusters:
    print(f"Cluster: {cluster.cluster_id}")
    print(f"  Addresses: {len(cluster.addresses)}")
    print(f"  Confidence: {cluster.confidence:.2%}")
    print(f"  Evidence: {cluster.evidence}")
```

#### Clustering Heuristics

1. **Common Input Ownership**: Addresses used as inputs in same transaction
2. **Change Address Detection**: Identify change addresses
3. **Co-spending Analysis**: Addresses that frequently spend together
4. **Peel Chain Detection**: Long chains of transactions with specific patterns

### 3. Multi-Blockchain API Integration

Unified interface for 50+ blockchain explorers:

#### Bitcoin APIs
- blockchain.info
- blockchair.com
- blockcypher.com
- btc.com

#### Ethereum APIs
- etherscan.io
- ethplorer.io
- alchemy.com

#### Multi-Chain APIs
- bscscan.com (Binance Smart Chain)
- polygonscan.com (Polygon)
- snowtrace.io (Avalanche)
- solscan.io (Solana)
- cardanoscan.io (Cardano)

```python
from blockchain_forensics.api_clients import BlockchainAPIManager

api = BlockchainAPIManager(config)
await api.initialize()

# Get transactions (automatically selects best API)
txs = await api.get_address_transactions(
    address="1Address...",
    blockchain="btc",
    limit=100
)

# Get transaction details
tx = await api.get_transaction(txid="abc123...", blockchain="btc")

# Get balance
balance = await api.get_address_balance(address="1Address...", blockchain="btc")
```

### 4. AML (Anti-Money Laundering) Scoring

Calculate risk scores (0-100) for compliance:

```python
from blockchain_forensics.aml import AMLScoringEngine

aml = AMLScoringEngine(db, api, config)

# Score an address
score = await aml.calculate_risk_score(
    address="1Address...",
    blockchain="btc"
)

print(f"Risk Score: {score.total_score}/100")
print(f"Risk Level: {score.risk_level}")  # low, medium, high, critical
print(f"Red Flags: {score.red_flags}")

# Generate compliance report
report = await aml.generate_compliance_report(
    address="1Address...",
    blockchain="btc"
)
```

#### Risk Scoring Factors

- **Known Bad Actors** (40 points): Connections to criminal addresses
- **Mixer Usage** (25 points): Use of tumblers/mixers
- **Suspicious Patterns** (20 points): Structuring, round amounts, velocity
- **Volume/Velocity** (10 points): Transaction frequency and amount
- **Sanctioned Entities** (Auto-100): OFAC/UN sanctions lists
- **Exchange Usage** (-5 points): Reduces risk for regulated exchanges
- **Address Age** (-3 points): Older addresses are less risky

### 5. Real-time Monitoring

Monitor addresses in real-time with alerts:

```python
from blockchain_forensics.monitoring import BlockchainMonitor

monitor = BlockchainMonitor(db, api, alerts, config)

# Add addresses to watch list
await monitor.add_address(
    address="1RujaAddress...",
    blockchain="btc",
    tags=["onecoin", "ruja", "high-priority"],
    alert_threshold_usd=10000  # Alert on txs > $10k
)

# Start monitoring (checks every 60 seconds)
await monitor.start_monitoring(interval_seconds=60)

# Register alert callback
async def on_alert(alert):
    print(f"ALERT: {alert.alert_type}")
    print(f"  Amount: ${alert.amount_usd:,.2f}")
    print(f"  Severity: {alert.severity}")

monitor.register_alert_callback(on_alert)
```

## Installation

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- 8GB+ RAM (for graph databases)

### Quick Start

1. **Clone the repository**
```bash
cd apollo/intelligence/blockchain-forensics
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your API keys and database credentials
```

4. **Start with Docker Compose**
```bash
docker-compose up -d
```

This starts:
- FastAPI application (port 8000)
- TimescaleDB (port 5432)
- Neo4j (ports 7474, 7687)
- Redis (port 6379)
- Elasticsearch (port 9200)
- Celery workers
- Flower monitoring (port 5555)

5. **Access the API**
```bash
curl http://localhost:8000/api/v1/health
```

## Environment Variables

Create a `.env` file with:

```bash
# Database
TIMESCALEDB_HOST=localhost
TIMESCALEDB_PORT=5432
TIMESCALEDB_USER=apollo
TIMESCALEDB_PASSWORD=your_password
TIMESCALEDB_DB=apollo_blockchain

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Elasticsearch
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200

# API Keys (optional but recommended)
BLOCKCHAIN_INFO_API_KEY=
BLOCKCYPHER_API_KEY=
ETHERSCAN_API_KEY=
BSCSCAN_API_KEY=
POLYGONSCAN_API_KEY=
SNOWTRACE_API_KEY=
ALCHEMY_API_KEY=

# Rate Limiting
API_RATE_LIMIT=5  # requests per second
CACHE_TTL=3600  # cache time-to-live in seconds

# Monitoring
ALERT_WEBHOOK_URL=https://your-webhook-url
MONITORING_ENABLED=true

# AML Settings
AML_HIGH_RISK_THRESHOLD=70
AML_MEDIUM_RISK_THRESHOLD=40
```

## API Endpoints

### OneCoin Tracking

```bash
# Track an address for OneCoin connections
POST /api/v1/onecoin/track
{
  "address": "1Address...",
  "blockchain": "btc",
  "depth": 3
}

# Identify Ruja Ignatova wallets
GET /api/v1/onecoin/ruja-wallets?min_confidence=0.7&limit=50

# Trace fund flow
POST /api/v1/onecoin/fund-flow
{
  "address": "1SourceAddress...",
  "blockchain": "btc",
  "depth": 10
}
```

### Wallet Clustering

```bash
# Cluster addresses
POST /api/v1/clustering/cluster
{
  "addresses": ["1Addr1...", "1Addr2...", ...],
  "blockchain": "btc",
  "min_confidence": 0.7
}

# Get cluster details
GET /api/v1/clustering/cluster/{cluster_id}
```

### Wallet Analysis

```bash
# Analyze a wallet
POST /api/v1/analysis/wallet
{
  "address": "1Address...",
  "blockchain": "btc"
}

# Compare two wallets
GET /api/v1/analysis/compare?address1=1Addr1...&address2=1Addr2...&blockchain=btc
```

### Transactions

```bash
# Get address transactions
GET /api/v1/transactions/address/{address}?blockchain=btc&limit=100

# Get transaction details
GET /api/v1/transactions/{txid}?blockchain=btc
```

### System

```bash
# Health check
GET /api/v1/health

# API statistics
GET /api/v1/stats
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Application                      │
│                         (Port 8000)                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │      Blockchain Forensics Modules       │
        ├─────────────────────────────────────────┤
        │  • OneCoin Tracker                      │
        │  • Wallet Clustering Engine             │
        │  • Fund Flow Analyzer                   │
        │  • AML Scoring Engine                   │
        │  • Real-time Monitor                    │
        └─────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
     ┌──────────────┐  ┌───────────┐  ┌────────────┐
     │ TimescaleDB  │  │   Neo4j   │  │   Redis    │
     │(Transactions)│  │  (Graph)  │  │  (Cache)   │
     └──────────────┘  └───────────┘  └────────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │   API Manager         │
                  │  (50+ Explorers)      │
                  ├───────────────────────┤
                  │ • Bitcoin APIs        │
                  │ • Ethereum APIs       │
                  │ • Multi-chain APIs    │
                  └───────────────────────┘
```

## OneCoin Investigation Guide

### Step 1: Identify Seed Addresses

Start with known OneCoin-related addresses:

```python
# Known addresses from public investigations
seed_addresses = [
    "1OneCoinAddress1...",
    "1OneCoinAddress2...",
    # Add more from investigations
]

# Track each address
for addr in seed_addresses:
    result = await tracker.track_address(addr, depth=5)
    if result['onecoin_confidence'] > 0.8:
        print(f"High confidence: {addr}")
```

### Step 2: Identify Ruja's Wallets

```python
# Use advanced heuristics
ruja_wallets = await identifier.identify_ruja_wallets(
    min_confidence=0.7
)

# Cluster related wallets
cluster = await identifier.cluster_ruja_wallets(
    seed_addresses=[w['address'] for w in ruja_wallets]
)

print(f"Found {len(cluster['cluster_members'])} related wallets")
print(f"Total value: ${cluster['total_value']:,.2f}")
```

### Step 3: Trace Fund Flows

```python
# Trace where the money went
for wallet in ruja_wallets[:10]:  # Top 10
    flows = await analyzer.trace_fund_flow(
        source_address=wallet['address'],
        max_hops=10,
        min_amount_usd=10000
    )

    # Identify cash-out points
    consolidation = await analyzer.identify_consolidation_points(flows)

    for point in consolidation:
        if point['type'].startswith('exchange:'):
            print(f"Exchange cash-out: {point['type']}")
            print(f"  Amount: ${point['total_amount_usd']:,.2f}")
```

### Step 4: Generate Investigation Report

```python
# Comprehensive report
report = await tracker.generate_investigation_report(
    addresses=cluster['cluster_members'],
    include_timeline=True,
    include_network_graph=True
)

# Export for law enforcement
with open('onecoin_investigation_report.json', 'w') as f:
    json.dump(report, f, indent=2)
```

## Testing

Run the test suite:

```bash
# All tests
pytest

# With coverage
pytest --cov=blockchain_forensics --cov-report=html

# Specific module
pytest tests/test_onecoin.py

# Verbose output
pytest -v
```

## Performance

- **API Rate Limiting**: 5 requests/second per API (configurable)
- **Caching**: 1-hour TTL for transaction data
- **Concurrent Processing**: Async/await for parallel API calls
- **Database Indexing**: Optimized queries for TimescaleDB and Neo4j

## Security

- **API Key Rotation**: Multiple keys per service
- **Rate Limiting**: Prevents API abuse
- **Data Encryption**: Sensitive data encrypted at rest
- **Access Control**: Role-based access to endpoints

## Troubleshooting

### API Rate Limiting

If you encounter rate limits:
```python
# Increase rate limit interval
config.API_RATE_LIMIT = 2  # 2 requests per second instead of 5

# Add more API keys for rotation
config.BLOCKCYPHER_API_KEY = "key1,key2,key3"
```

### Database Connection Issues

```bash
# Check TimescaleDB
docker-compose logs timescaledb

# Check Neo4j
docker-compose logs neo4j

# Restart services
docker-compose restart
```

### Memory Issues

For large-scale analysis:
```python
# Process in batches
addresses = [...]  # Large list
batch_size = 100

for i in range(0, len(addresses), batch_size):
    batch = addresses[i:i+batch_size]
    results = await process_batch(batch)
```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../../LICENSE) for details.

## Disclaimer

This tool is for legitimate investigative and compliance purposes only. Users must comply with all applicable laws and regulations regarding cryptocurrency tracking and data privacy.

## Support

For issues and questions:
- GitHub Issues: [Apollo Issues](https://github.com/your-org/apollo/issues)
- Documentation: [Full Docs](../../docs/)
- Contact: apollo-support@your-org.com

---

**Built for the Apollo Platform by Agent 4: Blockchain & Cryptocurrency Forensics**

Track the untraceable. Find Ruja Ignatova.
