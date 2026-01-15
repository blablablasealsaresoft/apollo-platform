# Apollo Intelligence Platform
## Comprehensive Intelligence & OSINT Integration

> Elite-level intelligence gathering system integrating 1,686+ external tools and APIs

---

## Overview

The Apollo Intelligence Platform is a comprehensive intelligence gathering and analysis system that integrates:

- **400+ Social Media Platforms** (Sherlock OSINT)
- **50+ Blockchain APIs** (Bitcoin, Ethereum, BSC, Polygon, etc.)
- **1,000+ Public APIs** (Orchestrated with rate limiting)
- **Advanced OSINT Tools** (BBOT, subdomain enumeration, tech detection)
- **Breach Databases** (DeHashed, Have I Been Pwned)
- **Dark Web Intelligence** (Tor monitoring, paste sites)
- **Geolocation Intelligence** (IP, phone, WHOIS, DNS)
- **Social Media Intelligence** (Twitter, Facebook, LinkedIn, TikTok)
- **Public Records Search**
- **Intelligence Fusion Engine** (Correlation, scoring, entity resolution)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI REST API                         │
│                   (Port 8000)                               │
└────────────┬────────────────────────────────────────────────┘
             │
     ┌───────┴───────────────────────────────────┐
     │                                           │
┌────▼─────┐  ┌──────────┐  ┌──────────┐  ┌────▼─────┐
│ Sherlock │  │   BBOT   │  │Blockchain│  │  Fusion  │
│  Engine  │  │  Engine  │  │  Intel   │  │  Engine  │
└────┬─────┘  └─────┬────┘  └────┬─────┘  └────┬─────┘
     │              │             │             │
     └──────────────┴─────────────┴─────────────┘
                    │
          ┌─────────┴─────────┐
          │                   │
     ┌────▼────┐      ┌───────▼────┐
     │  Redis  │      │Elasticsearch│
     │ Cache   │      │   Storage   │
     └─────────┘      └────────────┘
```

---

## Features

### 1. Sherlock OSINT Integration
- Search usernames across **400+ social media platforms**
- Batch username searches
- Confidence scoring
- Results stored in Elasticsearch
- Export to JSON, CSV, Markdown

**Supported Platforms:**
- Instagram, Twitter, Facebook, LinkedIn, TikTok, Snapchat
- YouTube, Reddit, Pinterest, Tumblr
- GitHub, GitLab, Bitbucket, Stack Overflow
- Steam, Twitch, PlayStation, Xbox, Discord
- VKontakte, Odnoklassniki (Russian)
- Weibo, Douban (Chinese)
- And 380+ more...

### 2. BBOT (Reconnaissance)
- **Subdomain Enumeration**: CertSpotter, crt.sh, VirusTotal, HackerTarget
- **Port Scanning**: Async port scanning across discovered IPs
- **Technology Detection**: Web frameworks, CMS, servers
- **Vulnerability Scanning**: SSL/TLS checks, security headers

### 3. Blockchain Intelligence
- **50+ Blockchain APIs**
- Bitcoin: blockchain.info, blockchair, blockcypher
- Ethereum: etherscan, ethplorer
- Multi-chain: BSC, Polygon, Avalanche, Fantom, Arbitrum
- Wallet analysis and transaction tracing
- Fund flow visualization
- Multi-hop transaction tracking

### 4. API Orchestration
- **1,000+ Public APIs** managed centrally
- **Rate Limiting**: Token bucket algorithm per API
- **Circuit Breaker**: Automatic failover on errors
- **Response Caching**: Redis-based caching with TTL
- **Retry Logic**: Exponential backoff
- **API Key Rotation**: Support for multiple auth methods

### 5. Intelligence Fusion Engine
- **Entity Resolution**: Merge duplicate entities
- **Correlation Algorithm**: Find relationships across data sources
- **Confidence Scoring**: Weighted scoring system
- **Risk Assessment**: Multi-factor risk calculation
- **Timeline Generation**: Chronological event ordering
- **Deduplication**: Advanced fuzzy matching

---

## Installation

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- 8GB RAM minimum
- 50GB disk space

### Quick Start

1. **Clone Repository**
```bash
cd apollo/intelligence
```

2. **Set Environment Variables**
```bash
cp .env.example .env
# Edit .env with your API keys
```

3. **Start Services**
```bash
docker-compose up -d
```

4. **Verify Installation**
```bash
curl http://localhost:8000/health
```

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start services
uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
```

---

## API Configuration

### Required API Keys

Create a `.env` file with:

```env
# Shodan
SHODAN_API_KEY=your_shodan_key

# Censys
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# VirusTotal
VIRUSTOTAL_API_KEY=your_virustotal_key

# DeHashed
DEHASHED_API_KEY=your_dehashed_key
DEHASHED_EMAIL=your_email

# Have I Been Pwned
HIBP_API_KEY=your_hibp_key

# Blockchain APIs
ETHERSCAN_API_KEY=your_etherscan_key
BSCSCAN_API_KEY=your_bscscan_key
POLYGONSCAN_API_KEY=your_polygonscan_key

# Twitter/X
TWITTER_BEARER_TOKEN=your_twitter_token

# Elasticsearch
ELASTICSEARCH_HOSTS=http://localhost:9200

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# RabbitMQ
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
```

---

## API Usage

### Health Check
```bash
GET /health
```

### Username Search
```bash
POST /api/v1/osint/username/search
Content-Type: application/json

{
  "username": "johndoe",
  "platforms": ["Instagram", "Twitter", "GitHub"]
}
```

### Batch Username Search
```bash
POST /api/v1/osint/username/batch-search
Content-Type: application/json

{
  "usernames": ["johndoe", "janedoe", "target123"],
  "platforms": null
}
```

### Domain Reconnaissance
```bash
POST /api/v1/osint/domain/scan
Content-Type: application/json

{
  "domain": "example.com",
  "scan_types": ["subdomain", "port", "tech", "vuln"]
}
```

### Blockchain Wallet Info
```bash
POST /api/v1/blockchain/wallet/info
Content-Type: application/json

{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "blockchain": "bitcoin"
}
```

### Fund Tracing
```bash
POST /api/v1/blockchain/trace/funds
Content-Type: application/json

{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "blockchain": "bitcoin",
  "max_hops": 5,
  "min_amount": 0.1
}
```

### Intelligence Fusion
```bash
POST /api/v1/fusion/intelligence
Content-Type: application/json

{
  "target": "ruja.ignatova@onecoin.eu",
  "target_type": "person",
  "sources": ["sherlock", "blockchain", "breach_databases"]
}
```

---

## Celery Tasks (Async Processing)

### Start Celery Worker
```bash
celery -A celery_tasks worker --loglevel=info --concurrency=4
```

### Start Celery Beat (Scheduler)
```bash
celery -A celery_tasks beat --loglevel=info
```

### Monitor with Flower
```bash
celery -A celery_tasks flower --port=5555
```
Then visit: http://localhost:5555

### Submit Async Task
```python
from celery_tasks import search_username_task

result = search_username_task.delay("johndoe", None)
print(f"Task ID: {result.id}")

# Check result
print(result.get(timeout=300))
```

---

## Testing

### Unit Tests
```bash
pytest tests/ -v
```

### Integration Tests
```bash
pytest tests/integration/ -v
```

### Coverage Report
```bash
pytest --cov=. --cov-report=html
```

---

## Performance

### Benchmarks
- **Username Search**: 400 platforms in ~30 seconds
- **Domain Scan**: Average 2-5 minutes for comprehensive scan
- **Blockchain Query**: <1 second per wallet
- **API Orchestration**: 1000 req/min sustained throughput
- **Fusion Engine**: Process 100K entities in ~60 seconds

### Scaling
- Horizontal scaling via Docker Compose replicas
- Celery workers scale independently
- Redis cluster for high availability
- Elasticsearch sharding for large datasets

---

## Security

### Best Practices
- All API keys stored in environment variables
- No credentials in code or logs
- Rate limiting on all endpoints
- Input validation and sanitization
- HTTPS enforced in production
- Regular dependency updates

### Compliance
- Respects robots.txt
- Rate limiting per API provider
- Data retention policies
- GDPR compliance considerations
- Audit logging

---

## Monitoring

### Elasticsearch Indices
```bash
# Check Sherlock results
curl http://localhost:9200/apollo-sherlock-results/_count

# Check fusion intelligence
curl http://localhost:9200/apollo-fusion-intelligence/_count
```

### Redis Statistics
```bash
redis-cli info stats
```

### Celery Queue Status
```bash
celery -A celery_tasks inspect active
celery -A celery_tasks inspect scheduled
```

---

## Troubleshooting

### Common Issues

**Elasticsearch connection failed**
```bash
# Check if Elasticsearch is running
docker ps | grep elasticsearch
docker logs apollo-elasticsearch
```

**Redis connection timeout**
```bash
# Test Redis connectivity
redis-cli ping
```

**Rate limiting errors**
```bash
# Check API rate limits in Redis
redis-cli keys "rate_limit:*"
```

**Celery tasks not executing**
```bash
# Check RabbitMQ
docker logs apollo-rabbitmq
# Restart worker
docker-compose restart celery-worker
```

---

## Development

### Project Structure
```
intelligence/
├── osint-tools/
│   ├── sherlock/         # Username search
│   └── bbot/             # Reconnaissance
├── blockchain-intelligence/
│   ├── bitcoin_tracker.py
│   ├── ethereum_tracker.py
│   └── wallet_clustering.py
├── fusion-engine/        # Intelligence correlation
├── api-orchestrator/     # API management
├── api_server.py         # FastAPI application
├── celery_tasks.py       # Async tasks
├── requirements.txt      # Dependencies
├── Dockerfile           # API container
├── Dockerfile.celery    # Worker container
└── docker-compose.yml   # Full stack
```

### Adding New Intelligence Sources

1. Create module in appropriate directory
2. Implement async collection methods
3. Add to fusion engine data sources
4. Create FastAPI endpoint
5. Add Celery task if needed
6. Write tests
7. Update documentation

---

## License

Proprietary - Apollo Platform
For authorized use only

---

## Support

For issues and questions:
- Create GitHub issue
- Check documentation
- Review logs: `docker-compose logs -f`

---

## Roadmap

- [ ] Machine learning entity resolution
- [ ] Real-time threat intelligence feeds
- [ ] Advanced graph visualization
- [ ] Mobile app integration
- [ ] Automated report generation
- [ ] Multi-language support
- [ ] Enhanced dark web monitoring
- [ ] AI-powered correlation

---

**Built for the Apollo Platform**
**Elite Intelligence. Unparalleled Coverage.**
