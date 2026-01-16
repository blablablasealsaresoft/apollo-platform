# Apollo Platform - Development Environment

This directory contains all configuration files for the development environment.

## Quick Start

1. **Copy environment file:**
   ```bash
   cp .env.development ../../.env
   ```

2. **Update API keys:**
   Edit `.env.development` and add your API keys for:
   - OpenRouter / OpenAI / Anthropic (AI models)
   - Shodan / DeHashed / Hunter.io (OSINT)
   - Etherscan / Blockchain.com (Blockchain)
   - Twitter / Social media APIs

3. **Start databases:**
   ```bash
   docker-compose -f ../docker/docker-compose.dev.yml up -d
   ```

4. **Run setup script:**
   ```bash
   ../scripts/setup-dev.sh
   ```

## Configuration Files

### `.env.development`
Main environment variables including:
- Database connection strings
- API keys and secrets
- Feature flags
- Development-specific settings

### `database.yaml`
Database configuration for:
- PostgreSQL (primary relational database)
- Neo4j (graph database)
- Redis (cache)
- Elasticsearch (search)
- MongoDB (document store)
- RabbitMQ (message queue)
- TimescaleDB (time-series)

### `services.yaml`
Service configuration for:
- Backend microservices (8 services)
- Frontend application
- Surveillance components
- AI engine services
- External integrations
- Message queue workers

### `ai-models.yaml`
AI model configuration for:
- Model providers (OpenRouter, OpenAI, Anthropic, Google, DeepSeek, Groq)
- Routing strategies
- Use case specific configurations
- Prompt templates
- Cost management

### `integrations.yaml`
External integration configuration for:
- OSINT tools (Shodan, DeHashed, HIBP, Hunter.io, VirusTotal)
- Blockchain APIs (Etherscan, Blockchain.com, CoinGecko)
- Social media (Twitter, Reddit)
- Communication services (Email, Slack, Discord)
- Security tools (Metasploit, Nmap)
- Monitoring (Prometheus, Grafana, Sentry)

## Development Features

### Enabled Features
- ✅ Hot reload
- ✅ Debug logging
- ✅ Query logging
- ✅ Source maps
- ✅ Dev tools
- ✅ Mock data (optional)

### Disabled Features
- ❌ MFA authentication
- ❌ Rate limiting
- ❌ SSL/TLS
- ❌ Production security hardening
- ❌ Physical camera feeds
- ❌ Dark web monitoring (requires Tor setup)

## Database Setup

The development environment uses Docker containers for all databases:

```bash
# Start all databases
docker-compose -f ../docker/docker-compose.dev.yml up -d

# Check status
docker-compose -f ../docker/docker-compose.dev.yml ps

# View logs
docker-compose -f ../docker/docker-compose.dev.yml logs -f

# Stop databases
docker-compose -f ../docker/docker-compose.dev.yml down
```

### Database Credentials (Development Only)

**PostgreSQL:**
- Host: localhost:5432
- Database: apollo_dev
- Username: apollo_admin
- Password: dev_password

**Neo4j:**
- URI: bolt://localhost:7687
- Username: neo4j
- Password: dev_neo4j_pass
- Browser: http://localhost:7474

**Redis:**
- Host: localhost:6379
- No password

**Elasticsearch:**
- URL: http://localhost:9200
- No authentication

**MongoDB:**
- URI: mongodb://localhost:27017
- Username: apollo
- Password: dev_mongo_pass

**RabbitMQ:**
- AMQP: amqp://localhost:5672
- Management UI: http://localhost:15672
- Username: apollo
- Password: dev_rabbit

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | React web application |
| API Gateway | 4000 | Main API endpoint |
| Authentication | 4001 | Auth service |
| Operations | 4002 | Case/task management |
| Intelligence Fusion | 4003 | Intelligence analysis |
| RedTeam Ops | 4004 | Security testing |
| Notifications | 4005 | Alert delivery |
| Alert Orchestration | 4006 | Alert routing |
| Audit Logging | 4007 | Compliance logging |
| Evidence Management | 4008 | Chain of custody |
| Facial Recognition | 5001 | Face detection/recognition |
| Voice Recognition | 5002 | Voice analysis |
| AI Model Router | 6001 | AI model routing |
| Swagger UI | 8080 | API documentation |
| Prometheus | 9090 | Metrics |
| Health Check | 9000 | Service health |

## AI Model Configuration

### Available Models

**High Quality (Expensive):**
- Claude 3 Opus - Deep analysis
- GPT-4 Turbo - General intelligence
- Gemini Pro 1.5 - Long context

**Balanced:**
- Claude 3 Sonnet - General use
- GPT-3.5 Turbo - Quick tasks

**Cost Optimized:**
- Claude 3 Haiku - Fast tasks
- DeepSeek - Code analysis
- Llama 3.1 70B (Groq) - Real-time

### Routing Strategies

The system automatically routes requests to optimal models based on:
- Task complexity
- Cost constraints
- Response time requirements
- Context length

## Surveillance Configuration

### Facial Recognition
- **Model:** HOG (CPU-based, fast)
- **GPU:** Disabled (use CPU for dev)
- **Threshold:** 0.6 (60% confidence)
- **Database:** `data/dev/face_database/`

### Voice Recognition
- **Sample Rate:** 16kHz
- **Threshold:** 0.75 (75% confidence)
- **Database:** `data/dev/voice_database/`

### Camera Feeds
- **Enabled:** No (no physical cameras in dev)
- **Mock Feeds:** Available for testing

## OSINT Integration

### Free Tier Limits

**Shodan:**
- 1 request/second
- 100 results per search

**DeHashed:**
- 10 requests/minute
- Requires subscription

**Have I Been Pwned:**
- 1,500 requests/day
- Requires API key

**Hunter.io:**
- 50 requests/month (free tier)
- 25 email verifications/month

**VirusTotal:**
- 4 requests/minute (free tier)
- 500 requests/day

## Security Notes

⚠️ **Important:** This is a development configuration. DO NOT use in production!

- All passwords are default/weak
- SSL/TLS is disabled
- Rate limiting is disabled
- Security features are relaxed
- Audit logging is minimal
- Data is not encrypted at rest

## Troubleshooting

### Database Connection Issues

```bash
# Check if databases are running
docker-compose -f ../docker/docker-compose.dev.yml ps

# Restart specific database
docker-compose -f ../docker/docker-compose.dev.yml restart postgres

# View database logs
docker-compose -f ../docker/docker-compose.dev.yml logs postgres
```

### Port Conflicts

If ports are already in use, update the port mappings in `docker-compose.dev.yml`.

### API Key Issues

Verify your API keys are correctly set in `.env.development`:
```bash
grep API_KEY .env.development
```

### Permission Issues

Ensure data directories exist and are writable:
```bash
mkdir -p c:/SECURE_THREAT_INTEL/YoureGunnaHAveToShootMeToStopME/apollo/data/{dev,uploads,temp,backups,evidence}
```

## Testing

### Test Data

The development environment includes test fixtures:
- Ignatova case data
- Sample users
- Sample surveillance events
- Financial transaction samples

### Running Tests

```bash
# Unit tests
npm run test

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# With coverage
npm run test:coverage
```

## Next Steps

1. Set up API keys in `.env.development`
2. Start databases with Docker Compose
3. Run database migrations
4. Seed initial data
5. Start development servers
6. Access web UI at http://localhost:3000

## Support

For development environment issues:
1. Check Docker container status
2. Verify environment variables
3. Review service logs
4. Check port availability
5. Consult main documentation
