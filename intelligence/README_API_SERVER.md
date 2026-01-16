# Apollo Intelligence Server - API Documentation

## Overview

The Apollo Intelligence Server is a comprehensive REST API platform providing advanced intelligence gathering and analysis capabilities across multiple domains:

- **OSINT** - Open Source Intelligence
- **Blockchain Intelligence** - Cryptocurrency analysis
- **SOCMINT** - Social Media Intelligence
- **GEOINT** - Geospatial Intelligence
- **Intelligence Fusion** - Multi-source analysis
- **Breach Intelligence** - Data breach analysis
- **Dark Web Intelligence** - Dark web monitoring

## Features

- 50+ REST API endpoints
- JWT & API key authentication
- Role-based access control (RBAC)
- Rate limiting with token bucket algorithm
- Automatic API documentation (Swagger/ReDoc)
- Request validation with Pydantic
- CORS support
- Comprehensive error handling
- Request/Response logging
- Production-ready deployment

## Architecture

```
intelligence/
├── api_server.py              # Main FastAPI application
├── config.py                  # Configuration management
├── dependencies.py            # Dependency injection
│
├── routes/                    # API route modules
│   ├── osint_routes.py       # OSINT endpoints
│   ├── blockchain_routes.py  # Blockchain endpoints
│   ├── socmint_routes.py     # Social media endpoints
│   ├── geoint_routes.py      # Geolocation endpoints
│   ├── fusion_routes.py      # Intelligence fusion
│   ├── breach_routes.py      # Breach database endpoints
│   └── darkweb_routes.py     # Dark web endpoints
│
├── middleware/                # Middleware components
│   ├── auth.py               # JWT authentication
│   └── rate_limiter.py       # Rate limiting
│
└── models/                    # Pydantic models
    ├── request_models.py     # Request schemas
    └── response_models.py    # Response schemas
```

## Quick Start

### Installation

```bash
cd intelligence/
pip install -r requirements.txt
```

### Configuration

Create a `.env` file:

```env
# Environment
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=INFO

# API Server
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_VERSION=v1

# Security
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=*
CORS_ORIGINS=*

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=apollo
POSTGRES_USER=apollo
POSTGRES_PASSWORD=changeme

# Cache
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Running the Server

```bash
# Development mode
python api_server.py

# Production mode with Uvicorn
uvicorn api_server:app --host 0.0.0.0 --port 8000 --workers 4

# With Docker
docker-compose up intelligence-api
```

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## Authentication

### JWT Token Authentication

1. Login to get JWT token:

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

2. Use token in requests:

```bash
curl -X POST "http://localhost:8000/api/v1/osint/username/search" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe"}'
```

### API Key Authentication

```bash
curl -X POST "http://localhost:8000/api/v1/osint/username/search" \
  -H "X-API-Key: apollo_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe"}'
```

## Endpoint Reference

### OSINT Endpoints

#### Username Search
```http
POST /api/v1/osint/username/search
```

Search username across 400+ platforms.

**Request:**
```json
{
  "username": "johndoe",
  "platforms": ["twitter", "instagram", "github"],
  "timeout": 30
}
```

**Response:**
```json
{
  "success": true,
  "username": "johndoe",
  "total_platforms_checked": 400,
  "platforms_found": 25,
  "results": [
    {
      "platform": "github",
      "url": "https://github.com/johndoe",
      "status": "found",
      "confidence_score": 0.95
    }
  ]
}
```

#### Email Intelligence
```http
POST /api/v1/osint/email/intelligence
```

Comprehensive email address investigation.

#### Phone Lookup
```http
POST /api/v1/osint/phone/lookup
```

Phone number intelligence and location.

#### Domain Scan
```http
POST /api/v1/osint/domain/scan
```

Domain reconnaissance and security analysis.

#### Image Reverse Search
```http
POST /api/v1/osint/image/reverse-search
```

Reverse image search with EXIF extraction.

### Blockchain Endpoints

#### Wallet Information
```http
POST /api/v1/blockchain/wallet/info
```

Get wallet balance, transactions, and risk assessment.

**Request:**
```json
{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "blockchain": "bitcoin"
}
```

#### Transaction Trace
```http
POST /api/v1/blockchain/trace/funds
```

Trace cryptocurrency through transaction graph.

#### Wallet Clustering
```http
POST /api/v1/blockchain/cluster/analyze
```

Identify related wallet addresses.

#### Risk Assessment
```http
POST /api/v1/blockchain/risk/assess
```

Comprehensive risk scoring for addresses.

### SOCMINT Endpoints

#### Profile Aggregation
```http
POST /api/v1/socmint/profile/aggregate
```

Aggregate social media profiles across platforms.

#### Network Analysis
```http
POST /api/v1/socmint/network/analyze
```

Analyze social network connections.

#### Sentiment Analysis
```http
POST /api/v1/socmint/sentiment/analyze
```

Analyze sentiment of user posts.

### GEOINT Endpoints

#### IP Geolocation
```http
POST /api/v1/geoint/ip/geolocate
```

Geolocate IP address with detailed information.

**Request:**
```json
{
  "ip_address": "8.8.8.8"
}
```

#### Phone Location
```http
POST /api/v1/geoint/phone/location
```

Determine location from phone number.

#### Photo Geolocation
```http
POST /api/v1/geoint/photo/geolocate
```

Extract geolocation from photo EXIF data.

### Intelligence Fusion Endpoints

#### Fuse Intelligence
```http
POST /api/v1/fusion/intelligence/fuse
```

Combine intelligence from all sources.

**Request:**
```json
{
  "target": "johndoe",
  "target_type": "person",
  "sources": ["osint", "socmint", "blockchain"]
}
```

#### Build Profile
```http
POST /api/v1/fusion/profile/build
```

Build comprehensive target profile.

#### Risk Assessment
```http
POST /api/v1/fusion/risk/assess
```

Multi-factor risk assessment.

### Breach Intelligence Endpoints

#### Email Breach Search
```http
POST /api/v1/breach/email/search
```

Search email in breach databases.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "email": "user@example.com",
  "found_in_breaches": 3,
  "breaches": [
    {
      "name": "LinkedIn 2021",
      "date": "2021-06-15",
      "records": 700000000,
      "data_types": ["email", "name", "username"]
    }
  ]
}
```

#### Credentials Lookup
```http
POST /api/v1/breach/credentials/lookup
```

Search for compromised credentials.

#### Password Check
```http
POST /api/v1/breach/password/check
```

Check if password hash is compromised.

### Dark Web Endpoints

#### Marketplace Monitor
```http
POST /api/v1/darkweb/marketplace/monitor
```

Monitor dark web marketplaces for keywords.

#### Forum Scraping
```http
POST /api/v1/darkweb/forum/scrape
```

Scrape dark web forums for information.

#### Paste Monitor
```http
POST /api/v1/darkweb/paste/monitor
```

Monitor paste sites for sensitive data.

## Rate Limiting

Rate limits are enforced per user and per endpoint:

| Tier | Per Minute | Per Hour | Per Day |
|------|-----------|----------|---------|
| Free | 10 | 100 | 1,000 |
| Pro | 60 | 1,000 | 10,000 |
| Enterprise | 300 | 10,000 | 100,000 |

Rate limit headers in responses:
```
X-Rate-Limit-Remaining: 59
X-Rate-Limit-Limit: 60
Retry-After: 60
```

## Error Handling

All errors follow consistent format:

```json
{
  "error": {
    "code": 400,
    "message": "Invalid request parameters",
    "request_id": "req_1234567890"
  }
}
```

Common status codes:
- `200` - Success
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

## Deployment

### Docker Deployment

```bash
docker build -t apollo-intelligence-api .
docker run -p 8000:8000 --env-file .env apollo-intelligence-api
```

### Docker Compose

```yaml
services:
  intelligence-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DEBUG=false
    depends_on:
      - postgres
      - redis
```

### Production Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Configure `ALLOWED_HOSTS` and `CORS_ORIGINS`
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limiting
- [ ] Set up monitoring and logging
- [ ] Configure database backups
- [ ] Implement API key rotation
- [ ] Set up alerting for errors
- [ ] Load testing
- [ ] Security audit

## Performance

- Async/await for non-blocking I/O
- Connection pooling for databases
- Redis caching for frequent requests
- Background tasks with Celery
- Horizontal scaling with load balancer

## Monitoring

The API exposes monitoring endpoints:

```http
GET /health        # Health check
GET /metrics       # Prometheus metrics
```

## Testing

```bash
# Run tests
pytest tests/

# With coverage
pytest --cov=intelligence tests/

# Load testing
locust -f tests/load_test.py
```

## Security

- JWT tokens with expiration
- API key authentication
- Rate limiting per user
- Input validation with Pydantic
- SQL injection protection
- XSS prevention
- CORS configuration
- Audit logging

## Support

For issues and questions:
- GitHub Issues: https://github.com/apollo/intelligence/issues
- Documentation: http://docs.apollo-intelligence.com
- Email: support@apollo-intelligence.com

## License

Proprietary - All Rights Reserved

## Version

API Version: v1
Last Updated: 2026-01-14
