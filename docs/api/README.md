# Apollo Platform API Documentation

## Overview

This directory contains comprehensive API documentation for the Apollo Criminal Investigation Platform.

## Documentation Files

| File | Description |
|------|-------------|
| `../services/API_DOCUMENTATION.yaml` | Complete OpenAPI 3.0 specification |
| `apollo-postman-collection.json` | Postman collection with all endpoints |
| `apollo-postman-environment.json` | Postman environment variables |
| `API_VERSIONING.md` | API versioning guide and migration documentation |

## Quick Start

### Interactive Documentation (Swagger UI)

When the API Gateway is running, access interactive documentation at:

```
http://localhost:3000/api/docs
```

### OpenAPI Specification

Download the OpenAPI specification:

- **JSON Format**: `GET /api/openapi.json`
- **YAML Format**: `GET /api/openapi.yaml`

### Postman Collection

1. Import `apollo-postman-collection.json` into Postman
2. Import `apollo-postman-environment.json` as an environment
3. Select "Apollo Platform Environment"
4. Start with Authentication > Login to get tokens

## API Architecture

```
                    +------------------+
                    |   API Gateway    |
                    |   (Port 3000)    |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
+--------+-------+  +--------+-------+  +--------+-------+
| Authentication |  |   Operations   |  |  Intelligence  |
|    Service     |  |    Service     |  |    Service     |
+----------------+  +----------------+  +----------------+
         |                   |                   |
+--------+-------+  +--------+-------+  +--------+-------+
|     Search     |  |   Analytics    |  | Notifications  |
|    Service     |  |    Service     |  |    Service     |
+----------------+  +----------------+  +----------------+

                    +------------------+
                    | Intelligence     |
                    | Server (8000)    |
                    +--------+---------+
                             |
    +------------------------+------------------------+
    |           |            |            |           |
+-------+  +--------+  +---------+  +-------+  +------+
| OSINT |  |Blockchain| | Facial  |  | Voice |  |GEOINT|
+-------+  +--------+  +---------+  +-------+  +------+
```

## Authentication

### JWT Bearer Token (Recommended)

```bash
# Login to get tokens
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Use access token for requests
curl -X GET http://localhost:3000/api/operations \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### API Key

```bash
# Use API key for requests
curl -X GET http://localhost:3000/api/operations \
  -H "X-API-Key: YOUR_API_KEY"
```

## Rate Limiting

| Tier | Requests/Hour | Use Case |
|------|---------------|----------|
| Free | 100 | Development |
| Pro | 1,000 | Production |
| Enterprise | 10,000 | High-volume |

Rate limit headers included in responses:
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Time until limit resets

## Error Responses

All errors follow a consistent format:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "request_id": "req_abc123"
  }
}
```

### Common Error Codes

| HTTP Code | Error Code | Description |
|-----------|------------|-------------|
| 400 | VALIDATION_ERROR | Invalid request parameters |
| 401 | UNAUTHORIZED | Missing or invalid authentication |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |

## Endpoint Categories

### Node.js Microservices

| Category | Base Path | Description |
|----------|-----------|-------------|
| Authentication | `/api/auth/*` | Login, register, MFA, sessions |
| Users | `/api/users/*` | User management |
| Operations | `/api/operations/*` | Operation CRUD, team management |
| Intelligence | `/api/intelligence/*` | Intelligence reports |
| Search | `/api/search/*` | Full-text search |
| Analytics | `/api/analytics/*` | Metrics and dashboards |
| Notifications | `/api/notifications/*` | User notifications |
| Alerts | `/api/alerts/*` | System alerts |

### Python Intelligence Server

| Category | Base Path | Description |
|----------|-----------|-------------|
| OSINT | `/api/v1/osint/*` | Username, email, phone, domain |
| Blockchain | `/api/v1/blockchain/*` | Wallet info, tracing, risk |
| Facial | `/api/v1/facial/*` | Face search, compare, enroll |
| Voice | `/api/v1/voice/*` | Transcribe, identify, diarize |
| GEOINT | `/api/v1/geoint/*` | IP, phone, photo geolocation |
| SOCMINT | `/api/v1/socmint/*` | Social media analysis |
| Fusion | `/api/v1/fusion/*` | Intelligence correlation |
| Breach | `/api/v1/breach/*` | Breach database search |
| Dark Web | `/api/v1/darkweb/*` | Dark web monitoring |

## Development

### Generating Client SDKs

Use OpenAPI Generator to create client libraries:

```bash
# Install OpenAPI Generator
npm install @openapitools/openapi-generator-cli -g

# Generate Python client
openapi-generator-cli generate \
  -i services/API_DOCUMENTATION.yaml \
  -g python \
  -o ./sdks/python

# Generate TypeScript client
openapi-generator-cli generate \
  -i services/API_DOCUMENTATION.yaml \
  -g typescript-axios \
  -o ./sdks/typescript
```

### Validating OpenAPI Spec

```bash
# Install spectral
npm install -g @stoplight/spectral-cli

# Validate spec
spectral lint services/API_DOCUMENTATION.yaml
```

## Support

- **Interactive Docs**: http://localhost:3000/api/docs
- **Status Page**: https://status.apollo-platform.com
- **Support**: api-support@apollo-platform.com
