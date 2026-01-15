# Apollo Platform API Documentation

> Complete REST API Reference for Apollo Platform

Version: 1.0.0
Last Updated: January 2026

---

## Table of Contents

1. [Authentication](#authentication)
2. [Operations Management](#operations-management)
3. [Intelligence Fusion](#intelligence-fusion)
4. [Surveillance](#surveillance)
5. [Blockchain Forensics](#blockchain-forensics)
6. [Red Team Operations](#red-team-operations)
7. [Alerts & Notifications](#alerts--notifications)
8. [Evidence Management](#evidence-management)
9. [Error Handling](#error-handling)
10. [Rate Limiting](#rate-limiting)

---

## Base URL

```
Development:  http://localhost:4000/api/v1
Production:   https://api.apollo-platform.com/api/v1
```

---

## Authentication

### POST /auth/register

Register a new user account.

**Request Body:**
```json
{
  "email": "investigator@agency.gov",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "role": "investigator",
  "agency": "FBI",
  "badgeNumber": "12345"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "userId": "usr_abc123",
    "email": "investigator@agency.gov",
    "role": "investigator",
    "createdAt": "2026-01-14T10:00:00Z"
  }
}
```

---

### POST /auth/login

Authenticate and receive JWT tokens.

**Request Body:**
```json
{
  "email": "investigator@agency.gov",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
    "expiresIn": 900,
    "user": {
      "id": "usr_abc123",
      "email": "investigator@agency.gov",
      "role": "investigator",
      "permissions": ["read:investigations", "write:investigations"]
    }
  }
}
```

---

### POST /auth/mfa/setup

Setup multi-factor authentication.

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrCode": "data:image/png;base64,...",
    "backupCodes": [
      "12345678",
      "87654321"
    ]
  }
}
```

---

### POST /auth/mfa/verify

Verify MFA code during login.

**Request Body:**
```json
{
  "userId": "usr_abc123",
  "code": "123456"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

---

## Operations Management

### POST /operations/investigations

Create a new investigation.

**Headers:**
```
Authorization: Bearer {accessToken}
Content-Type: application/json
```

**Request Body:**
```json
{
  "title": "OneCoin Fraud Investigation",
  "type": "cryptocurrency_fraud",
  "priority": "critical",
  "targets": [
    {
      "name": "Ruja Plamenova Ignatova",
      "aliases": ["CryptoQueen", "Dr. Ruja"],
      "dateOfBirth": "1980-05-30",
      "nationality": "Bulgaria"
    }
  ],
  "description": "Investigation into $4B OneCoin Ponzi scheme",
  "tags": ["cryptocurrency", "fraud", "fbi_most_wanted"]
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "investigationId": "inv_crypto_001",
    "status": "active",
    "createdAt": "2026-01-14T10:00:00Z",
    "assignedTo": ["usr_abc123"],
    "caseNumber": "CRYPTO-2026-0001"
  }
}
```

---

### GET /operations/investigations/{investigationId}

Retrieve investigation details.

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "investigationId": "inv_crypto_001",
    "title": "OneCoin Fraud Investigation",
    "status": "active",
    "targets": [...],
    "timeline": [...],
    "evidence": [...],
    "alerts": [...],
    "statistics": {
      "faceMatches": 12,
      "voiceMatches": 3,
      "walletTransactions": 4567,
      "osintHits": 89
    }
  }
}
```

---

### PATCH /operations/investigations/{investigationId}

Update investigation status or details.

**Request Body:**
```json
{
  "status": "closed",
  "resolution": "Target apprehended",
  "closedAt": "2026-01-14T15:00:00Z"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "investigationId": "inv_crypto_001",
    "status": "closed",
    "updatedAt": "2026-01-14T15:00:00Z"
  }
}
```

---

## Intelligence Fusion

### POST /intelligence/osint/search

Run OSINT search across multiple platforms.

**Headers:**
```
Authorization: Bearer {accessToken}
Content-Type: application/json
```

**Request Body:**
```json
{
  "query": {
    "username": "CryptoQueen",
    "email": "ruja@onecoin.eu",
    "phone": "+359-2-123-4567"
  },
  "platforms": ["sherlock", "dehashed", "holehe"],
  "depth": "comprehensive"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "queryId": "osint_q_12345",
    "status": "processing",
    "estimatedTime": 30,
    "resultsUrl": "/intelligence/osint/results/osint_q_12345"
  }
}
```

---

### GET /intelligence/osint/results/{queryId}

Retrieve OSINT search results.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "queryId": "osint_q_12345",
    "status": "completed",
    "results": {
      "socialMedia": [
        {
          "platform": "linkedin",
          "username": "cryptoqueen",
          "url": "https://linkedin.com/in/cryptoqueen",
          "confidence": 0.95
        }
      ],
      "breaches": [
        {
          "source": "Collection #1",
          "email": "ruja@onecoin.eu",
          "password": "[REDACTED]",
          "date": "2019-01-16"
        }
      ],
      "domains": [...],
      "phoneRecords": [...]
    }
  }
}
```

---

### POST /intelligence/correlate

Correlate intelligence from multiple sources.

**Request Body:**
```json
{
  "sources": ["osint", "blockchain", "surveillance"],
  "targetId": "tgt_ignatova",
  "timeRange": {
    "start": "2023-01-01T00:00:00Z",
    "end": "2026-01-14T23:59:59Z"
  }
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "correlationId": "corr_abc123",
    "connections": [
      {
        "type": "financial_link",
        "source": "blockchain_wallet",
        "target": "known_associate",
        "confidence": 0.87
      }
    ],
    "timeline": [...],
    "graph": {
      "nodes": [...],
      "edges": [...]
    }
  }
}
```

---

## Surveillance

### POST /surveillance/cameras/register

Register a new camera feed.

**Request Body:**
```json
{
  "cameraId": "cam_dubai_airport_t3_g15",
  "streamUrl": "rtsp://10.0.1.50:554/stream1",
  "location": {
    "name": "Dubai Airport Terminal 3, Gate 15",
    "coordinates": {
      "lat": 25.2532,
      "lon": 55.3657
    },
    "country": "UAE",
    "timezone": "Asia/Dubai"
  },
  "priority": 10,
  "enabled": true
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "cameraId": "cam_dubai_airport_t3_g15",
    "status": "active",
    "registeredAt": "2026-01-14T10:00:00Z"
  }
}
```

---

### GET /surveillance/matches/facial

Retrieve facial recognition matches.

**Query Parameters:**
```
?investigationId=inv_crypto_001
&startDate=2026-01-01
&minConfidence=0.6
&limit=100
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "matches": [
      {
        "matchId": "match_face_12345",
        "targetName": "Ruja Ignatova",
        "confidence": 0.87,
        "cameraId": "cam_dubai_airport_t3_g15",
        "location": "Dubai Airport Terminal 3, Gate 15",
        "timestamp": "2026-01-14T08:23:15Z",
        "evidencePath": "/evidence/facial_matches/match_face_12345.jpg",
        "frameId": 1234567
      }
    ],
    "total": 12,
    "page": 1
  }
}
```

---

### GET /surveillance/matches/voice

Retrieve voice recognition matches.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "matches": [
      {
        "matchId": "match_voice_67890",
        "targetName": "Ruja Ignatova",
        "confidence": 0.92,
        "source": "Phone intercept - +971-50-123-4567",
        "duration": 45.3,
        "timestamp": "2026-01-14T12:45:30Z",
        "transcript": "[TRANSCRIPT REDACTED]",
        "audioFile": "/evidence/voice_matches/match_voice_67890.mp3"
      }
    ]
  }
}
```

---

## Blockchain Forensics

### POST /blockchain/wallets/analyze

Analyze a cryptocurrency wallet.

**Request Body:**
```json
{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "blockchain": "bitcoin",
  "depth": "comprehensive"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "balance": 67.89123456,
    "totalReceived": 1234.56789,
    "totalSent": 1166.67665544,
    "transactionCount": 456,
    "firstSeen": "2009-01-09T02:54:25Z",
    "lastActivity": "2026-01-14T10:00:00Z",
    "riskScore": 45,
    "cluster": {
      "wallets": 23,
      "totalValue": 234.56789
    },
    "flags": ["high_value", "multiple_exchanges"]
  }
}
```

---

### GET /blockchain/transactions/{txHash}

Get transaction details.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "txHash": "abc123...",
    "blockchain": "bitcoin",
    "timestamp": "2026-01-14T10:00:00Z",
    "inputs": [...],
    "outputs": [...],
    "value": 12.34567890,
    "fee": 0.00012345,
    "confirmations": 6
  }
}
```

---

### POST /blockchain/monitor

Monitor wallet for activity.

**Request Body:**
```json
{
  "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "blockchain": "bitcoin",
  "alertThreshold": 1.0,
  "webhookUrl": "https://apollo.local/webhooks/blockchain"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "monitorId": "mon_wallet_12345",
    "status": "active",
    "createdAt": "2026-01-14T10:00:00Z"
  }
}
```

---

## Red Team Operations

### POST /redteam/c2/sessions

Start a C2 session.

**Request Body:**
```json
{
  "framework": "sliver",
  "targetHost": "10.0.1.100",
  "protocol": "mtls",
  "port": 443,
  "operationId": "op_crypto_001"
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "sessionId": "c2_session_12345",
    "status": "active",
    "beacon": "sliver_abc123",
    "createdAt": "2026-01-14T10:00:00Z"
  }
}
```

---

### POST /redteam/recon/scan

Run reconnaissance scan.

**Request Body:**
```json
{
  "target": "victim.com",
  "type": "comprehensive",
  "tools": ["bbot", "nmap", "masscan"],
  "stealth": true
}
```

**Response (202):**
```json
{
  "success": true,
  "data": {
    "scanId": "recon_scan_12345",
    "status": "running",
    "estimatedTime": 300
  }
}
```

---

## Alerts & Notifications

### GET /alerts

Retrieve all alerts.

**Query Parameters:**
```
?investigationId=inv_crypto_001
&type=facial_recognition
&priority=critical
&limit=50
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "alertId": "alert_12345",
        "type": "facial_recognition",
        "priority": "critical",
        "message": "Target match detected",
        "data": {...},
        "timestamp": "2026-01-14T10:00:00Z",
        "acknowledged": false
      }
    ],
    "total": 23
  }
}
```

---

### POST /alerts/{alertId}/acknowledge

Acknowledge an alert.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "alertId": "alert_12345",
    "acknowledgedBy": "usr_abc123",
    "acknowledgedAt": "2026-01-14T10:05:00Z"
  }
}
```

---

## Evidence Management

### POST /evidence/upload

Upload evidence file.

**Headers:**
```
Authorization: Bearer {accessToken}
Content-Type: multipart/form-data
```

**Form Data:**
```
file: [binary]
investigationId: inv_crypto_001
type: photo
description: Surveillance photo from Dubai Airport
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "evidenceId": "evd_12345",
    "filename": "surveillance_dubai_20260114.jpg",
    "sha256": "abc123...",
    "uploadedAt": "2026-01-14T10:00:00Z",
    "url": "/evidence/evd_12345"
  }
}
```

---

### GET /evidence/{evidenceId}

Download evidence file.

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Response (200):**
Binary file download with appropriate Content-Type header.

---

## Error Handling

All API errors follow this format:

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "statusCode": 401,
    "timestamp": "2026-01-14T10:00:00Z",
    "requestId": "req_abc123"
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_CREDENTIALS` | 401 | Authentication failed |
| `TOKEN_EXPIRED` | 401 | JWT token expired |
| `INSUFFICIENT_PERMISSIONS` | 403 | User lacks required permissions |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_SERVER_ERROR` | 500 | Server error |

---

## Rate Limiting

Apollo API implements rate limiting to ensure fair usage:

**Limits by Role:**
- **Admin**: 10,000 requests/hour
- **Investigator**: 5,000 requests/hour
- **Analyst**: 2,000 requests/hour
- **Viewer**: 1,000 requests/hour

**Rate Limit Headers:**
```
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4987
X-RateLimit-Reset: 1642168800
```

**Rate Limit Exceeded Response (429):**
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Retry after 3600 seconds.",
    "statusCode": 429,
    "retryAfter": 3600
  }
}
```

---

## WebSocket API

### Real-time Alerts

Connect to WebSocket for real-time alerts:

**URL:**
```
ws://localhost:4000/ws/alerts?token={accessToken}
```

**Message Format:**
```json
{
  "type": "facial_match",
  "data": {
    "matchId": "match_face_12345",
    "targetName": "Ruja Ignatova",
    "confidence": 0.87,
    "location": "Dubai Airport Terminal 3",
    "timestamp": "2026-01-14T10:00:00Z"
  }
}
```

---

## SDK Examples

### JavaScript/TypeScript

```javascript
import { ApolloClient } from '@apollo-platform/client';

const client = new ApolloClient({
  baseUrl: 'http://localhost:4000/api/v1',
  apiKey: 'your-api-key'
});

// Create investigation
const investigation = await client.investigations.create({
  title: 'OneCoin Fraud',
  type: 'cryptocurrency_fraud',
  priority: 'critical'
});

// Search OSINT
const results = await client.intelligence.osint.search({
  username: 'CryptoQueen',
  platforms: ['sherlock', 'dehashed']
});
```

### Python

```python
from apollo_sdk import ApolloClient

client = ApolloClient(
    base_url='http://localhost:4000/api/v1',
    api_key='your-api-key'
)

# Analyze wallet
analysis = client.blockchain.analyze_wallet(
    address='1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    blockchain='bitcoin'
)

print(f"Risk Score: {analysis['riskScore']}")
```

---

## Pagination

All list endpoints support pagination:

**Query Parameters:**
```
?page=1&limit=50&sortBy=createdAt&sortOrder=desc
```

**Response:**
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 234,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  }
}
```

---

## Filtering & Search

Most endpoints support filtering:

**Query Parameters:**
```
?filter[status]=active
&filter[priority]=critical
&search=OneCoin
```

---

## Audit Logging

All API calls are logged for compliance:

**GET /audit/logs**

```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "logId": "log_12345",
        "userId": "usr_abc123",
        "action": "investigation.create",
        "resourceId": "inv_crypto_001",
        "timestamp": "2026-01-14T10:00:00Z",
        "ipAddress": "10.0.1.100",
        "userAgent": "Mozilla/5.0..."
      }
    ]
  }
}
```

---

**For additional API support, contact**: api-support@apollo-platform.local

**API Status Page**: https://status.apollo-platform.com
