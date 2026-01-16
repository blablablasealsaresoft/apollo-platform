# Apollo Platform API Versioning Guide

## Overview

The Apollo Platform API follows semantic versioning and provides a clear path for API evolution while maintaining backward compatibility.

## Current Version

**API Version: 2.0.0**

- Node.js Services: `/api/*` endpoints
- Python Intelligence Server: `/api/v1/*` endpoints

## Version Format

All versioned endpoints follow the format:
```
/api/v{major}/*
```

Example:
- `/api/v1/osint/username/search`
- `/api/v1/blockchain/wallet/info`
- `/api/v1/facial/search`

## Versioning Strategy

### Semantic Versioning

We follow semantic versioning (SemVer):

- **Major version** (v1, v2): Breaking changes that require client updates
- **Minor version**: New features added in a backward-compatible manner
- **Patch version**: Backward-compatible bug fixes

### Version Lifecycle

| Phase | Duration | Description |
|-------|----------|-------------|
| Current | Ongoing | Active development, full support |
| Maintenance | 12 months | Security patches only |
| Deprecated | 6 months | Deprecation warnings, migration support |
| Sunset | - | No longer available |

## API v1 (Current)

### Release Date
January 2026

### Status
Active (Current)

### Base URLs

| Environment | Node.js Gateway | Intelligence Server |
|-------------|-----------------|---------------------|
| Development | `http://localhost:3000` | `http://localhost:8000` |
| Staging | `https://api-staging.apollo-platform.com` | `https://intel-staging.apollo-platform.com` |
| Production | `https://api.apollo-platform.com` | `https://intel.apollo-platform.com` |

### Endpoints

#### Node.js Microservices (Unversioned)

| Service | Base Path | Description |
|---------|-----------|-------------|
| Authentication | `/api/auth/*` | User authentication and session management |
| Users | `/api/users/*` | User administration |
| Operations | `/api/operations/*` | Operation management |
| Intelligence | `/api/intelligence/*` | Intelligence reports |
| Search | `/api/search/*` | Full-text search |
| Analytics | `/api/analytics/*` | System analytics |
| Notifications | `/api/notifications/*` | User notifications |
| Alerts | `/api/alerts/*` | System alerts |

#### Python Intelligence Server (v1)

| Service | Base Path | Description |
|---------|-----------|-------------|
| OSINT | `/api/v1/osint/*` | Open source intelligence |
| Blockchain | `/api/v1/blockchain/*` | Cryptocurrency analysis |
| SOCMINT | `/api/v1/socmint/*` | Social media intelligence |
| GEOINT | `/api/v1/geoint/*` | Geospatial intelligence |
| Facial | `/api/v1/facial/*` | Facial recognition |
| Voice | `/api/v1/voice/*` | Voice recognition |
| Fusion | `/api/v1/fusion/*` | Intelligence fusion |
| Breach | `/api/v1/breach/*` | Breach intelligence |
| Dark Web | `/api/v1/darkweb/*` | Dark web monitoring |

## Breaking Changes Policy

### What Constitutes a Breaking Change

1. **Endpoint removal** - Removing an existing endpoint
2. **Required parameter addition** - Adding new required parameters
3. **Response structure changes** - Modifying existing response fields
4. **Authentication changes** - Changing authentication requirements
5. **Error code changes** - Modifying error response structure

### What Does NOT Constitute a Breaking Change

1. **New endpoints** - Adding new optional endpoints
2. **Optional parameters** - Adding new optional parameters
3. **Response additions** - Adding new fields to responses
4. **New error codes** - Adding new error codes (clients should handle unknowns)

## Deprecation Process

### Deprecation Timeline

```
Day 0:    Deprecation announced
          - Deprecation warning header added
          - Documentation updated
          - Migration guide published

Month 3:  First sunset warning
          - Email notifications to API users
          - Rate limiting notices

Month 6:  Final warning period
          - Increased deprecation warnings
          - Direct outreach to heavy users

Month 12: API version sunset
          - Endpoints return 410 Gone
          - Redirect to new version documentation
```

### Deprecation Headers

When using deprecated endpoints, responses will include:

```http
X-API-Deprecated: true
X-API-Deprecation-Date: 2027-01-15
X-API-Sunset-Date: 2027-07-15
Link: <https://api.apollo-platform.com/docs/migration/v1-to-v2>; rel="deprecation"
```

## Version Negotiation

### URL Path Versioning (Preferred)

```
GET /api/v1/osint/username/search
```

### Accept Header Versioning (Alternative)

```http
Accept: application/vnd.apollo.v1+json
```

### Query Parameter Versioning (Fallback)

```
GET /api/osint/username/search?api_version=1
```

## Migration Guides

### Future: v1 to v2 Migration

When API v2 is released, a comprehensive migration guide will be provided covering:

1. **Endpoint mapping** - Old to new endpoint paths
2. **Request changes** - Parameter and body modifications
3. **Response changes** - New response structures
4. **Authentication changes** - Any auth updates
5. **Code examples** - Updated client code samples

### Example Migration (Hypothetical v2)

```diff
# Endpoint path
- GET /api/v1/osint/username/search
+ GET /api/v2/osint/identity/search

# Request body
{
-   "username": "target123"
+   "query": "target123",
+   "type": "username"
}

# Response structure
{
    "success": true,
    "data": {
-       "results": [...]
+       "matches": [...],
+       "metadata": {
+           "searchId": "search_abc123",
+           "timestamp": "2026-01-15T10:30:00Z"
+       }
    }
}
```

## SDK Version Support

| SDK | v1 Support | Notes |
|-----|------------|-------|
| Python | 1.0+ | Full support |
| Node.js | 1.0+ | Full support |
| Go | 1.0+ | Full support |

## API Changelog

### v2.0.0 (January 2026)

**New Features:**
- Facial Recognition API (`/api/v1/facial/*`)
- Voice Recognition API (`/api/v1/voice/*`)
- Biometric Authentication
- API Key Management
- Session Management
- Alert System

**Improvements:**
- Enhanced rate limiting
- Better error responses
- Comprehensive OpenAPI documentation

### v1.0.0 (Initial Release)

**Features:**
- Authentication & Authorization
- OSINT Intelligence
- Blockchain Analysis
- GEOINT Services
- Search & Analytics

## Best Practices

### For API Consumers

1. **Always specify version** - Don't rely on default versioning
2. **Handle deprecation headers** - Log and alert on deprecated endpoints
3. **Test against staging** - Verify before production upgrades
4. **Subscribe to changelog** - Stay informed of updates
5. **Use SDKs when available** - They handle versioning automatically

### For API Developers

1. **Plan breaking changes carefully** - Minimize disruption
2. **Provide migration tools** - Automated code transformers when possible
3. **Maintain old versions** - Follow the deprecation timeline
4. **Document thoroughly** - Clear migration instructions

## Support

### Getting Help

- **Documentation**: `/api/docs` (Swagger UI)
- **OpenAPI Spec**: `/api/openapi.json`
- **Support Email**: api-support@apollo-platform.com
- **Status Page**: https://status.apollo-platform.com

### Reporting Issues

For API issues or version-related questions:

1. Check the documentation first
2. Review the changelog for recent changes
3. Contact support with request/response details

## Version History

| Version | Release Date | Status | Sunset Date |
|---------|-------------|--------|-------------|
| v2.0.0 | 2026-01 | Current | - |
| v1.0.0 | 2025-01 | Deprecated | 2027-01 |
