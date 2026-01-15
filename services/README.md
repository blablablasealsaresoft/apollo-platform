# Apollo Platform - Backend Microservices

Complete production-ready microservices architecture for the Apollo criminal investigation platform.

## Architecture Overview

The Apollo backend consists of 8 independent microservices:

1. **API Gateway** (Port 3000) - Central entry point with routing, authentication, and rate limiting
2. **Authentication Service** (Port 3001) - JWT, OAuth, MFA, and RBAC
3. **User Management Service** (Port 3002) - User CRUD, profiles, and clearance management
4. **Operations Management** (Port 3003) - Investigation operations and field reports
5. **Intelligence Fusion** (Port 3004) - Intelligence aggregation and correlation
6. **Notifications Service** (Port 3005) - Real-time alerts via WebSocket and Redis pub/sub
7. **Analytics Service** (Port 3006) - Metrics, statistics, and reporting
8. **Search Service** (Port 3007) - Full-text search with Elasticsearch

## Technology Stack

- **Runtime**: Node.js 20+ with TypeScript
- **Framework**: Express.js
- **Databases**: PostgreSQL, Redis, Elasticsearch
- **Authentication**: JWT, Passport.js (OAuth), Speakeasy (MFA)
- **Security**: Helmet, Bcrypt, Rate Limiting
- **Testing**: Jest
- **Containerization**: Docker

## Quick Start

### Prerequisites

- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+
- Elasticsearch 8+

### Installation

```bash
# Install dependencies for all services
npm install

# Build all services
npm run build --workspaces

# Start infrastructure (databases, Redis, Elasticsearch)
docker-compose up -d

# Run database migrations
npm run db:migrate

# Start all services in development mode
npm run dev:services
```

### Environment Configuration

Create `.env` file in the root directory:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=apollo
DB_USER=apollo_admin
DB_PASSWORD=your_secure_password_here

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT
JWT_SECRET=your_jwt_secret_minimum_32_characters_long
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# OAuth (Optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Email
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=

# Elasticsearch
ELASTICSEARCH_NODE=http://localhost:9200

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS
CORS_ORIGIN=*
```

### Running Services

#### Development Mode

```bash
# Start individual service
cd services/authentication
npm run dev

# Start all services
npm run dev:all
```

#### Production Mode with Docker

```bash
# Build and start all services
docker-compose -f services/docker-compose.services.yml up -d

# View logs
docker-compose -f services/docker-compose.services.yml logs -f

# Stop all services
docker-compose -f services/docker-compose.services.yml down
```

## API Documentation

### Authentication Service (`/api/auth`)

#### Register
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your_refresh_token"
}
```

### User Management Service (`/api/users`)

#### Get All Users
```bash
GET /api/users?page=1&limit=20
Authorization: Bearer YOUR_ACCESS_TOKEN
```

#### Get User by ID
```bash
GET /api/users/:id
Authorization: Bearer YOUR_ACCESS_TOKEN
```

#### Update User
```bash
PATCH /api/users/:id
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json

{
  "firstName": "Jane",
  "role": "investigator",
  "clearanceLevel": "secret"
}
```

### Operations Service (`/api/operations`)

#### Create Operation
```bash
POST /api/operations
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json

{
  "name": "Operation Phoenix",
  "codename": "PHOENIX-2026",
  "description": "High-value target investigation",
  "priority": "high",
  "clearanceLevel": "secret",
  "leadInvestigatorId": "user-uuid",
  "startDate": "2026-01-15T00:00:00Z"
}
```

#### Get Operations
```bash
GET /api/operations?status=active&priority=high
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### Intelligence Service (`/api/intelligence`)

#### Create Intelligence Report
```bash
POST /api/intelligence
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json

{
  "title": "Financial Transaction Analysis",
  "summary": "Suspicious crypto transactions detected",
  "content": "Detailed analysis...",
  "source": "finint",
  "confidence": "high",
  "clearanceLevel": "confidential",
  "authorId": "user-uuid",
  "tags": ["cryptocurrency", "money-laundering"]
}
```

### Search Service (`/api/search`)

#### Search Across Indices
```bash
POST /api/search
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json

{
  "query": "cryptocurrency fraud",
  "indices": ["investigations", "targets", "intelligence"],
  "filters": {
    "status": "active"
  }
}
```

### Notifications Service (`/api/notifications`)

#### Get User Notifications
```bash
GET /api/notifications/user/:userId
Authorization: Bearer YOUR_ACCESS_TOKEN
```

#### WebSocket Connection
```javascript
const ws = new WebSocket('ws://localhost:3005/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'auth', userId: 'user-uuid' }));
};
ws.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  console.log('New notification:', notification);
};
```

### Analytics Service (`/api/analytics`)

#### Get Investigation Metrics
```bash
GET /api/analytics/investigations
Authorization: Bearer YOUR_ACCESS_TOKEN
```

#### Get System Health
```bash
GET /api/analytics/system
Authorization: Bearer YOUR_ACCESS_TOKEN
```

## User Roles and Permissions

### Role Hierarchy

1. **Admin** - Full system access
   - Manage users
   - Configure system settings
   - Access all operations and intelligence

2. **Investigator** - Lead investigations
   - Create and manage operations
   - Assign team members
   - Access classified intelligence

3. **Analyst** - Intelligence analysis
   - Create intelligence reports
   - View operations
   - Perform searches

4. **Viewer** - Read-only access
   - View assigned operations
   - Read intelligence reports (within clearance)

### Clearance Levels

1. **Top Secret** - Highest classification
2. **Secret** - High-value operations
3. **Confidential** - Standard operations
4. **Restricted** - Limited access
5. **Unclassified** - Public information

## Testing

```bash
# Run all tests
npm test

# Run tests for specific service
cd services/authentication
npm test

# Run with coverage
npm run test:coverage

# Run integration tests
npm run test:integration
```

## Security Features

- **JWT Authentication** with refresh tokens
- **Multi-Factor Authentication** (TOTP)
- **OAuth Integration** (Google, Microsoft, GitHub)
- **Role-Based Access Control** (RBAC)
- **Clearance Level Enforcement**
- **Rate Limiting** (100 requests per 15 minutes)
- **Password Hashing** (Bcrypt, 12 rounds)
- **SQL Injection Protection** (Parameterized queries)
- **XSS Protection** (Helmet middleware)
- **CORS Configuration**
- **Input Validation** (Joi schemas)
- **Activity Logging**

## Database Schema

The system uses PostgreSQL with the following main tables:

- `users` - User accounts and authentication
- `operations` - Investigation operations
- `operation_team_members` - Team assignments
- `targets` - Investigation targets
- `intelligence_reports` - Intelligence data
- `field_reports` - Field operation reports
- `notifications` - User notifications
- `activity_logs` - System audit trail

See `infrastructure/databases/postgresql/schemas/01_init_schema.sql` for complete schema.

## Monitoring and Logging

- **Winston** for structured logging
- **Health Check Endpoints** on all services
- **Prometheus Metrics** (via docker-compose.yml)
- **Grafana Dashboards** for visualization
- **Activity Logs** for audit trail

## Development

### Project Structure

```
services/
├── shared/              # Shared utilities and types
├── api-gateway/         # API Gateway service
├── authentication/      # Authentication service
├── user-management/     # User management service
├── operations/          # Operations service
├── intelligence/        # Intelligence service
├── notifications/       # Notifications service
├── analytics/          # Analytics service
└── search/             # Search service
```

### Adding a New Service

1. Create service directory under `services/`
2. Initialize with `package.json` and `tsconfig.json`
3. Implement service logic in `src/`
4. Add routes and middleware
5. Create Dockerfile
6. Update `docker-compose.services.yml`
7. Add tests

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL status
docker ps | grep postgresql

# View database logs
docker logs apollo-postgresql

# Connect to database
docker exec -it apollo-postgresql psql -U apollo -d apollo
```

### Redis Connection Issues

```bash
# Check Redis status
docker exec -it apollo-redis redis-cli ping

# View Redis logs
docker logs apollo-redis
```

### Service Not Starting

```bash
# Check service logs
docker logs apollo-auth-service

# Rebuild service
docker-compose -f services/docker-compose.services.yml build auth-service

# Restart service
docker-compose -f services/docker-compose.services.yml restart auth-service
```

## Performance Optimization

- **Database Connection Pooling** (20 connections per service)
- **Redis Caching** for frequently accessed data
- **Query Optimization** with proper indexes
- **Rate Limiting** to prevent abuse
- **Compression** for API responses
- **Horizontal Scaling** with load balancer

## Contributing

1. Create a feature branch
2. Implement changes with tests
3. Ensure all tests pass
4. Update documentation
5. Submit pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- GitHub Issues: https://github.com/apollo-platform/apollo/issues
- Documentation: https://docs.apollo-platform.com
- Email: support@apollo-platform.com
