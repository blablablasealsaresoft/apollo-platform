# Apollo Platform - Database Infrastructure

**Production-grade database stack for criminal investigation platform**

## 🗄️ Database Stack

Apollo uses a multi-database architecture optimized for different data types:

| Database | Purpose | Port |
|----------|---------|------|
| **PostgreSQL 15** | Primary relational data (users, investigations, targets, evidence) | 5432 |
| **TimescaleDB** | Time-series data (blockchain transactions, surveillance) | 5433 |
| **Neo4j 5** | Graph database (criminal networks, relationships) | 7474, 7687 |
| **Redis 7** | Cache, sessions, pub/sub | 6379 |
| **Elasticsearch 8** | Full-text search, intelligence indexing | 9200, 9300 |
| **RabbitMQ 3.12** | Message queue for async processing | 5672, 15672 |
| **MongoDB 7** | Document store for unstructured data | 27017 |

## 🚀 Quick Start

### 1. Configure Passwords

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set secure passwords
notepad .env  # or nano .env on Linux/Mac
```

**CRITICAL**: Use strong passwords (20+ characters) in production!

### 2. Start All Databases

```bash
# Start all database containers
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3. Verify Databases

```bash
# PostgreSQL
docker exec -it apollo-postgresql psql -U apollo_admin -d apollo -c "SELECT version();"

# Neo4j (open browser)
# http://localhost:7474
# Username: neo4j
# Password: [your NEO4J_PASSWORD from .env]

# Redis
docker exec -it apollo-redis redis-cli -a [your REDIS_PASSWORD] ping

# Elasticsearch
curl -u elastic:[your ELASTIC_PASSWORD] http://localhost:9200/_cluster/health

# TimescaleDB
docker exec -it apollo-timescaledb psql -U apollo_admin -d apollo_timeseries -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';"
```

### 4. Initialize Schemas

Schemas are automatically initialized on first startup via `docker-entrypoint-initdb.d`.

To manually run schemas:

```bash
# PostgreSQL
docker exec -i apollo-postgresql psql -U apollo_admin -d apollo < postgresql/schemas/001_init.sql
docker exec -i apollo-postgresql psql -U apollo_admin -d apollo < postgresql/schemas/002_users_auth.sql
docker exec -i apollo-postgresql psql -U apollo_admin -d apollo < postgresql/schemas/003_investigations_targets.sql
docker exec -i apollo-postgresql psql -U apollo_admin -d apollo < postgresql/schemas/004_evidence_intelligence.sql

# TimescaleDB
docker exec -i apollo-timescaledb psql -U apollo_admin -d apollo_timeseries < timescaledb/schemas/001_timeseries.sql

# Neo4j
docker exec -i apollo-neo4j cypher-shell -u neo4j -p [your NEO4J_PASSWORD] < neo4j/schemas/001_init.cypher
```

## 📊 Database Schemas

### PostgreSQL Tables

**Authentication & Users**:
- `users` - System users with RBAC
- `user_sessions` - JWT session management
- `user_mfa` - Multi-factor authentication
- `oauth_providers` - OAuth integrations
- `api_keys` - API key management

**Investigations**:
- `investigations` - Criminal cases
- `investigation_members` - Team assignments
- `targets` - High-value individuals (including Ignatova!)
- `evidence` - Digital/physical evidence with chain of custody
- `intelligence_reports` - OSINT/SIGINT/GEOINT intelligence
- `alerts` - Real-time detection alerts
- `operations` - Field operations

**Default Data**:
- Admin user: `admin@apollo.local` / Password: `ChangeMe2026!` (⚠️ **CHANGE IMMEDIATELY!**)
- Pre-loaded investigation: OneCoin - Ruja Ignatova (CRYPTO-2026-0001)
- Pre-loaded target: Ruja Ignatova with full profile

### TimescaleDB Tables (Time-Series)

- `blockchain_transactions` - Cryptocurrency transactions
- `surveillance_events` - Camera detections, facial recognition matches
- `communication_logs` - Phone calls, messages, emails

**Continuous Aggregates**:
- `blockchain_daily_summary` - Daily blockchain statistics
- `surveillance_hourly_summary` - Hourly surveillance metrics

### Neo4j Graph

**Node Types**:
- `Person` - Individuals (targets, associates)
- `Organization` - Criminal organizations
- `Company` - Shell companies, fronts
- `BankAccount` - Financial accounts
- `CryptocurrencyAddress` - Crypto wallets
- `Location` - Geographic locations
- `PhoneNumber` - Contact numbers
- `EmailAddress` - Email accounts
- `SocialMediaAccount` - Social profiles

**Relationships**:
- `FOUNDED` - Founded organization
- `WORKED_FOR` - Employment
- `PARTNERED_WITH` - Business partners
- `SIBLING_OF`, `PARENT_OF`, `MARRIED_TO` - Family
- `TRANSACTION` - Financial transactions
- `COMMUNICATED_WITH` - Communications
- `TRAVELED_TO` - Travel history
- `LOCATED_IN` - Geographic presence

**Pre-loaded**:
- Complete OneCoin network (Ruja Ignatova, Konstantin Ignatov, Sebastian Greenwood, Mark Scott)
- Key locations (Sofia, Dubai, Athens, Frankfurt)

## 🔧 Management Commands

### PostgreSQL

```bash
# Connect to PostgreSQL
docker exec -it apollo-postgresql psql -U apollo_admin -d apollo

# Backup database
docker exec apollo-postgresql pg_dump -U apollo_admin apollo > apollo_backup_$(date +%Y%m%d).sql

# Restore database
docker exec -i apollo-postgresql psql -U apollo_admin -d apollo < apollo_backup.sql

# View tables
docker exec -it apollo-postgresql psql -U apollo_admin -d apollo -c "\dt"

# Query investigations
docker exec -it apollo-postgresql psql -U apollo_admin -d apollo -c "SELECT case_number, title, status FROM investigations;"
```

### Neo4j

```bash
# Connect to Neo4j
docker exec -it apollo-neo4j cypher-shell -u neo4j -p [your password]

# View OneCoin network
MATCH (p:Person)-[r]-(o:Organization {name: 'OneCoin'})
RETURN p, r, o;

# Find all connections to Ruja
MATCH (ruja:Person {id: 'ignatova-ruja'})-[r*1..3]-(connected)
RETURN ruja, r, connected;

# Network statistics
MATCH (p:Person)-[r]-(o:Organization {name: 'OneCoin'})
RETURN count(DISTINCT p) as people, count(DISTINCT r) as relationships;
```

### Redis

```bash
# Connect to Redis
docker exec -it apollo-redis redis-cli -a [your password]

# View keys
KEYS *

# Monitor real-time commands
MONITOR

# Get stats
INFO
```

### Elasticsearch

```bash
# Cluster health
curl -u elastic:[your password] http://localhost:9200/_cluster/health?pretty

# List indices
curl -u elastic:[your password] http://localhost:9200/_cat/indices?v

# Create index mapping
curl -X PUT -u elastic:[your password] http://localhost:9200/intelligence \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/mappings/intelligence-index.json
```

## 📈 Performance Tuning

### PostgreSQL

Configuration in `postgresql/postgresql.conf`:
- `shared_buffers = 4GB` - Memory for caching
- `effective_cache_size = 12GB` - Planner estimate of OS cache
- `work_mem = 16MB` - Memory per query operation
- `max_connections = 200` - Concurrent connections

### Neo4j

Configuration via environment variables:
- `NEO4J_dbms_memory_pagecache_size = 2G` - Page cache
- `NEO4J_dbms_memory_heap_max__size = 4G` - JVM heap

### TimescaleDB

- Automatic chunk management (1 week chunks)
- Compression after 30 days (blockchain), 7 days (surveillance)
- Continuous aggregates for fast queries
- Data retention: 5 years (blockchain), 3 years (surveillance), 7 years (communications)

## 🔒 Security Best Practices

1. **Change Default Passwords**: Use strong, unique passwords
2. **Enable SSL/TLS**: For production deployments
3. **Network Isolation**: Use Docker networks
4. **Firewall Rules**: Restrict access to database ports
5. **Regular Backups**: Daily automated backups
6. **Access Control**: Role-based permissions
7. **Audit Logging**: Track all database access
8. **Encryption at Rest**: Enable for sensitive data

## 🐳 Docker Commands

```bash
# Start all databases
docker-compose up -d

# Stop all databases
docker-compose down

# Stop and remove all data (⚠️ DESTRUCTIVE!)
docker-compose down -v

# Restart specific database
docker-compose restart postgresql

# View logs
docker-compose logs -f postgresql
docker-compose logs -f neo4j

# Remove and rebuild
docker-compose down
docker-compose up -d --build

# Resource usage
docker stats apollo-postgresql apollo-neo4j apollo-redis apollo-elasticsearch
```

## 📊 Monitoring

### Database Health Checks

All databases have health checks configured:
- PostgreSQL: `pg_isready`
- Neo4j: `cypher-shell` ping
- Redis: `redis-cli ping`
- Elasticsearch: `/_cluster/health`

Check health:
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Performance Monitoring

```bash
# PostgreSQL active queries
docker exec -it apollo-postgresql psql -U apollo_admin -d apollo -c \
  "SELECT pid, usename, application_name, state, query FROM pg_stat_activity WHERE state != 'idle';"

# Neo4j query performance
# Open http://localhost:7474 → Browser → :queries

# Redis memory usage
docker exec -it apollo-redis redis-cli -a [password] INFO memory
```

## 🆘 Troubleshooting

### PostgreSQL won't start
```bash
# Check logs
docker logs apollo-postgresql

# Check disk space
df -h

# Reset and reinitialize
docker-compose down -v
docker-compose up -d
```

### Neo4j authentication failed
```bash
# Reset Neo4j password
docker exec -it apollo-neo4j neo4j-admin set-initial-password [new password]
```

### Out of memory errors
```bash
# Increase Docker memory limits (Docker Desktop → Settings → Resources)
# Or reduce database memory allocations in docker-compose.yml
```

### Port already in use
```bash
# Find process using port
netstat -ano | findstr :5432  # Windows
lsof -i :5432  # Linux/Mac

# Stop conflicting service or change port in docker-compose.yml
```

## 📚 Additional Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Neo4j Documentation](https://neo4j.com/docs/)
- [TimescaleDB Documentation](https://docs.timescale.com/)
- [Redis Documentation](https://redis.io/docs/)
- [Elasticsearch Documentation](https://www.elastic.co/guide/)

## 🎯 Next Steps

After databases are running:

1. **Agent 1**: Implement backend services that connect to these databases
2. **Agent 3**: Configure intelligence tools to write to PostgreSQL/Neo4j/Elasticsearch
3. **Agent 4**: Set up blockchain monitoring to write to TimescaleDB
4. **Agent 5**: Configure facial recognition to write surveillance events to TimescaleDB

---

**Database Infrastructure: ✅ COMPLETE**

All databases operational and ready for Apollo platform!
