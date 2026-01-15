# Apollo Platform Quick Start Guide

> Get up and running with Apollo Platform in 10 minutes

Welcome to Apollo Platform! This guide will help you set up and start using the system quickly.

---

## Prerequisites

Before you begin, ensure you have:
- [ ] Docker 24.0+ installed
- [ ] Docker Compose 2.20+ installed
- [ ] 16GB+ RAM available
- [ ] 50GB+ free disk space
- [ ] Administrator/root access

---

## Step 1: Clone Repository

```bash
# Clone the Apollo Platform repository
git clone https://github.com/blablablasealsaresoft/apollo-platform.git

# Navigate to project directory
cd apollo-platform
```

---

## Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration (use your favorite editor)
nano .env
```

**Minimum required changes in `.env`**:
```bash
# Change these passwords!
POSTGRES_PASSWORD=YourSecurePassword123!
NEO4J_PASSWORD=YourNeo4jPassword123!
REDIS_PASSWORD=YourRedisPassword123!

# Change JWT secrets
JWT_SECRET=your-super-secret-jwt-key-min-32-characters
JWT_REFRESH_SECRET=your-refresh-secret-min-32-characters
```

---

## Step 3: Start Services

```bash
# Start all services with Docker Compose
docker-compose -f docker-compose.dev.yml up -d

# This will start:
# - PostgreSQL (port 5432)
# - Neo4j (port 7474, 7687)
# - Redis (port 6379)
# - Elasticsearch (port 9200)
# - RabbitMQ (port 5672, 15672)
# - MongoDB (port 27017)
```

**Wait 60 seconds** for all databases to initialize.

---

## Step 4: Initialize Databases

```bash
# Run database migrations
cd services/authentication
npm install
npm run migrate

# Seed initial data
npm run seed:initial

# Seed Ignatova case (FBI Most Wanted)
npm run seed:ignatova
```

---

## Step 5: Start Backend Services

```bash
# Terminal 1: Start authentication service
cd services/authentication
npm run dev

# Terminal 2: Start operations service
cd services/operations
npm run dev

# Terminal 3: Start intelligence fusion service
cd services/intelligence-fusion
npm run dev
```

**Or use PM2 to manage all services**:
```bash
npm install -g pm2
pm2 start ecosystem.config.js
pm2 logs
```

---

## Step 6: Start Frontend

```bash
# New terminal window
cd frontend/react-console
npm install
npm start
```

**Frontend will be available at**: http://localhost:3000

---

## Step 7: First Login

1. **Open your browser**: Navigate to http://localhost:3000

2. **Default admin credentials**:
   - Email: `admin@apollo.local`
   - Password: `Apollo2026!Admin`

3. **⚠️ IMPORTANT**: Change the admin password immediately!
   - Go to Settings > Security
   - Click "Change Password"

---

## Step 8: Verify Installation

### Check Backend Health

```bash
# API health check
curl http://localhost:4000/health

# Expected response:
{
  "status": "healthy",
  "services": {
    "postgres": "connected",
    "neo4j": "connected",
    "redis": "connected"
  }
}
```

### Check Databases

```bash
# PostgreSQL
docker exec -it apollo-postgres psql -U apollo_admin -d apollo -c "SELECT COUNT(*) FROM users;"

# Neo4j Browser
# Visit: http://localhost:7474
# Username: neo4j
# Password: [your NEO4J_PASSWORD]

# Redis
docker exec -it apollo-redis redis-cli PING
```

---

## Step 9: Explore Pre-loaded Ignatova Case

Apollo comes pre-loaded with the Ruja Ignatova (CryptoQueen) investigation:

1. **Login to frontend**: http://localhost:3000

2. **Navigate to Investigations**: Click "Investigations" in sidebar

3. **Open Ignatova Case**: Click on "CRYPTO-2026-0001 - OneCoin Fraud Investigation"

4. **Explore**:
   - **Targets Tab**: View Ruja Ignatova profile
   - **Timeline Tab**: See investigation timeline
   - **Evidence Tab**: Browse photos and documents
   - **Network Graph**: Visualize criminal network
   - **Surveillance Tab**: Check facial recognition status

---

## Step 10: Start Surveillance System (Optional)

```bash
# Install Python dependencies
cd intelligence/geoint-engine/surveillance-networks
pip install -r requirements.txt

# Start integrated surveillance
python integrated_surveillance.py
```

**Surveillance system features**:
- Facial recognition across camera feeds
- Voice recognition matching
- Age progression (Ignatova: 2017 → 2026)
- Real-time alerts via Redis pub/sub

---

## Quick Feature Tour

### 1. Create New Investigation

```bash
# Via API
curl -X POST http://localhost:4000/api/v1/operations/investigations \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Investigation",
    "type": "general",
    "priority": "medium"
  }'
```

Or use the web interface:
1. Click "New Investigation" button
2. Fill in investigation details
3. Click "Create"

### 2. Run OSINT Search

```bash
# Search for username across social media
cd intelligence/osint-engine
python sherlock_integration.py --username "testuser" --timeout 30
```

### 3. Analyze Blockchain Wallet

```bash
# Analyze Bitcoin wallet
cd blockchain-forensics
node analyze-wallet.js 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

### 4. Register Camera Feed

```bash
curl -X POST http://localhost:4000/api/v1/surveillance/cameras/register \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cameraId": "test_camera_001",
    "streamUrl": "rtsp://example.com/stream",
    "location": "Test Location",
    "priority": 5
  }'
```

---

## Common Tasks

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f postgres
docker-compose logs -f neo4j

# Backend services (if using PM2)
pm2 logs
```

### Restart Services

```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart postgres

# Restart backend (PM2)
pm2 restart all
```

### Stop Services

```bash
# Stop all services
docker-compose down

# Stop backend services
pm2 stop all

# Stop frontend
# Press Ctrl+C in terminal
```

---

## Troubleshooting

### Services Won't Start

```bash
# Check Docker status
docker ps

# Check for port conflicts
netstat -an | grep 5432  # PostgreSQL
netstat -an | grep 7474  # Neo4j
netstat -an | grep 6379  # Redis

# Restart Docker
systemctl restart docker  # Linux
# Or restart Docker Desktop on Windows/Mac
```

### Database Connection Failed

```bash
# Check database logs
docker-compose logs postgres
docker-compose logs neo4j

# Verify environment variables
cat .env | grep POSTGRES
cat .env | grep NEO4J

# Test connection manually
docker exec -it apollo-postgres psql -U apollo_admin -d apollo
```

### Frontend Won't Load

```bash
# Check if backend is running
curl http://localhost:4000/health

# Check frontend logs
cd frontend/react-console
npm run dev  # Run in foreground to see errors

# Clear cache and rebuild
rm -rf node_modules package-lock.json
npm install
npm start
```

### Memory Issues

```bash
# Check resource usage
docker stats

# Increase Docker memory
# Docker Desktop: Settings > Resources > Memory (increase to 8GB+)

# Stop unused services
docker-compose stop mongodb  # If not needed
docker-compose stop rabbitmq  # If not needed
```

---

## Next Steps

Now that you're set up, explore these guides:

1. **[User Guide](../README.md)** - Learn all features
2. **[Intelligence Collection](../intelligence-collection/)** - Run OSINT searches
3. **[Blockchain Forensics](../crypto-investigations/)** - Track cryptocurrency
4. **[Surveillance](../surveillance/)** - Set up camera feeds
5. **[API Documentation](../../API.md)** - Integrate with Apollo

---

## Getting Help

- **Documentation**: See [APOLLO_COMPLETE_STATUS.md](../../../APOLLO_COMPLETE_STATUS.md)
- **API Reference**: [docs/API.md](../../API.md)
- **Deployment**: [docs/DEPLOYMENT.md](../../DEPLOYMENT.md)
- **Troubleshooting**: Check logs and error messages

---

## Security Reminder

⚠️ **IMPORTANT SECURITY STEPS**:

1. **Change default passwords** immediately
2. **Enable MFA** for all users
3. **Configure firewall** rules
4. **Set strong JWT secrets** (32+ characters)
5. **Use HTTPS** in production
6. **Restrict database access** to localhost/internal network
7. **Review user permissions** regularly

---

**🎉 Congratulations!** You're now ready to use Apollo Platform for criminal investigations.

**Status**: Ready for authorized law enforcement use
**Support**: apollo-support@platform.local
