# CloudRecon - Cloud Infrastructure SSL/TLS Reconnaissance

## Overview

**CloudRecon** is a high-speed SSL/TLS certificate reconnaissance tool for discovering cloud infrastructure and services.

**Source**: [CloudRecon](https://github.com/blablablasealsaresoft/CloudRecon)  
**Purpose**: Cloud infrastructure discovery via certificate analysis  
**Status**: ✅ Integrated  
**Location**: `redteam/reconnaissance/cloud-reconnaissance/cloudrecon-enhanced/`

---

## What is CloudRecon?

CloudRecon is a Go-based tool that:
- **Scrapes SSL/TLS certificates** from IP ranges
- **Extracts Common Names (CN)** and Subject Alternative Names (SAN)
- **Identifies cloud infrastructure** through cert analysis
- **Maps organization infrastructure** globally
- **Stores in local database** for querying

### Use Cases

1. **Cloud Asset Discovery** - Find all cloud services
2. **Certificate Intelligence** - Analyze SSL/TLS certs
3. **Organization Mapping** - Map company infrastructure
4. **Subdomain Discovery** - Find subdomains via certs
5. **Infrastructure Attribution** - Link services to organizations

---

## Integration into Apollo

### Directory Structure

```
cloudrecon-enhanced/
├── core/
│   ├── cert-scraper.go          # Main scraping engine
│   ├── cert-analyzer.go         # Certificate analysis
│   ├── db-manager.go            # Local database
│   └── apollo-feeder.go         # Feed to Apollo intelligence
├── scanners/
│   ├── ip-range-scanner.go      # Scan IP ranges
│   ├── cidr-scanner.go          # CIDR notation support
│   ├── port-scanner.go          # Multi-port support
│   └── concurrent-scanner.go    # High-speed concurrent scanning
├── intelligence/
│   ├── cn-extractor.go          # Common Name extraction
│   ├── san-extractor.go         # SAN extraction
│   ├── org-mapper.go            # Organization mapping
│   └── subdomain-correlator.go  # Subdomain correlation
├── database/
│   ├── sqlite-backend.go        # SQLite storage
│   ├── query-engine.go          # Query interface
│   └── export-formats.go        # JSON, CSV export
└── apollo-integration/
    ├── neo4j-feeder.go          # Feed to Neo4j
    ├── elasticsearch-feeder.go   # Feed to Elasticsearch
    └── intelligence-fusion.go    # Feed to intelligence fusion
```

---

## Core Capabilities

### 1. Scrape SSL/TLS Certificates

**Command**: `scrape`

```bash
# Scrape certificates from IP range
apollo-cloudrecon scrape \
  --input 192.168.1.0/24 \
  --ports 443,8443 \
  --concurrent 100 \
  --output json

# Outputs:
# IP, PORT, Organization, CommonName, SAN
# 192.168.1.10, 443, "Suspect Corp", "admin.target.com", "api.target.com, www.target.com"
```

**Usage**:
```bash
# Single IP
CloudRecon scrape -i 1.2.3.4

# Multiple IPs
CloudRecon scrape -i 1.2.3.4,5.6.7.8

# CIDR range
CloudRecon scrape -i 192.168.1.0/24

# From file
CloudRecon scrape -i ips.txt

# With JSON output
CloudRecon scrape -i ips.txt -j | tee certs.json

# Multiple ports
CloudRecon scrape -i ips.txt -p 443,8443,9443

# High concurrency
CloudRecon scrape -i ips.txt -c 200
```

### 2. Store in Local Database

**Command**: `store`

```bash
# Store certificates in database
apollo-cloudrecon store \
  --input ips.txt \
  --database apollo-certs.db \
  --concurrent 100

# Creates SQLite database with:
# - IP addresses
# - Ports
# - Organizations
# - Common Names
# - SANs (Subject Alternative Names)
```

### 3. Query Database

**Command**: `retr` (retrieve)

```bash
# Query by organization
CloudRecon retr -org "Suspect Corp"

# Query by Common Name
CloudRecon retr -cn "admin"

# Query by SAN
CloudRecon retr -san "api"

# Query by IP
CloudRecon retr -ip "192.168"

# Get all results
CloudRecon retr -all

# Count results
CloudRecon retr -num
```

---

## Apollo Integration

### Cryptocurrency Investigation

**Scenario**: Map crypto exchange cloud infrastructure

```bash
# Phase 1: Enumerate exchange IPs
exchange_ips = apollo.osint.resolve_domain('suspect-exchange.com')
related_ips = apollo.osint.find_related_ips(exchange_ips)

# Phase 2: CloudRecon scan
apollo-cloudrecon crypto-infrastructure \
  --ips $exchange_ips,$related_ips \
  --ports 443,8443,3000,8080 \
  --store-db crypto-exchange-certs.db

# Phase 3: Analyze certificates
analysis = apollo-cloudrecon analyze \
  --db crypto-exchange-certs.db \
  --find-patterns \
  --map-infrastructure

# Discovers:
# - All subdomains (via SAN)
# - Cloud providers (AWS, Azure, GCP)
# - Organization structure
# - Hidden services
# - Development environments
# - Admin panels
# - API endpoints
```

**Intelligence Value**:
- Complete infrastructure map
- Cloud service providers
- Development vs. production environments
- Organization relationships
- Hidden/internal services

### Predator Platform Investigation

**Scenario**: Discover messaging platform infrastructure

```bash
# Scan messaging platform infrastructure
apollo-cloudrecon predator-platform \
  --target suspicious-chat-site.com \
  --scan-related-ips \
  --store-db chat-platform-certs.db \
  --focus message-servers,file-storage,user-database

# Query for admin panels
apollo-cloudrecon query \
  --db chat-platform-certs.db \
  --search "admin" \
  --priority high
```

---

## Massive Scale Scanning

### Scan Entire IP Ranges

```bash
# Download global IPv4 ranges
wget https://raw.githubusercontent.com/lord-alfred/ipranges/main/all/ipv4_merged.txt

# Mass scan (run in tmux/screen)
apollo-cloudrecon mass-scan \
  --input ipv4_merged.txt \
  --concurrent 500 \
  --output apollo-global-certs.db \
  --compress

# Discovers certificates globally
# Builds massive infrastructure database
# Useful for:
# - Finding criminal infrastructure worldwide
# - Discovering hiding criminal servers
# - Mapping dark web hosting
# - Identifying money laundering services
```

---

## Integration with Other Tools

### CloudRecon + BBOT + dnsReaper

**Complete Cloud Discovery Pipeline**:

```bash
# Ultimate cloud reconnaissance
apollo-cloud-recon-ultimate \
  --target target.com \
  --pipeline cloudrecon,bbot,dnsreaper

# Pipeline:
# 1. BBOT: Discover all subdomains
# 2. Resolve subdomains to IPs
# 3. CloudRecon: Scan IP ranges for certificates
# 4. Extract SANs to find more subdomains
# 5. BBOT: Scan newly discovered subdomains (recursive)
# 6. dnsReaper: Check all for takeover
# 7. Result: Complete infrastructure map + takeover opportunities
```

### CloudRecon + cloud_enum

```bash
# Multi-cloud enumeration
apollo-cloud-discovery \
  --tool1 cloudrecon \  # Certificate-based discovery
  --tool2 cloud-enum \  # Keyword permutation
  --target target-company \
  --clouds aws,azure,gcp

# Comprehensive cloud asset discovery
```

---

## Apollo Intelligence Feeding

### Automatic Intelligence Integration

```go
// Feed CloudRecon data to Apollo intelligence
package main

import "github.com/apollo/intelligence"

func feedToApollo(certData CertificateData) {
    // Feed to Neo4j
    apollo.Neo4j.CreateNodes({
        "type": "CERTIFICATE",
        "cn": certData.CommonName,
        "san": certData.SANs,
        "org": certData.Organization,
        "ip": certData.IP
    })
    
    // Feed to Elasticsearch
    apollo.Elasticsearch.Index({
        "index": "cloud-infrastructure",
        "document": certData
    })
    
    // Feed to Intelligence Fusion
    apollo.IntelligenceFusion.Ingest({
        "source": "cloudrecon",
        "type": "cloud-infrastructure",
        "data": certData
    })
}
```

---

## Database Schema

### SQLite Database Structure

```sql
-- CloudRecon database schema
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    organization TEXT,
    common_name TEXT,
    san TEXT,  -- Comma-separated SANs
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    case_id TEXT,
    INDEX(ip),
    INDEX(organization),
    INDEX(common_name),
    INDEX(san)
);

-- Apollo enhancements
CREATE TABLE certificate_intelligence (
    cert_id INTEGER,
    intelligence_type TEXT,  -- 'crypto', 'predator', 'general'
    risk_score REAL,
    related_cases TEXT,
    notes TEXT,
    FOREIGN KEY(cert_id) REFERENCES certificates(id)
);
```

---

## Use Cases

### 1. Criminal Organization Infrastructure Mapping

```bash
# Map entire criminal organization
apollo-cloudrecon map-org \
  --organization "Suspect Criminal Org" \
  --scan-entire-ipspace \
  --duration 24h \
  --case CRIMINAL-ORG-2026

# Discovers:
# - All domains owned by organization
# - All cloud services
# - All IP addresses
# - Complete infrastructure map
# - Hidden services
# - Development environments
```

### 2. Crypto Mining Farm Discovery

```bash
# Find hidden crypto mining operations
apollo-cloudrecon find-mining \
  --search-patterns "mine,mining,pool,crypto" \
  --scan-ranges cloud-provider-ranges.txt \
  --indicators high-cpu-instances

# Discovers illegal crypto mining farms
```

### 3. Dark Web Hosting Discovery

```bash
# Find dark web marketplace hosting
apollo-cloudrecon darkweb-hosting \
  --organizations darkweb-hosting-providers.txt \
  --identify-onion-hosting \
  --correlate-with-darkweb-markets
```

---

## Performance Configuration

### High-Speed Scanning

```yaml
cloudrecon:
  performance:
    concurrent_goroutines: 500  # Very high concurrency
    timeout: 4                  # seconds
    ports: [443, 8443, 9443]
    retry_failed: false
    
  optimization:
    skip_invalid_certs: true
    cache_results: true
    batch_db_inserts: 1000
```

---

## Quick Reference

### Common Operations

```bash
# Scan and store
CloudRecon store -i ips.txt -db apollo.db

# Query organization
CloudRecon retr -org "Suspect Corp" -db apollo.db

# Query Common Name
CloudRecon retr -cn "admin" -db apollo.db

# Query SAN
CloudRecon retr -san "api" -db apollo.db

# Export all
CloudRecon retr -all -db apollo.db > all-certs.txt
```

### Integration with Apollo

```bash
# Apollo wrapper commands
apollo-cloudrecon scan-and-feed \
  --ips ips.txt \
  --feed-to neo4j,elasticsearch

apollo-cloudrecon query-and-investigate \
  --org "Suspect Corp" \
  --trigger-bugtrace-ai

apollo-cloudrecon continuous-monitor \
  --targets monitoring-ips.txt \
  --alert-on new-certs,changes
```

---

## Statistics

```
CloudRecon in Apollo
═══════════════════════════════════════

Scanning:
  - Concurrent: Up to 500 goroutines
  - Speed: Depends on network, very fast
  - Ports: Customizable (default 443)

Database:
  - Type: SQLite
  - Size: Scales to millions of certs
  - Query: Fast indexed lookups
  
Intelligence:
  - Auto-feed: Neo4j, Elasticsearch
  - Real-time: Yes
  - Correlation: With OSINT, blockchain data

Integration:
  - BBOT: ✅ Pipeline ready
  - SubHunterX: ✅ Workflow ready
  - cloud_enum: ✅ Combined scanning
  - dnsReaper: ✅ Subdomain correlation

Status: ✅ Operational
```

---

## References

- **CloudRecon Repository**: https://github.com/blablablasealsaresoft/CloudRecon
- **Apollo Cloud Reconnaissance**: `../README.md`
- **cloud_enum Integration**: `../cloud-enum/`

---

**Integration Date**: January 13, 2026  
**Status**: ✅ Integrated  
**Language**: Go (high performance)  
**Purpose**: Cloud infrastructure mapping via certificate analysis  
**Mission**: Discover criminal cloud infrastructure for crypto and predator investigations
