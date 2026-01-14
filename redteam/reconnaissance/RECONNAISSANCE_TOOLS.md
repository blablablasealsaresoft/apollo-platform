# Reconnaissance Tools Integration

This directory contains tools and integrations for the reconnaissance phase of red team operations.

## Tools from Red-Teaming-Toolkit

Source: [Red-Teaming-Toolkit](https://github.com/blablablasealsaresoft/Red-Teaming-Toolkit)

### Port Scanning & Network Discovery

#### automation/
- **RustScan** - Modern port scanner (finds ports in 3 seconds)
  ```bash
  rustscan -a target.com -- -A -sC
  ```
  
- **Masscan** - Fast TCP port scanner
  ```bash
  masscan -p1-65535 target.com --rate=10000
  ```
  
- **Nmap** - Network exploration and security auditing
  ```bash
  nmap -sV -sC -O target.com
  ```

### Subdomain Enumeration

#### subdomain-operations/subdomain-discovery/
- **Sublist3r** - Fast subdomain enumeration
  ```bash
  python sublist3r.py -d target.com
  ```
  
- **Subfinder** - Passive subdomain discovery
  ```bash
  subfinder -d target.com
  ```
  
- **Assetfinder** - Find domains and subdomains
  ```bash
  assetfinder --subs-only target.com
  ```
  
- **Findomain** - Fast and cross-platform subdomain enumerator
  ```bash
  findomain -t target.com
  ```

#### subdomain-operations/subdomain-bruteforce/
- **dnscan** - Wordlist-based DNS subdomain scanner
  ```bash
  python dnscan.py -d target.com -w wordlist.txt
  ```
  
- **fierce** - DNS reconnaissance tool
  ```bash
  fierce --domain target.com
  ```

#### subdomain-operations/certificate-transparency/
- **cert.sh** - Certificate transparency log search
- **crt.sh integration** - Automated CT log monitoring

### Cloud Reconnaissance

#### cloud-reconnaissance/cloud-enum/
- **cloud_enum** - Multi-cloud OSINT tool
  ```bash
  python cloud_enum.py -k target -k target-backup
  ```

#### cloud-reconnaissance/aws-enumeration/
- **S3Scanner** - Scan for open S3 buckets
  ```bash
  python s3scanner.py --list bucket-list.txt
  ```
  
- **aws_stealth_perm_enum** - AWS permission enumeration
- **CloudBrute** - Cloud infrastructure keyword permutation
- **ScoutSuite** - Multi-cloud security auditing

#### cloud-reconnaissance/azure-recon/
- **MicroBurst** - Azure security assessment
- **ROADtools** - Azure AD exploration

#### cloud-reconnaissance/gcp-discovery/
- **GCPBucketBrute** - Google Cloud Storage bucket enumeration
- **gcp-enum** - GCP resource enumeration

### Web Reconnaissance

#### web-reconnaissance/spiderfoot/
- **SpiderFoot** - OSINT automation tool
  ```bash
  python sf.py -s target.com -m all
  ```
  
- **Integration**: Feeds data into Apollo intelligence-fusion service

#### web-reconnaissance/witnessme/
- **WitnessMe** - Web inventory and screenshots
  ```bash
  witnessme screenshot https://target.com
  ```

#### web-reconnaissance/nuclei-scanner/
- **Nuclei** - Fast vulnerability scanner
  ```bash
  nuclei -u https://target.com -t exposures/ -t cves/
  ```

#### web-reconnaissance/custom-crawlers/
- **gospider** - Fast web spider
- **hakrawler** - Web crawler for gathering URLs
- **gau** - Fetch known URLs from multiple sources

### GitHub Intelligence

#### github-intelligence/secret-scanning/
- **gitleaks** - Detect hardcoded secrets
  ```bash
  gitleaks detect --source . --verbose
  ```
  
- **TruffleHog** - Find credentials in git history
  ```bash
  trufflehog git https://github.com/target/repo
  ```
  
- **Gitrob** - GitHub organization reconnaissance
  ```bash
  gitrob analyze target-org
  ```

#### github-intelligence/gato-toolkit/
- **Gato** - GitHub self-hosted runner attacks
  ```bash
  gato e --token TOKEN --org target-org
  ```

#### github-intelligence/repo-analysis/
- **GitGot** - Search GitHub for sensitive information
- **GitDorker** - GitHub dorking tool
- **GitRob** - Reconnaissance tool for GitHub

### Active Directory Reconnaissance

#### Located in: `reconnaissance/`

- **BloodHound** - AD attack path analysis
  ```bash
  SharpHound.exe -c All
  ```
  
- **ADRecon** - AD enumeration
  ```bash
  .\ADRecon.ps1 -OutputDir C:\temp
  ```
  
- **PingCastle** - AD security audit
  ```bash
  PingCastle.exe --healthcheck
  ```

### Email & User Enumeration

#### Located in: `../../intelligence/osint-engine/`

- **buster** - Email reconnaissance
- **linkedin2username** - Generate usernames from LinkedIn
- **CrossLinked** - LinkedIn enumeration tool

### Domain & DNS Intelligence

- **spoofcheck** - Check for SPF/DMARC weaknesses
  ```bash
  python spoofcheck.py target.com
  ```
  
- **DNSRecon** - DNS enumeration
  ```bash
  python dnsrecon.py -d target.com -t std
  ```

## Automation Integration

### BBOT Integration

Location: `automation/bbot-integration/`

```bash
# Install BBOT
pip install bbot

# Run comprehensive scan
bbot -t target.com -f subdomain-enum -f cloud-enum -f web-basic

# Custom Apollo modules
bbot -t target.com -m apollo-crypto-intel -m apollo-social-recon
```

### SubHunterX Integration

Location: `automation/subhunterx/`

Automated workflow for:
1. Subdomain discovery
2. Vulnerability scanning
3. Exploit chaining
4. Evidence collection

### Amass Integration

Location: `automation/amass-integration/`

```bash
# Full reconnaissance
amass enum -d target.com -o domains.txt

# Active scanning
amass enum -active -d target.com -p 80,443,8080,8443

# Integration with Apollo intelligence fusion
amass enum -d target.com | apollo-intel ingest --source amass
```

## Apollo-Specific Enhancements

### AI-Enhanced Reconnaissance

All reconnaissance tools feed into Apollo's AI engines for:
- **Automated prioritization** of discovered assets
- **Risk scoring** based on vulnerability assessment
- **Correlation** with existing intelligence
- **Predictive analysis** of attack surface

### Intelligence Fusion

Reconnaissance data automatically flows to:
- **Intelligence Fusion Service** - Correlation and analysis
- **Neo4j Graph Database** - Relationship mapping
- **Elasticsearch** - Searchable intelligence
- **Real-time Dashboards** - Live reconnaissance monitoring

### Operational Security

All reconnaissance activities:
- Logged for audit compliance
- Proxied through rotating infrastructure
- Rate-limited to avoid detection
- Monitored by RedELK

## Configuration

### Global Reconnaissance Config

Edit: `config/recon-config.yaml`

```yaml
reconnaissance:
  concurrency: 50
  timeout: 300
  retries: 3
  stealth_mode: true
  
  rate_limits:
    requests_per_second: 10
    max_concurrent: 50
  
  proxies:
    enabled: true
    rotation: true
    sources:
      - socks5://localhost:9050  # Tor
      - http://proxy-pool:8080
  
  output:
    format: json
    elasticsearch: true
    neo4j: true
    files: true
```

### Tool-Specific Configs

Each tool has its own configuration in its subdirectory:
- `automation/bbot-integration/bbot.yml`
- `subdomain-operations/dnsreaper/config.yml`
- `cloud-reconnaissance/cloud-enum/config.yml`

## Usage Examples

### Cryptocurrency Investigation

```bash
# Enumerate crypto exchange infrastructure
./scripts/crypto-recon.sh target-exchange.com

# Output:
# - Subdomains discovered
# - Cloud resources identified
# - API endpoints enumerated
# - SSL certificate intelligence
# - GitHub repositories found
```

### Predator Investigation

```bash
# Social media and web presence reconnaissance
./scripts/predator-recon.sh target-username

# Output:
# - Social media profiles
# - Email addresses
# - Phone numbers  
# - Associated domains
# - GitHub activity
```

## Integration with Other Apollo Components

### Data Flow

```
Reconnaissance Tools
    ↓
Apollo Intelligence Fusion
    ↓
Neo4j Graph Database
    ↓
Web Console Dashboard
```

### Automated Workflows

1. **Continuous Monitoring**
   - Scheduled reconnaissance scans
   - Real-time subdomain monitoring
   - Cloud infrastructure tracking

2. **Alert Generation**
   - New subdomains discovered
   - Exposed sensitive data found
   - Vulnerable services identified

3. **Investigation Enrichment**
   - Automatic asset discovery
   - Infrastructure mapping
   - Evidence collection

## Best Practices

1. **Always use stealth mode** in production
2. **Rotate proxies** for attribution avoidance
3. **Rate limit requests** to avoid detection
4. **Log all activities** for audit compliance
5. **Validate targets** before scanning
6. **Respect scope** of engagement

## References

- [MITRE ATT&CK - Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
- [Apollo Documentation](../../docs/user-guides/red-team-operations/)

---

**Integration Status**: ✅ Mapped  
**Tools Count**: 40+  
**Automation**: BBOT, SubHunterX, Amass  
**AI Enhancement**: Active
