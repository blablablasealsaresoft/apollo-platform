# Email Intelligence System

Comprehensive email OSINT and intelligence gathering toolkit for threat intelligence operations.

## Overview

The Email Intelligence System is a powerful suite of tools for investigating email addresses, discovering associated accounts, analyzing email reputation, and correlating information across multiple sources.

## Components

### 1. **email_intel.py** - Main Email Intelligence Module

The orchestrator that coordinates all email intelligence gathering operations.

#### Features:
- Comprehensive email investigation
- Multi-source intelligence gathering
- Risk scoring and assessment
- Batch processing capabilities
- Multiple export formats (JSON, CSV, HTML)

#### Usage:
```python
from email_intel import EmailIntelligence

# Initialize with API keys
config = {
    'emailrep_api_key': 'YOUR_EMAILREP_KEY',
    'hunter_api_key': 'YOUR_HUNTER_KEY'
}

email_intel = EmailIntelligence(config)

# Single email investigation
profile = email_intel.investigate("target@example.com")

# Access results
print(f"Risk Score: {profile.risk_score}/100")
print(f"Risk Level: {profile.summary['risk_level']}")
print(f"Total Accounts: {len(profile.accounts)}")
print(f"Total Breaches: {len(profile.breaches)}")

# Batch investigation
emails = ["email1@example.com", "email2@example.com"]
profiles = email_intel.batch_investigate(emails)

# Export results
json_output = email_intel.export_profile(profile, format='json')
html_report = email_intel.export_profile(profile, format='html')
```

### 2. **holehe_integration.py** - Account Enumeration

Checks if an email is registered on 120+ platforms including social media, gaming, shopping, and more.

#### Features:
- Asynchronous checking across multiple platforms
- Categorized platform checks (social media, gaming, professional, etc.)
- Response time tracking
- Confidence scoring

#### Supported Categories:
- Social Media (Twitter, Instagram, Facebook, LinkedIn, etc.)
- Professional (GitHub, GitLab, StackOverflow)
- Gaming (Steam, Epic Games, Xbox, PlayStation)
- Shopping (Amazon, eBay, Etsy)
- Communication (Discord, Slack, Skype)
- Entertainment (Spotify, Netflix, SoundCloud)
- Finance (PayPal, Venmo)
- Dating (Tinder, Bumble)

#### Usage:
```python
from holehe_integration import HoleheIntegration

holehe = HoleheIntegration()

# Check all platforms
results = holehe.check("target@example.com")

# Check specific category
social_platforms = holehe.get_platforms_by_category('social_media')
results = holehe.check("target@example.com", platforms=social_platforms)

# Get statistics
stats = holehe.get_statistics(results)
print(f"Found on {stats['total_found']} platforms")
```

### 3. **email_validator.py** - Email Validation

Comprehensive email validation including syntax, domain, MX records, and SMTP verification.

#### Features:
- RFC 5322 syntax validation
- Domain validation
- MX record checking
- SMTP verification (optional)
- Disposable email detection
- Role-based email detection
- Free provider detection
- SPF/DMARC record lookup

#### Usage:
```python
from email_validator import EmailValidator

validator = EmailValidator(verify_smtp=False)

# Validate email
result = validator.validate("test@example.com")

if result['valid']:
    print("Email is valid!")
    print(f"Domain: {result['domain']}")
    print(f"MX Records: {result['mx_records']}")
else:
    print(f"Invalid: {result['errors']}")

# Check for disposable/role-based
if result['disposable']:
    print("Warning: Disposable email detected")
if result['role_based']:
    print("Warning: Role-based email detected")

# Get DNS records
mx_records = validator.get_mx_records("example.com")
spf_record = validator.get_spf_record("example.com")
dmarc_record = validator.get_dmarc_record("example.com")
```

### 4. **email_reputation.py** - Reputation Analysis

Analyzes email reputation using multiple sources including EmailRep.io, blacklists, and breach databases.

#### Features:
- EmailRep.io integration
- Spam blacklist checking
- Malicious activity detection
- Phishing activity detection
- Credential leak detection
- Spam score calculation (0-100)
- Risk assessment

#### Usage:
```python
from email_reputation import EmailReputation

reputation = EmailReputation(api_key='YOUR_API_KEY')

# Check reputation
result = reputation.check("suspicious@example.com")

print(f"Reputation: {result['reputation']}")
print(f"Spam Score: {result['spam_score']}/100")
print(f"Malicious: {result['malicious']}")
print(f"Blacklisted: {result['blacklisted']}")

# Get risk assessment
assessment = reputation.get_risk_assessment("target@example.com")
print(f"Risk Level: {assessment['risk_level']}")
print(f"Risk Score: {assessment['risk_score']}/100")
print(f"Recommendation: {assessment['recommendation']}")
```

### 5. **email_hunter.py** - Email Discovery

Discovers and verifies company emails using Hunter.io API and pattern detection.

#### Features:
- Hunter.io integration
- Email pattern detection
- Email verification
- Employee email discovery
- Domain information lookup
- Email generation from patterns

#### Usage:
```python
from email_hunter import EmailHunter

hunter = EmailHunter(api_key='YOUR_HUNTER_API_KEY')

# Find emails for domain
emails = hunter.find_emails("example.com", limit=10)

# Verify email
verification = hunter.verify_email("john.doe@example.com")
print(f"Verified: {verification['verified']}")
print(f"Score: {verification['score']}")

# Get email pattern
pattern = hunter.get_email_pattern("example.com")
print(f"Pattern: {pattern.pattern}")
print(f"Example: {pattern.example}")

# Generate email from pattern
email = hunter.generate_email("John", "Doe", "example.com")

# Find employee emails
employees = hunter.find_employee_emails("example.com", department="engineering")
```

### 6. **email_format.py** - Email Format Detection

Detects company email patterns and generates employee email addresses.

#### Features:
- Pattern detection from samples
- Email generation from patterns
- All variation generation
- Pattern validation
- Permutation generation

#### Supported Patterns:
- `{first}.{last}` - john.doe@example.com
- `{first}{last}` - johndoe@example.com
- `{f}{last}` - jdoe@example.com
- `{first}` - john@example.com
- `{last}` - doe@example.com
- And many more...

#### Usage:
```python
from email_format import EmailFormatFinder, PermutationGenerator

finder = EmailFormatFinder()

# Detect pattern from samples
samples = [
    "john.doe@company.com",
    "jane.smith@company.com"
]
pattern = finder.detect_pattern(samples)
print(f"Pattern: {pattern.pattern} (Confidence: {pattern.confidence:.2%})")

# Generate email
email = finder.generate_email("John", "Doe", "company.com", "{first}.{last}")

# Generate all variations
variations = finder.generate_all_variations("John", "Doe", "company.com")

# Generate permutations
gen = PermutationGenerator()
perms = gen.generate_permutations("John", "Doe", "company.com",
                                  include_numbers=True)
```

### 7. **email_header_analyzer.py** - Header Analysis

Parses and analyzes email headers for forensic investigation.

#### Features:
- Email header parsing
- IP address extraction
- Routing path analysis
- Authentication check (SPF, DKIM, DMARC)
- Suspicious indicator detection
- Reverse DNS lookup
- Geographic location (with integration)

#### Usage:
```python
from email_header_analyzer import EmailHeaderAnalyzer

analyzer = EmailHeaderAnalyzer()

# Analyze headers
with open('email_headers.txt', 'r') as f:
    headers = f.read()

analysis = analyzer.analyze(headers)

print(f"From: {analysis['from_address']}")
print(f"Hops: {analysis['hop_count']}")
print(f"IPs: {analysis['ip_addresses']}")
print(f"SPF: {analysis['spf_result']}")
print(f"DKIM: {analysis['dkim_result']}")
print(f"DMARC: {analysis['dmarc_result']}")

# Check for suspicious indicators
if analysis['suspicious_indicators']:
    print("\nSuspicious Indicators:")
    for indicator in analysis['suspicious_indicators']:
        print(f"  - {indicator}")

# Export report
report = analyzer.export_analysis(analysis, format='text')
print(report)
```

### 8. **email_correlator.py** - Cross-Source Correlation

Correlates information from multiple sources to build comprehensive profiles.

#### Features:
- Email-to-username mapping
- Related email discovery
- Social media account linking
- Shared attribute detection
- Account linking
- Confidence scoring

#### Usage:
```python
from email_correlator import EmailCorrelator

correlator = EmailCorrelator()

# Correlate email with data
data = {
    'accounts': [...],
    'breaches': [...],
    'social_media': [...]
}

result = correlator.correlate("target@example.com", data)

print(f"Username: {result['username']}")
print(f"Related Emails: {len(result['related_emails'])}")
print(f"Related Usernames: {len(result['related_usernames'])}")
print(f"Confidence: {result['confidence_score']:.2%}")

# Link multiple accounts
linked = correlator.link_accounts([
    "john.doe@example.com",
    "johndoe@gmail.com",
    "j.doe@company.com"
])
print(f"Same Person Probability: {linked['likely_same_person']:.2%}")
```

## Installation

### Requirements:
```bash
pip install requests aiohttp dnspython email-validator
```

### Optional Dependencies:
```bash
# For enhanced features
pip install geoip2 maxminddb
```

## API Keys

The system integrates with several services that require API keys:

### EmailRep.io
- Free tier: 100 requests/day
- Signup: https://emailrep.io/

### Hunter.io
- Free tier: 50 requests/month
- Signup: https://hunter.io/

### Have I Been Pwned (optional)
- Requires API key for automated checking
- Signup: https://haveibeenpwned.com/API/Key

## Configuration

Create a configuration file or dictionary:

```python
config = {
    'emailrep_api_key': 'your_emailrep_key',
    'hunter_api_key': 'your_hunter_key',
    'hibp_api_key': 'your_hibp_key',  # Optional

    # Settings
    'smtp_timeout': 10,
    'dns_timeout': 5,
    'verify_smtp': False,  # Enable SMTP verification
    'rate_limit': 50,
    'cache_ttl': 3600
}
```

## Complete Investigation Example

```python
from email_intel import EmailIntelligence
import json

# Initialize
config = {
    'emailrep_api_key': 'YOUR_KEY',
    'hunter_api_key': 'YOUR_KEY'
}

intel = EmailIntelligence(config)

# Investigate email
target = "target@example.com"
profile = intel.investigate(target, deep=True)

# Display results
print(f"\n{'='*70}")
print(f"EMAIL INTELLIGENCE REPORT: {target}")
print(f"{'='*70}")

print(f"\nRisk Assessment:")
print(f"  Level: {profile.summary['risk_level']}")
print(f"  Score: {profile.risk_score}/100")

print(f"\nValidation:")
print(f"  Valid: {profile.validation['valid']}")
print(f"  Disposable: {profile.validation['disposable']}")
print(f"  Role-based: {profile.validation['role_based']}")

print(f"\nReputation:")
print(f"  Status: {profile.reputation.get('reputation', 'unknown')}")
print(f"  Spam Score: {profile.reputation.get('spam_score', 0)}/100")
print(f"  Malicious: {profile.reputation.get('malicious', False)}")

print(f"\nAccounts Found: {len(profile.accounts)}")
for account in profile.accounts[:5]:
    print(f"  - {account['platform']}: {account.get('username', 'N/A')}")

print(f"\nBreaches: {len(profile.breaches)}")

print(f"\nRelated Information:")
print(f"  Related Emails: {len(profile.related_emails)}")
print(f"  Related Usernames: {len(profile.related_usernames)}")

# Export full report
with open('email_report.json', 'w') as f:
    json.dump(profile.__dict__, f, indent=2)

with open('email_report.html', 'w') as f:
    f.write(intel.export_profile(profile, format='html'))

print(f"\nReports exported successfully!")
```

## Batch Processing

```python
from email_intel import EmailIntelligence

intel = EmailIntelligence(config)

# Load emails from file
with open('targets.txt', 'r') as f:
    emails = [line.strip() for line in f if line.strip()]

# Batch investigate
profiles = intel.batch_investigate(emails, workers=5)

# Generate summary
print(f"Investigated {len(profiles)} emails")

high_risk = [p for p in profiles if p.risk_score >= 50]
print(f"High risk emails: {len(high_risk)}")

for profile in high_risk:
    print(f"  {profile.email} - Risk: {profile.risk_score}/100")
```

## Best Practices

1. **API Rate Limits**: Be mindful of API rate limits
2. **SMTP Verification**: Use cautiously as it can be slow and blocked
3. **Caching**: Enable caching for repeated queries
4. **Parallel Processing**: Use batch operations for multiple emails
5. **Error Handling**: Always handle API errors gracefully
6. **Privacy**: Ensure compliance with data protection regulations

## Legal Considerations

- Only investigate emails you have authorization to research
- Comply with local data protection laws (GDPR, CCPA, etc.)
- Respect Terms of Service for all integrated APIs
- Use responsibly for legitimate security research and threat intelligence

## Troubleshooting

### DNS Resolution Issues
```python
# Increase timeout
validator = EmailValidator(dns_timeout=10)
```

### API Rate Limiting
```python
# Add delays between requests
import time
time.sleep(1)  # Wait 1 second between requests
```

### SMTP Connection Issues
```python
# Disable SMTP verification
validator = EmailValidator(verify_smtp=False)
```

## Performance Tips

1. Use async operations for checking multiple platforms
2. Enable caching to avoid duplicate lookups
3. Use batch operations when processing multiple emails
4. Adjust worker count based on your system resources
5. Set appropriate timeouts to avoid hanging requests

## Future Enhancements

- [ ] Machine learning-based risk scoring
- [ ] Integration with more breach databases
- [ ] Advanced correlation algorithms
- [ ] Real-time monitoring capabilities
- [ ] Graph visualization of relationships
- [ ] Automated reporting and alerting
- [ ] Integration with SIEM systems

## Support

For issues, questions, or contributions, please refer to the main Apollo framework documentation.

## License

Part of the Apollo Threat Intelligence Framework.

---

**Author**: Agent 10 - Email Intelligence Specialist
**Version**: 1.0
**Last Updated**: 2026-01-14
