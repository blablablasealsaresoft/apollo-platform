# Email Intelligence System - Quick Start Guide

## Installation

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\email-intelligence

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. Copy the example config:
```bash
copy config.example.json config.json
```

2. Edit `config.json` and add your API keys:
```json
{
  "api_keys": {
    "emailrep": "YOUR_EMAILREP_API_KEY",
    "hunter": "YOUR_HUNTER_API_KEY"
  }
}
```

## Quick Usage

### 1. Simple Email Validation

```python
from email_validator import EmailValidator

validator = EmailValidator()
result = validator.validate("test@example.com")

print(f"Valid: {result['valid']}")
print(f"MX Records: {result['mx_records']}")
```

### 2. Complete Investigation

```python
from email_intel import EmailIntelligence

config = {
    'emailrep_api_key': 'YOUR_KEY',
    'hunter_api_key': 'YOUR_KEY'
}

intel = EmailIntelligence(config)
profile = intel.investigate("target@example.com")

print(f"Risk Score: {profile.risk_score}/100")
print(f"Risk Level: {profile.summary['risk_level']}")
print(f"Accounts Found: {len(profile.accounts)}")
```

### 3. Account Enumeration

```python
from holehe_integration import HoleheIntegration

holehe = HoleheIntegration()
results = holehe.check("target@example.com")

for result in results:
    if result['exists']:
        print(f"Found on {result['platform']}")
```

### 4. Email Pattern Detection

```python
from email_format import EmailFormatFinder

finder = EmailFormatFinder()
samples = [
    "john.doe@company.com",
    "jane.smith@company.com"
]

pattern = finder.detect_pattern(samples)
print(f"Pattern: {pattern.pattern}")

# Generate email
email = finder.generate_email("John", "Doe", "company.com", pattern.pattern)
print(f"Generated: {email}")
```

### 5. Header Analysis

```python
from email_header_analyzer import EmailHeaderAnalyzer

analyzer = EmailHeaderAnalyzer()

with open('headers.txt', 'r') as f:
    headers = f.read()

analysis = analyzer.analyze(headers)
print(f"SPF: {analysis['spf_result']}")
print(f"DKIM: {analysis['dkim_result']}")
print(f"Suspicious: {len(analysis['suspicious_indicators'])} indicators")
```

## Run Examples

```bash
python example_usage.py
```

## API Keys

### EmailRep.io (Free)
- Sign up: https://emailrep.io/
- Free tier: 100 requests/day

### Hunter.io (Free/Paid)
- Sign up: https://hunter.io/
- Free tier: 50 requests/month

## Basic Workflow

```python
from email_intel import EmailIntelligence
import json

# Initialize
intel = EmailIntelligence({
    'emailrep_api_key': 'YOUR_KEY',
    'hunter_api_key': 'YOUR_KEY'
})

# Investigate
profile = intel.investigate("target@example.com", deep=True)

# View results
print(json.dumps({
    'email': profile.email,
    'risk_level': profile.summary['risk_level'],
    'risk_score': profile.risk_score,
    'valid': profile.validation['valid'],
    'accounts': len(profile.accounts),
    'breaches': len(profile.breaches)
}, indent=2))

# Export report
html = intel.export_profile(profile, format='html')
with open('report.html', 'w') as f:
    f.write(html)
```

## Batch Processing

```python
# Process multiple emails
emails = [
    "email1@example.com",
    "email2@example.com",
    "email3@example.com"
]

profiles = intel.batch_investigate(emails, workers=5)

# Filter high risk
high_risk = [p for p in profiles if p.risk_score >= 50]
print(f"High risk emails: {len(high_risk)}")
```

## Tips

1. **Start without SMTP verification** - It's slow and can be blocked
2. **Use caching** - Enable it for repeated queries
3. **Respect rate limits** - Especially on free API tiers
4. **Batch process** - More efficient for multiple emails
5. **Check logs** - Review for errors and warnings

## Common Issues

### DNS Timeouts
```python
validator = EmailValidator(dns_timeout=10)
```

### API Rate Limiting
```python
import time
time.sleep(1)  # Add delay between requests
```

### Import Errors
```bash
pip install --upgrade -r requirements.txt
```

## Next Steps

1. Read the full documentation: `README_EMAIL_INTEL.md`
2. Configure API keys in `config.json`
3. Run example scripts: `python example_usage.py`
4. Integrate into your workflow

## Support

For detailed documentation, see `README_EMAIL_INTEL.md`

For code examples, see `example_usage.py`

---

**Quick Reference Commands:**

```bash
# Validate email
python -c "from email_validator import EmailValidator; print(EmailValidator().validate('test@example.com'))"

# Check reputation
python -c "from email_reputation import EmailReputation; print(EmailReputation().check('test@example.com'))"

# Run all examples
python example_usage.py
```
