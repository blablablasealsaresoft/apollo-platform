# Phone Intelligence OSINT Toolkit

Comprehensive phone number intelligence gathering and investigation system. This toolkit provides deep analysis of phone numbers including carrier lookup, caller ID, social media linking, breach correlation, VoIP detection, SMS intelligence, and person attribution.

## Features

### Core Capabilities

- **Phone Validation**: Format validation, country code verification, number type detection
- **Carrier Lookup**: International carrier identification, network information
- **Caller ID**: Name identification, spam detection, reputation scoring
- **Social Media Linking**: Find associated social media accounts across multiple platforms
- **Breach Correlation**: Search data breach databases for phone number exposure
- **VoIP Detection**: Identify VoIP numbers and providers (Skype, Google Voice, etc.)
- **SMS Intelligence**: Gateway detection, bulk sender identification, message analysis
- **HLR Lookup**: Network status, roaming status, IMSI identification
- **Person Attribution**: Link phone numbers to individuals with names, addresses, emails

### Advanced Features

- **Batch Processing**: Investigate multiple numbers simultaneously
- **Risk Scoring**: Automatic risk assessment based on intelligence gathered
- **Export Reports**: Generate reports in JSON, HTML, and text formats
- **Parallel Processing**: Fast data gathering using concurrent requests
- **Comprehensive Correlation**: Link phones to emails, usernames, and other identifiers

## Installation

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\phone-intelligence
pip install -r requirements.txt
```

## Configuration

Create a configuration dictionary with your API keys:

```python
config = {
    'truecaller': {
        'api_key': 'YOUR_TRUECALLER_API_KEY',
        'installation_id': 'YOUR_INSTALLATION_ID'
    },
    'hlr': {
        'provider': 'hlr-lookups',  # or 'nexmo', 'twilio', 'numverify'
        'api_key': 'YOUR_HLR_API_KEY',
        'username': 'YOUR_USERNAME'
    },
    'phoneinfoga': {
        'api_url': 'http://localhost:5000',
        'use_cli': False,
        'google_dork': True
    },
    'correlator': {
        'dehashed_api_key': 'YOUR_DEHASHED_KEY',
        'snusbase_api_key': 'YOUR_SNUSBASE_KEY',
        'hibp_api_key': 'YOUR_HIBP_KEY'
    }
}
```

## Quick Start

### Basic Phone Investigation

```python
from phone_intel import PhoneIntelligence

# Initialize
phone_intel = PhoneIntelligence(config)

# Investigate a phone number
result = phone_intel.investigate("+1-555-0123", deep=True)

# Print summary
print(result['summary'])
print(f"Risk Score: {result['risk_score']}/100")

# Access specific data
print(f"Carrier: {result['basic_info']['carrier']}")
print(f"Location: {result['basic_info']['country']}")
print(f"Type: {result['basic_info']['number_type']}")

if result['caller_id'].get('name'):
    print(f"Registered to: {result['caller_id']['name']}")

if result['voip_analysis']['is_voip']:
    print(f"VoIP Provider: {result['voip_analysis']['provider']}")
```

### Phone Validation

```python
from phone_validator import PhoneValidator

validator = PhoneValidator()

# Validate phone number
result = validator.validate("+1-555-0123", region="US")

if result['is_valid']:
    print(f"Valid number: {result['normalized']}")
    print(f"Type: {result['metadata']['number_type']}")
    print(f"Region: {result['metadata']['region']}")
else:
    print(f"Invalid: {result['validation_errors']}")

# Quick checks
is_mobile = validator.is_mobile("+14155552671")
is_voip = validator.is_voip("+14155552671")
region = validator.get_region("+14155552671")

# Extract numbers from text
text = "Call me at +1-415-555-2671 or (555) 123-4567"
numbers = validator.extract_numbers(text, region="US")
print(f"Found numbers: {numbers}")
```

### Carrier Lookup (PhoneInfoga)

```python
from phoneinfoga_integration import PhoneInfogaClient

client = PhoneInfogaClient({
    'api_url': 'http://localhost:5000',
    'use_cli': False
})

# Lookup phone
result = client.lookup("+14155552671")

print(f"Carrier: {result['carrier']['name']}")
print(f"Country: {result['location']['country']}")
print(f"Line Type: {result['line_type']}")

# Check if mobile
if client.is_mobile("+14155552671"):
    print("This is a mobile number")

# Google dorking
dorks = client.google_dork_search("+14155552671")
for dork in dorks:
    print(f"Search: {dork['url']}")
```

### Caller ID Lookup (TrueCaller)

```python
from truecaller_integration import TrueCallerClient

truecaller = TrueCallerClient({
    'api_key': 'YOUR_API_KEY',
    'installation_id': 'YOUR_INSTALLATION_ID'
})

# Lookup caller ID
result = truecaller.lookup("+14155552671")

print(f"Name: {result['name']}")
print(f"Spam Score: {result['spam_score']}/100")

if result['is_spam']:
    print("WARNING: Reported as spam!")

# Get social profiles
profiles = truecaller.get_social_profiles("+14155552671")
for profile in profiles:
    print(f"{profile['service']}: {profile['url']}")

# Search by name
results = truecaller.search_by_name("John Smith", "US")
for person in results:
    print(f"{person['name']}: {person['phone']}")
```

### HLR Lookup

```python
from hlr_lookup import HLRLookup

hlr = HLRLookup({
    'provider': 'hlr-lookups',
    'api_key': 'YOUR_API_KEY',
    'username': 'YOUR_USERNAME'
})

# Perform HLR lookup
result = hlr.lookup("+14155552671")

print(f"Status: {result['status']}")
print(f"Network: {result['network']['network_name']}")
print(f"Country: {result['network']['country']}")

# Check status
if hlr.is_active("+14155552671"):
    print("Number is active on network")

if hlr.is_roaming("+14155552671"):
    print("Number is currently roaming")

if hlr.is_ported("+14155552671"):
    print("Number has been ported")
```

### VoIP Detection

```python
from voip_intelligence import VoIPIntelligence

voip = VoIPIntelligence()

# Analyze for VoIP
result = voip.analyze("+14155552671")

if result['is_voip']:
    print(f"VoIP Provider: {result['provider']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Features: {result['features']}")
    print(f"Detection Methods: {result['detection_methods']}")

# Check specific providers
skype_result = voip.check_skype("+991234567890")
if skype_result['is_skype']:
    print("This is a Skype number")

google_voice = voip.check_google_voice("+14155552671")
if google_voice['is_google_voice']:
    print("This is a Google Voice number")

# Get supported providers
providers = voip.get_voip_providers_list()
for provider in providers:
    print(f"{provider['name']}: {provider['description']}")
```

### SMS Intelligence

```python
from sms_intelligence import SMSIntelligence

sms = SMSIntelligence()

# Analyze phone for SMS characteristics
result = sms.analyze("+14155552671")

if result['is_sms_gateway']:
    print(f"SMS Gateway: {result['gateway_provider']}")

if result['is_disposable']:
    print("WARNING: Disposable/temporary number")

if result['is_bulk_sender']:
    print("Bulk SMS sender detected")

# Analyze SMS message
message = "URGENT: Click here to claim your prize!"
msg_analysis = sms.analyze_message(message)

print(f"Spam Score: {msg_analysis['spam_score']}/100")
print(f"Message Type: {msg_analysis['message_type']}")

if msg_analysis['is_likely_spam']:
    print("WARNING: Message is likely spam")

# Detect SMS campaign
messages = [
    {'sender': '+14155551234', 'text': 'Special offer!', 'timestamp': '2024-01-01'},
    {'sender': '+14155551234', 'text': 'Special offer!', 'timestamp': '2024-01-01'},
]

campaign = sms.detect_campaign(messages)
if campaign['is_campaign']:
    print(f"SMS campaign detected with {campaign['unique_senders']} senders")
```

### Phone Correlation

```python
from phone_correlator import PhoneCorrelator

correlator = PhoneCorrelator({
    'dehashed_api_key': 'YOUR_DEHASHED_KEY',
    'snusbase_api_key': 'YOUR_SNUSBASE_KEY'
})

# Correlate phone number
result = correlator.correlate("+14155552671")

# Social media accounts
if result['social_media']['total_found'] > 0:
    print(f"Found {result['social_media']['total_found']} social media accounts")

    if result['social_media']['facebook']:
        print(f"Facebook: {result['social_media']['facebook']}")

    if result['social_media']['twitter']:
        print(f"Twitter: {result['social_media']['twitter']}")

# Data breaches
if result['breaches']['total_breaches'] > 0:
    print(f"Found in {result['breaches']['total_breaches']} data breaches")
    print(f"Breaches: {', '.join(result['breaches']['found_in'][:5])}")
    print(f"Exposed data: {', '.join(result['breaches']['exposed_data'])}")

# Related information
print(f"Related emails: {result['related_emails']}")
print(f"Related usernames: {result['related_usernames']}")
print(f"Related names: {result['related_names']}")

# Check phone-email linkage
linkage = correlator.link_to_email("+14155552671", "user@example.com")
if linkage['linked']:
    print(f"Phone and email are linked (confidence: {linkage['confidence']})")
    print(f"Evidence: {linkage['evidence']}")
```

### Batch Processing

```python
from phone_intel import PhoneIntelligence

phone_intel = PhoneIntelligence(config)

# Investigate multiple numbers
numbers = [
    "+1-555-0123",
    "+44-20-7123-4567",
    "+91-98765-43210"
]

results = phone_intel.batch_investigate(numbers, deep=False)

for number, data in results.items():
    print(f"\n{number}:")
    print(f"  Summary: {data.get('summary')}")
    print(f"  Risk: {data.get('risk_score')}/100")
```

### Export Reports

```python
from phone_intel import PhoneIntelligence

phone_intel = PhoneIntelligence(config)

# Investigate
result = phone_intel.investigate("+1-555-0123")

# Export as JSON
json_report = phone_intel.export_report(result, format='json')
with open('phone_report.json', 'w') as f:
    f.write(json_report)

# Export as text
text_report = phone_intel.export_report(result, format='txt')
with open('phone_report.txt', 'w') as f:
    f.write(text_report)

# Export as HTML
html_report = phone_intel.export_report(result, format='html')
with open('phone_report.html', 'w') as f:
    f.write(html_report)

print("Reports exported successfully")
```

## Module Overview

### 1. phone_intel.py
Main intelligence module that orchestrates all sub-modules for comprehensive phone investigation.

**Key Features:**
- Comprehensive investigation with parallel processing
- Risk scoring algorithm
- Report generation in multiple formats
- Batch processing support

### 2. phoneinfoga_integration.py
PhoneInfoga integration for international phone lookup and carrier identification.

**Key Features:**
- API and CLI mode support
- Carrier information lookup
- Location detection
- Google dorking for phone numbers

### 3. truecaller_integration.py
TrueCaller integration for caller ID and spam detection.

**Key Features:**
- Caller ID lookup
- Spam score detection
- Social media profile linking
- Name-to-phone search

### 4. phone_validator.py
Comprehensive phone number validation and formatting.

**Key Features:**
- Format validation
- Number type detection
- Country code verification
- Number extraction from text
- Portability checking

### 5. hlr_lookup.py
Home Location Register lookup for network information.

**Key Features:**
- Network status checking
- Roaming detection
- IMSI identification
- Multiple provider support (HLR-Lookups, Nexmo, Twilio, NumVerify)

### 6. sms_intelligence.py
SMS gateway detection and message analysis.

**Key Features:**
- SMS gateway detection
- Disposable number identification
- Bulk sender detection
- Message spam analysis
- Campaign detection

### 7. voip_intelligence.py
VoIP number identification and provider detection.

**Key Features:**
- VoIP detection with multiple methods
- Provider identification (Skype, Google Voice, etc.)
- Confidence scoring
- Feature analysis

### 8. phone_correlator.py
Correlation engine to link phones with other identifiers.

**Key Features:**
- Social media account discovery
- Data breach database search
- Email correlation
- Person information lookup
- Confidence scoring

## API Keys Required

### Optional APIs (enhance functionality):
- **TrueCaller API**: Caller ID and spam detection
- **HLR Lookup Service**: Network status (HLR-Lookups, Nexmo, Twilio, NumVerify)
- **Dehashed**: Data breach searches
- **SnusBase**: Data breach searches
- **HaveIBeenPwned**: Breach verification

### Free/Basic Features:
The toolkit works with limited functionality without API keys using:
- phonenumbers library (offline validation)
- Pattern-based detection
- Basic carrier lookup

## Risk Scoring

The system calculates a risk score (0-100) based on:

- **VoIP Detection** (+20): VoIP numbers are higher risk
- **Data Breaches** (+10 per breach, max +30): Found in breach databases
- **Spam Reports** (+15): High spam score from caller ID databases
- **Disposable Numbers** (+25): Temporary/disposable SMS services
- **No Carrier Info** (+10): Suspicious lack of carrier information
- **Inactive Status** (+15): HLR lookup shows inactive

**Risk Levels:**
- 0-40: LOW RISK
- 41-70: MODERATE RISK
- 71-100: HIGH RISK

## Output Format

### Investigation Result Structure

```json
{
  "phone_number": "+14155552671",
  "timestamp": "2024-01-15T10:30:00Z",
  "risk_score": 25,
  "summary": "Carrier: AT&T | Location: United States | Type: MOBILE | LOW RISK",

  "basic_info": {
    "carrier": "AT&T",
    "country": "United States",
    "number_type": "MOBILE",
    "timezone": ["America/Los_Angeles"]
  },

  "validation": {
    "is_valid": true,
    "normalized": "+14155552671"
  },

  "caller_id": {
    "name": "John Smith",
    "spam_score": 10,
    "is_spam": false
  },

  "voip_analysis": {
    "is_voip": false,
    "confidence": 0.0
  },

  "breaches": {
    "total_breaches": 2,
    "found_in": ["Collection1", "LinkedIn"],
    "exposed_data": ["email", "password", "phone"]
  },

  "social_media": {
    "facebook": "facebook.com/johnsmith",
    "twitter": "twitter.com/jsmith",
    "total_found": 2
  }
}
```

## Performance

- **Single Investigation**: 5-15 seconds (depending on deep mode)
- **Batch Processing**: ~10 seconds per number (parallelized)
- **Concurrent Requests**: Up to 6 parallel API calls
- **Rate Limiting**: Automatic rate limit enforcement for all APIs

## Error Handling

All modules include comprehensive error handling:

```python
try:
    result = phone_intel.investigate("+1-555-0123")

    if 'error' in result:
        print(f"Error: {result['error']}")
    else:
        print(f"Success: {result['summary']}")

except Exception as e:
    print(f"Investigation failed: {e}")
```

## Legal and Ethical Considerations

**IMPORTANT**: This toolkit is designed for legitimate OSINT research and security investigations.

### Legal Usage:
- ✅ Security research and threat intelligence
- ✅ Fraud investigation and prevention
- ✅ Law enforcement investigations (with proper authority)
- ✅ Personal phone number verification
- ✅ OSINT research and analysis

### Prohibited Usage:
- ❌ Harassment or stalking
- ❌ Unauthorized surveillance
- ❌ Privacy violations
- ❌ Spam or unsolicited marketing
- ❌ Social engineering attacks

### Best Practices:
1. Obtain proper authorization before investigating phone numbers
2. Respect privacy laws and regulations (GDPR, CCPA, etc.)
3. Use responsibly and ethically
4. Secure API keys and sensitive data
5. Implement proper access controls
6. Log all investigations for audit purposes

## Troubleshooting

### Common Issues:

**1. Invalid Phone Number Format**
```python
# Solution: Use E.164 format with country code
phone = "+14155552671"  # Correct
phone = "4155552671"     # Wrong - missing country code
```

**2. API Rate Limits**
```python
# Solution: Configure rate limits in config
config = {
    'truecaller': {
        'rate_limit': 30  # requests per minute
    }
}
```

**3. Missing API Keys**
```python
# Solution: Check if API key is required
result = phone_intel.investigate(phone, deep=False)  # Skip APIs requiring keys
```

**4. Timeout Errors**
```python
# Solution: Increase timeout in config
config = {
    'timeout': 60  # seconds
}
```

## Advanced Configuration

### Custom Timeout Settings

```python
config = {
    'timeout': 30,  # Default request timeout
    'max_retries': 3,  # Retry failed requests
    'backoff_factor': 2  # Exponential backoff
}
```

### Logging Configuration

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phone_intel.log'),
        logging.StreamHandler()
    ]
)
```

### Custom Cache Implementation

```python
from phone_intel import PhoneIntelligence

class CustomCache:
    def get(self, key):
        # Your cache implementation
        pass

    def set(self, key, value, ttl=3600):
        # Your cache implementation
        pass

phone_intel = PhoneIntelligence(config)
phone_intel.cache = CustomCache()
```

## Contributing

Contributions are welcome! Areas for improvement:

1. Additional VoIP provider detection
2. More breach database integrations
3. Enhanced social media discovery
4. Improved risk scoring algorithms
5. Additional export formats
6. Performance optimizations

## Version History

- **1.0.0** (2024-01-15): Initial release
  - Complete phone intelligence suite
  - 8 core modules
  - Comprehensive correlation engine
  - Risk scoring system

## License

This toolkit is provided for legitimate OSINT and security research purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues, questions, or feature requests, please refer to the main Apollo Intelligence Platform documentation.

## Acknowledgments

This toolkit integrates with and builds upon several excellent open-source projects and services:

- phonenumbers library (Google)
- PhoneInfoga
- TrueCaller
- HLR lookup services
- Data breach databases

---

**Phone Intelligence OSINT Toolkit** - Part of the Apollo Intelligence Platform
