# GEOINT System - Setup Guide

## Quick Setup

### 1. Install Dependencies

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\geoint
pip install -r requirements.txt
```

### 2. Download MaxMind GeoIP2 Database

1. Register for free account at: https://dev.maxmind.com/geoip/geolite2/
2. Download GeoLite2-City.mmdb
3. Place in geoint directory or update config path

### 3. Configure API Keys

```bash
# Copy template
copy config.json.template config.json

# Edit config.json and add your API keys
notepad config.json
```

### 4. Test Installation

```bash
python example_usage.py
```

## API Key Setup

### Free APIs (No Credit Card Required)

1. **IPinfo.io** - https://ipinfo.io/signup
   - Free: 50,000 requests/month
   - Add to config: `ipinfo_token`

2. **MaxMind GeoLite2** - https://dev.maxmind.com/geoip/geolite2/
   - Free database download
   - Update path in config

3. **Mozilla Location Service** - https://ichnaea.readthedocs.io/
   - Free API for geolocation
   - No key required for basic use

### Premium APIs (Require Payment)

1. **Twilio** - https://www.twilio.com/
   - Phone number lookup and validation
   - Add: `twilio_sid`, `twilio_token`

2. **Google Cloud Vision** - https://cloud.google.com/vision
   - Image analysis and landmark detection
   - Add: `google_vision_key`

3. **WiGLE** - https://wigle.net/
   - WiFi network database (free tier available)
   - Add: `wigle_key`, `wigle_token`

4. **SecurityTrails** - https://securitytrails.com/
   - DNS and subdomain intelligence
   - Add: `securitytrails_key`

5. **WhoisXML API** - https://www.whoisxmlapi.com/
   - Enhanced WHOIS data
   - Add: `whoisxml_key`

## Basic Usage Examples

### Example 1: Simple IP Lookup

```python
from ip_geolocation import IPGeolocation

ip_geo = IPGeolocation()
result = ip_geo.geolocate("8.8.8.8")

print(f"Location: {result['location']['city']}, {result['location']['country']}")
print(f"ISP: {result['network']['isp']}")
```

### Example 2: Phone Analysis

```python
from phone_geolocation import PhoneGeolocation

phone_geo = PhoneGeolocation()
result = phone_geo.geolocate("+1-555-0123")

print(f"Country: {result['location']['country']}")
print(f"Carrier: {result['carrier_info']['name']}")
print(f"Type: {result['type']}")
```

### Example 3: Comprehensive Analysis

```python
from geoint_engine import GEOINT

geoint = GEOINT(config_path="config.json")

result = geoint.locate_target(
    target_id="SUSPECT_001",
    ip="203.0.113.1",
    phone="+1-555-0100",
    domain="example.com"
)

print(f"Confidence: {result.confidence_score:.2f}")
print(f"Locations: {len(result.locations)}")

# Export
geoint.export_result(result, "output.json", format='json')
geoint.export_result(result, "output.kml", format='kml')
```

### Example 4: Geofencing

```python
from geofencing import Geofencing

geofence = Geofencing()

# Create zone
zone_id = geofence.create_zone(
    "Target Area",
    latitude=37.7749,
    longitude=-122.4194,
    radius_meters=500
)

# Track movement
result = geofence.track_movement(
    tracking_id="SUBJECT_001",
    latitude=37.7749,
    longitude=-122.4194
)

# Check for events
for event in result['events']:
    print(f"Alert: {event['event_type']} at {event['timestamp']}")
```

## Troubleshooting

### Common Issues

**Issue: ModuleNotFoundError**
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Issue: MaxMind database not found**
```bash
# Solution: Download and configure path
# 1. Download from https://dev.maxmind.com/geoip/geolite2/
# 2. Update config.json: "maxmind_db_path": "./GeoLite2-City.mmdb"
```

**Issue: API rate limit exceeded**
```python
# Solution: Add delays between requests
import time

for target in targets:
    result = geoint.locate_target(**target)
    time.sleep(1)  # Wait 1 second
```

**Issue: Invalid phone number**
```python
# Solution: Include country code
# Wrong: "555-0123"
# Right: "+1-555-0123"
```

## Performance Tips

1. **Enable Caching**
   ```json
   {
     "enable_caching": true,
     "cache_ttl": 3600
   }
   ```

2. **Parallel Processing**
   ```json
   {
     "max_workers": 10
   }
   ```

3. **Selective Sources**
   ```python
   # Only use specific sources
   result = ip_geo.geolocate("8.8.8.8", sources=['maxmind'])
   ```

## Security Recommendations

1. **Protect API Keys**
   - Never commit config.json to version control
   - Use environment variables in production
   - Rotate keys regularly

2. **Secure Data Storage**
   - Encrypt sensitive location data
   - Implement access controls
   - Regular security audits

3. **Legal Compliance**
   - Follow local privacy laws
   - Respect API terms of service
   - Obtain proper authorization

## Directory Structure

```
geoint/
├── __init__.py                  # Package initialization
├── geoint_engine.py             # Main GEOINT orchestration engine
├── ip_geolocation.py            # IP intelligence module
├── phone_geolocation.py         # Phone location module
├── photo_geolocation.py         # Image geolocation module
├── address_intelligence.py      # Address analysis module
├── whois_intelligence.py        # Domain WHOIS module
├── dns_intelligence.py          # DNS analysis module
├── wifi_geolocation.py          # WiFi location module
├── geofencing.py                # Geofence monitoring module
├── requirements.txt             # Python dependencies
├── config.json.template         # Configuration template
├── config.json                  # Your configuration (create from template)
├── README_GEOINT.md            # Full documentation
├── SETUP.md                     # This file
└── example_usage.py             # Usage examples
```

## Production Deployment

### Environment Variables

```python
import os

config = {
    'ip_config': {
        'ipinfo_token': os.environ.get('IPINFO_TOKEN')
    },
    'phone_config': {
        'twilio_sid': os.environ.get('TWILIO_SID'),
        'twilio_token': os.environ.get('TWILIO_TOKEN')
    }
}

geoint = GEOINT(config)
```

### Docker Deployment (Optional)

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "geoint_engine.py"]
```

## Support

For issues and questions:
1. Check README_GEOINT.md for detailed documentation
2. Review example_usage.py for code examples
3. Verify API keys are correctly configured
4. Check API provider status pages

## Next Steps

1. Configure API keys in config.json
2. Run example_usage.py to test functionality
3. Read README_GEOINT.md for comprehensive documentation
4. Start with simple queries before complex analysis
5. Monitor API usage and costs

## Updates

Keep system updated:
- Update MaxMind database monthly
- Check for API changes from providers
- Update dependencies: `pip install -r requirements.txt --upgrade`
- Review new features in documentation

---

**GEOINT System v1.0.0**
Production-Ready Geolocation Intelligence Platform
