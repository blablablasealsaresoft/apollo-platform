# GEOINT - Geolocation Intelligence System

## Overview

Comprehensive geolocation intelligence gathering system for OSINT operations. Combines multiple data sources to provide accurate location intelligence from various inputs including IP addresses, phone numbers, photos, physical addresses, WiFi networks, and more.

## Features

### Core Capabilities

1. **IP Geolocation** - Locate and analyze IP addresses
2. **Phone Geolocation** - Phone number intelligence and location
3. **Photo Geolocation** - Extract location from images using EXIF and AI
4. **Address Intelligence** - Physical address validation and geocoding
5. **WHOIS Intelligence** - Domain registration and ownership data
6. **DNS Intelligence** - DNS records analysis and subdomain enumeration
7. **WiFi Geolocation** - WiFi access point location and intelligence
8. **Geofencing** - Create geographic zones and track movements
9. **Location Correlation** - Cross-reference data from multiple sources

## Installation

### Requirements

```bash
pip install -r requirements.txt
```

### Required Dependencies

```
geoip2
phonenumbers
Pillow
python-whois
dnspython
requests
geopy
```

### Optional API Keys

For enhanced functionality, configure API keys:

- **MaxMind GeoIP2** - IP geolocation database
- **IPinfo.io** - IP intelligence
- **NumVerify** - Phone number validation
- **Twilio** - Phone lookup
- **GeoSpy AI** - Image geolocation
- **Google Vision** - Landmark detection
- **WiGLE** - WiFi database
- **SecurityTrails** - DNS intelligence
- **WhoisXML** - Enhanced WHOIS data

## Quick Start

### Basic Usage

```python
from geoint_engine import GEOINT

# Initialize engine
geoint = GEOINT()

# Analyze target with multiple data points
result = geoint.locate_target(
    target_id="SUSPECT_001",
    ip="8.8.8.8",
    phone="+1-555-0123",
    photo="suspect_photo.jpg",
    address="123 Main St, City, State"
)

# View results
print(f"Confidence: {result.confidence_score:.2f}")
print(f"Locations found: {len(result.locations)}")

# Export results
geoint.export_result(result, "suspect_001.json", format='json')
geoint.export_result(result, "suspect_001.kml", format='kml')
```

### Configuration

Create a `config.json` file:

```json
{
  "ip_config": {
    "ipinfo_token": "your_token_here",
    "maxmind_db_path": "./GeoLite2-City.mmdb"
  },
  "phone_config": {
    "numverify_key": "your_key_here",
    "twilio_sid": "your_sid",
    "twilio_token": "your_token"
  },
  "photo_config": {
    "geospy_key": "your_key_here",
    "google_vision_key": "your_key_here"
  },
  "wifi_config": {
    "wigle_key": "your_key_here",
    "wigle_token": "your_token_here"
  },
  "whois_config": {
    "whoisxml_key": "your_key_here"
  },
  "dns_config": {
    "securitytrails_key": "your_key_here"
  }
}
```

Load configuration:

```python
geoint = GEOINT(config_path="config.json")
```

## Module Documentation

### 1. IP Geolocation

Locate IP addresses using multiple providers.

```python
from ip_geolocation import IPGeolocation

ip_geo = IPGeolocation({
    'ipinfo_token': 'your_token',
    'maxmind_db_path': './GeoLite2-City.mmdb'
})

# Geolocate IP
result = ip_geo.geolocate("8.8.8.8")

print(f"Location: {result['location']['city']}, {result['location']['country']}")
print(f"ISP: {result['network']['isp']}")
print(f"VPN Detected: {result['security']['is_vpn']}")

# Check IP reputation
reputation = ip_geo.get_ip_reputation("8.8.8.8")

# Batch geolocate
ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
results = ip_geo.batch_geolocate(ips)
```

**Features:**
- MaxMind GeoIP2 database integration
- IPinfo.io API support
- VPN/Proxy/Tor detection
- ASN and ISP identification
- IP reputation checking
- Batch processing

### 2. Phone Geolocation

Analyze phone numbers for location and carrier information.

```python
from phone_geolocation import PhoneGeolocation

phone_geo = PhoneGeolocation({
    'numverify_key': 'your_key',
    'twilio_sid': 'your_sid',
    'twilio_token': 'your_token'
})

# Geolocate phone number
result = phone_geo.geolocate("+1-555-0123")

print(f"Country: {result['location']['country']}")
print(f"Carrier: {result['carrier_info']['name']}")
print(f"Type: {result['type']}")
print(f"Valid: {result['is_valid']}")

# Check portability
portability = phone_geo.check_portability("+1-555-0123")

# Validate number
is_valid = phone_geo.validate_number("+14155552671")
```

**Features:**
- International number parsing
- Carrier identification
- Number type detection (mobile, landline, VoIP)
- Timezone identification
- HLR lookup integration
- Number portability tracking
- Batch lookup

### 3. Photo Geolocation

Extract location data from images.

```python
from photo_geolocation import PhotoGeolocation

photo_geo = PhotoGeolocation({
    'geospy_key': 'your_key',
    'google_vision_key': 'your_key'
})

# Extract location from photo
result = photo_geo.extract_location("suspect_photo.jpg")

if result['gps']:
    print(f"GPS: {result['gps']['latitude']}, {result['gps']['longitude']}")
    print(f"Location: {result['gps']['location_name']}")

print(f"Camera: {result['camera']['make']} {result['camera']['model']}")
print(f"Date taken: {result['datetime']['datetime_original']}")

# AI-based location estimation
if result['estimated_location']:
    print(f"Estimated: {result['estimated_location']['city']}")
    print(f"Confidence: {result['estimated_location']['confidence']}")

# Landmark detection
for landmark in result['landmarks']:
    print(f"Landmark: {landmark['name']} ({landmark['confidence']})")
```

**Features:**
- EXIF data extraction
- GPS coordinates parsing
- GeoSpy AI integration
- Google Vision landmark detection
- Camera information
- Shadow and sun position analysis
- Reverse geocoding
- Batch processing

### 4. Address Intelligence

Validate and analyze physical addresses.

```python
from address_intelligence import AddressIntelligence

addr_intel = AddressIntelligence({
    'google_maps_key': 'your_key'
})

# Analyze address
result = addr_intel.analyze("1600 Amphitheatre Parkway, Mountain View, CA")

print(f"Valid: {result['is_valid']}")
print(f"Formatted: {result['formatted_address']}")
print(f"Coordinates: {result['coordinates']['latitude']}, {result['coordinates']['longitude']}")

# Nearby POIs
for poi in result['nearby_pois']:
    print(f"POI: {poi['name']} ({poi['type']})")

# Reverse geocode
reverse = addr_intel.reverse_geocode(37.4224764, -122.0842499)

# Calculate distance
distance = addr_intel.calculate_distance("Address 1", "Address 2")
print(f"Distance: {distance} km")
```

**Features:**
- Address validation
- Geocoding (address to coordinates)
- Reverse geocoding (coordinates to address)
- Nearby POI discovery
- Property records lookup
- Demographics data
- Distance calculation
- Multiple geocoding providers

### 5. WHOIS Intelligence

Domain registration and ownership intelligence.

```python
from whois_intelligence import WhoisIntelligence

whois_intel = WhoisIntelligence({
    'whoisxml_key': 'your_key'
})

# WHOIS lookup
result = whois_intel.lookup("google.com")

print(f"Registrant: {result['registrant']['name']}")
print(f"Registrar: {result['registrar']['name']}")
print(f"Created: {result['dates']['creation_date']}")
print(f"Expires: {result['dates']['expiration_date']}")
print(f"Privacy: {result['privacy_protected']}")

# Historical WHOIS
historical_result = whois_intel.lookup("google.com", historical=True)

# Check availability
availability = whois_intel.check_availability("example-domain-12345.com")

# Find related domains
related = whois_intel.get_related_domains("google.com")

# Monitor changes
changes = whois_intel.monitor_domain("google.com")
```

**Features:**
- Comprehensive WHOIS data extraction
- Registrant information
- Historical WHOIS records
- Privacy protection detection
- Domain availability checking
- Related domain discovery
- Change monitoring
- Batch lookup

### 6. DNS Intelligence

DNS records analysis and subdomain enumeration.

```python
from dns_intelligence import DNSIntelligence

dns_intel = DNSIntelligence({
    'securitytrails_key': 'your_key',
    'virustotal_key': 'your_key'
})

# Analyze domain
result = dns_intel.analyze("google.com", include_subdomains=True)

print(f"Nameservers: {result['nameservers']}")
print(f"Mail servers: {result['mail_servers']}")
print(f"IP addresses: {result['ip_addresses']}")
print(f"DNSSEC: {result['dnssec']}")

# Subdomains
for subdomain in result['subdomains']:
    print(f"Subdomain: {subdomain['subdomain']} ({subdomain['source']})")

# Check DNS propagation
propagation = dns_intel.check_dns_propagation("google.com", "A")

# Reverse DNS
hostname = dns_intel.reverse_dns("8.8.8.8")
```

**Features:**
- All DNS record types (A, AAAA, MX, NS, TXT, etc.)
- Subdomain enumeration
- Certificate Transparency logs
- Zone transfer attempts
- DNSSEC validation
- Historical DNS records
- DNS propagation checking
- Reverse DNS lookup

### 7. WiFi Geolocation

WiFi access point location and intelligence.

```python
from wifi_geolocation import WiFiGeolocation

wifi_geo = WiFiGeolocation({
    'wigle_key': 'your_key',
    'wigle_token': 'your_token'
})

# Locate access point
result = wifi_geo.locate("00:11:22:33:44:55", ssid="TestNetwork")

print(f"Location: {result['location']['city']}, {result['location']['country']}")
print(f"Coordinates: {result['location']['latitude']}, {result['location']['longitude']}")
print(f"Encryption: {result['network_info']['encryption']}")

# Search by location
nearby = wifi_geo.search_by_location(37.7749, -122.4194, radius_km=0.5)
print(f"Found {len(nearby)} networks")

# Search by SSID
networks = wifi_geo.search_by_ssid("Starbucks WiFi")

# Identify network owner
owner = wifi_geo.identify_network_owner("00:11:22:33:44:55")
print(f"Vendor: {owner['vendor']}")

# Security analysis
security = wifi_geo.analyze_network_security("00:11:22:33:44:55")
print(f"Security level: {security['security_level']}")

# Track movement
tracking = wifi_geo.track_access_point("00:11:22:33:44:55", duration_days=30)
```

**Features:**
- WiGLE database integration
- BSSID location lookup
- SSID search
- Nearby network discovery
- Vendor identification (OUI lookup)
- Security analysis
- Access point tracking
- Google/Mozilla geolocation APIs

### 8. Geofencing

Create geographic zones and monitor movement.

```python
from geofencing import Geofencing

geofence = Geofencing()

# Create zones
home_zone = geofence.create_zone(
    "Home",
    latitude=37.7749,
    longitude=-122.4194,
    radius_meters=100
)

office_zone = geofence.create_zone(
    "Office",
    latitude=37.3861,
    longitude=-122.0839,
    radius_meters=200,
    alert_on_entry=True,
    alert_on_exit=True
)

# Check if point is in zone
check = geofence.check_point(home_zone, 37.7749, -122.4194)
print(f"Inside: {check['inside']}")

# Track movement
result = geofence.track_movement(
    tracking_id="SUBJECT_001",
    latitude=37.7749,
    longitude=-122.4194,
    check_zones=[home_zone, office_zone]
)

# View events
for event in result['events']:
    print(f"Event: {event['event_type']} at {event['zone_name']}")

# Get all events
events = geofence.get_events(zone_id=home_zone, limit=50)

# Analyze movement patterns
analysis = geofence.analyze_movement_pattern("SUBJECT_001")
print(f"Total distance: {analysis['total_distance_km']} km")
print(f"Average speed: {analysis['average_speed_kmh']} km/h")

# Export to KML
geofence.export_zones_kml("geofences.kml")
```

**Features:**
- Circular geofence zones
- Entry/exit detection
- Movement tracking
- Pattern analysis
- Event logging
- Distance calculation
- Speed analysis
- KML export

## Advanced Usage

### Cross-Source Correlation

The GEOINT engine automatically correlates data from multiple sources:

```python
result = geoint.locate_target(
    target_id="TARGET_001",
    ip="203.0.113.1",
    phone="+1-555-0100",
    photo="image.jpg",
    address="123 Main St",
    domain="example.com"
)

# View correlations
for correlation in result.correlations:
    print(f"Match: {correlation['sources']} - {correlation['match_type']}")
    print(f"Confidence: {correlation['confidence']}")
```

### Batch Processing

Process multiple targets:

```python
targets = [
    {"target_id": "T001", "ip": "8.8.8.8"},
    {"target_id": "T002", "phone": "+1-555-0100"},
    {"target_id": "T003", "photo": "photo.jpg"}
]

results = geoint.batch_analyze(targets, output_dir="./results")
```

### Geofence Monitoring

Real-time movement monitoring:

```python
# Create monitoring zones
zone1 = geofence.create_zone("Zone 1", 37.7749, -122.4194, 500)
zone2 = geofence.create_zone("Zone 2", 37.3861, -122.0839, 500)

# Continuous tracking
tracking_id = "SUBJECT_001"

while True:
    # Get current location (from GPS, cell tower, etc.)
    current_lat, current_lon = get_current_location()

    # Track movement
    result = geofence.track_movement(tracking_id, current_lat, current_lon)

    # Handle events
    for event in result['events']:
        if event['event_type'] == 'entry':
            alert(f"Subject entered {event['zone_name']}")
        elif event['event_type'] == 'exit':
            alert(f"Subject exited {event['zone_name']}")
```

## Output Formats

### JSON Export

```python
geoint.export_result(result, "output.json", format='json')
```

### KML Export (Google Earth)

```python
geoint.export_result(result, "output.kml", format='kml')
```

### CSV Export

```python
geoint.export_result(result, "output.csv", format='csv')
```

## Best Practices

### 1. API Key Management

Store API keys securely:

```python
import os

config = {
    'ip_config': {
        'ipinfo_token': os.environ.get('IPINFO_TOKEN')
    }
}
```

### 2. Caching

Enable caching to reduce API calls:

```python
geoint = GEOINT({
    'enable_caching': True,
    'cache_ttl': 3600  # 1 hour
})
```

### 3. Rate Limiting

Respect API rate limits:

```python
import time

for target in targets:
    result = geoint.locate_target(**target)
    time.sleep(1)  # Delay between requests
```

### 4. Error Handling

Always handle errors gracefully:

```python
try:
    result = geoint.locate_target(ip="invalid")
except Exception as e:
    logger.error(f"Analysis failed: {e}")
```

## Troubleshooting

### Common Issues

**MaxMind Database Not Found**
```
Download GeoLite2 from https://dev.maxmind.com/geoip/geoip2/geolite2/
```

**API Authentication Failed**
```
Verify API keys in configuration
```

**No GPS Data in Photo**
```
Many cameras/phones strip EXIF data
Use AI-based estimation instead
```

## Legal and Ethical Considerations

1. **Respect Privacy** - Only use for legitimate OSINT purposes
2. **Comply with Laws** - Follow local laws and regulations
3. **API Terms** - Respect API provider terms of service
4. **Data Protection** - Secure sensitive location data
5. **Attribution** - Cite sources when using intelligence

## Performance Optimization

### Parallel Processing

```python
geoint = GEOINT({'max_workers': 10})
```

### Selective Sources

```python
# Only use specific IP sources
ip_geo.geolocate("8.8.8.8", sources=['maxmind', 'ipinfo'])
```

### Cache Configuration

```python
config = {
    'enable_caching': True,
    'cache_ttl': 7200  # 2 hours
}
```

## Integration Examples

### Integration with Other OSINT Tools

```python
from geoint_engine import GEOINT
from some_other_tool import TargetAnalyzer

geoint = GEOINT()
analyzer = TargetAnalyzer()

# Get target data
target_data = analyzer.get_target("suspect@example.com")

# Enrich with GEOINT
geo_result = geoint.locate_target(
    ip=target_data.last_ip,
    phone=target_data.phone
)
```

## Updates and Maintenance

Keep databases updated:

```bash
# Update MaxMind GeoIP2 database monthly
wget https://download.maxmind.com/app/geoip_download?...

# Update WiGLE data periodically
# Check API for latest data
```

## Support and Resources

- **Documentation**: Full API documentation in code comments
- **Examples**: See example scripts in `/examples` directory
- **Issues**: Report issues with detailed error messages
- **Updates**: Check for module updates regularly

## License

Production-ready code for OSINT operations.

## Changelog

### Version 1.0.0
- Initial release
- Complete GEOINT functionality
- All modules operational
- Comprehensive documentation
