"""
GEOINT Example Usage
Demonstrates various capabilities of the GEOINT system
"""

import json
from geoint_engine import GEOINT
from ip_geolocation import IPGeolocation
from phone_geolocation import PhoneGeolocation
from photo_geolocation import PhotoGeolocation
from address_intelligence import AddressIntelligence
from whois_intelligence import WhoisIntelligence
from dns_intelligence import DNSIntelligence
from wifi_geolocation import WiFiGeolocation
from geofencing import Geofencing


def example_comprehensive_analysis():
    """Example: Comprehensive target analysis"""
    print("=" * 80)
    print("COMPREHENSIVE TARGET ANALYSIS")
    print("=" * 80)

    geoint = GEOINT()

    # Analyze target with multiple data points
    result = geoint.locate_target(
        target_id="SUSPECT_001",
        ip="8.8.8.8",
        phone="+1-555-0123",
        domain="google.com"
    )

    print(f"\nTarget ID: {result.target_id}")
    print(f"Confidence Score: {result.confidence_score:.2f}")
    print(f"Total Locations Found: {len(result.locations)}")

    # Display IP data
    if result.ip_data:
        print(f"\nIP Location: {result.ip_data.get('location', {}).get('city')}, "
              f"{result.ip_data.get('location', {}).get('country')}")

    # Display correlations
    print(f"\nCorrelations Found: {len(result.correlations)}")
    for corr in result.correlations:
        print(f"  - {corr['sources']}: {corr['match_type']} (confidence: {corr['confidence']})")

    # Export results
    geoint.export_result(result, "suspect_001.json", format='json')
    geoint.export_result(result, "suspect_001.kml", format='kml')

    print("\nResults exported to suspect_001.json and suspect_001.kml")


def example_ip_geolocation():
    """Example: IP Geolocation"""
    print("\n" + "=" * 80)
    print("IP GEOLOCATION")
    print("=" * 80)

    ip_geo = IPGeolocation()

    # Single IP lookup
    result = ip_geo.geolocate("8.8.8.8")

    print(f"\nIP: {result['ip']}")
    print(f"Location: {result['location'].get('city')}, {result['location'].get('country')}")
    print(f"Coordinates: {result['location'].get('latitude')}, {result['location'].get('longitude')}")
    print(f"ISP: {result['network'].get('isp')}")
    print(f"VPN Detected: {result['security'].get('is_vpn')}")
    print(f"Proxy Detected: {result['security'].get('is_proxy')}")

    # Batch lookup
    print("\nBatch IP Lookup:")
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    batch_results = ip_geo.batch_geolocate(ips)

    for r in batch_results:
        print(f"  {r['ip']}: {r.get('location', {}).get('city', 'Unknown')}, "
              f"{r.get('location', {}).get('country', 'Unknown')}")


def example_phone_geolocation():
    """Example: Phone Geolocation"""
    print("\n" + "=" * 80)
    print("PHONE GEOLOCATION")
    print("=" * 80)

    phone_geo = PhoneGeolocation()

    # Analyze phone number
    result = phone_geo.geolocate("+1-555-0123")

    print(f"\nPhone: {result['phone_number']}")
    print(f"Valid: {result['is_valid']}")
    print(f"Country: {result['location'].get('country')}")
    print(f"Region: {result['location'].get('region')}")
    print(f"Carrier: {result['carrier_info'].get('name')}")
    print(f"Type: {result['type']}")
    print(f"Timezone: {result['timezone']}")
    print(f"Formatted (E164): {result['formatted'].get('e164')}")
    print(f"Formatted (International): {result['formatted'].get('international')}")


def example_photo_geolocation():
    """Example: Photo Geolocation"""
    print("\n" + "=" * 80)
    print("PHOTO GEOLOCATION")
    print("=" * 80)

    photo_geo = PhotoGeolocation()

    # Note: This requires an actual image file
    # result = photo_geo.extract_location("suspect_photo.jpg")

    print("\nPhoto geolocation extracts:")
    print("  - GPS coordinates from EXIF data")
    print("  - Camera make and model")
    print("  - Date and time photo was taken")
    print("  - Estimated location using AI (GeoSpy)")
    print("  - Landmarks using Google Vision")
    print("  - Shadow and sun position analysis")

    print("\nExample output structure:")
    example_output = {
        'gps': {
            'latitude': 37.7749,
            'longitude': -122.4194,
            'location_name': 'San Francisco, CA, USA'
        },
        'camera': {
            'make': 'Apple',
            'model': 'iPhone 13 Pro'
        },
        'datetime': {
            'datetime_original': '2024:01:15 14:30:22'
        },
        'confidence': 0.95
    }
    print(json.dumps(example_output, indent=2))


def example_address_intelligence():
    """Example: Address Intelligence"""
    print("\n" + "=" * 80)
    print("ADDRESS INTELLIGENCE")
    print("=" * 80)

    addr_intel = AddressIntelligence()

    # Analyze address
    result = addr_intel.analyze("1600 Amphitheatre Parkway, Mountain View, CA")

    print(f"\nInput: {result['input_address']}")
    print(f"Valid: {result['is_valid']}")
    print(f"Formatted: {result['formatted_address']}")
    print(f"Coordinates: {result['coordinates'].get('latitude')}, "
          f"{result['coordinates'].get('longitude')}")
    print(f"Components:")
    for key, value in result['components'].items():
        if value:
            print(f"  {key}: {value}")

    # Reverse geocode
    print("\nReverse Geocoding:")
    reverse = addr_intel.reverse_geocode(37.4224764, -122.0842499)
    if reverse['addresses']:
        print(f"  Address: {reverse['addresses'][0]['formatted_address']}")


def example_whois_intelligence():
    """Example: WHOIS Intelligence"""
    print("\n" + "=" * 80)
    print("WHOIS INTELLIGENCE")
    print("=" * 80)

    whois_intel = WhoisIntelligence()

    # WHOIS lookup
    result = whois_intel.lookup("google.com")

    print(f"\nDomain: {result['domain']}")
    print(f"Registrant: {result['registrant'].get('name')}")
    print(f"Organization: {result['registrant'].get('organization')}")
    print(f"Email: {result['registrant'].get('email')}")
    print(f"Country: {result['registrant'].get('country')}")
    print(f"\nRegistrar: {result['registrar'].get('name')}")
    print(f"Created: {result['dates'].get('creation_date')}")
    print(f"Expires: {result['dates'].get('expiration_date')}")
    print(f"Privacy Protected: {result['privacy_protected']}")

    # Check availability
    print("\nDomain Availability Check:")
    avail = whois_intel.check_availability("example-nonexistent-domain-12345.com")
    print(f"  Available: {avail['available']}")


def example_dns_intelligence():
    """Example: DNS Intelligence"""
    print("\n" + "=" * 80)
    print("DNS INTELLIGENCE")
    print("=" * 80)

    dns_intel = DNSIntelligence()

    # Analyze domain
    result = dns_intel.analyze("google.com")

    print(f"\nDomain: {result['domain']}")
    print(f"DNSSEC: {result['dnssec']}")

    print("\nNameservers:")
    for ns in result['nameservers'][:3]:
        print(f"  {ns['hostname']}: {ns['ip_addresses']}")

    print("\nMail Servers:")
    for mx in result['mail_servers'][:3]:
        print(f"  {mx['hostname']} (priority: {mx['priority']})")

    print("\nIP Addresses:")
    for ip in result['ip_addresses'][:5]:
        print(f"  IPv{ip['version']}: {ip['address']}")

    print("\nDNS Records:")
    for record_type, values in result['records'].items():
        if values:
            print(f"  {record_type}: {len(values)} records")


def example_wifi_geolocation():
    """Example: WiFi Geolocation"""
    print("\n" + "=" * 80)
    print("WIFI GEOLOCATION")
    print("=" * 80)

    wifi_geo = WiFiGeolocation()

    print("\nWiFi geolocation capabilities:")
    print("  - Locate access points by BSSID")
    print("  - Search networks by SSID")
    print("  - Find nearby networks by location")
    print("  - Identify network owner (vendor)")
    print("  - Analyze network security")
    print("  - Track access point movements")

    # Example network owner lookup
    print("\nExample: Network Owner Identification")
    owner = wifi_geo.identify_network_owner("00:11:22:33:44:55")
    print(f"  Vendor lookup for BSSID: {owner['bssid']}")
    print(f"  Note: Requires valid BSSID for actual results")


def example_geofencing():
    """Example: Geofencing"""
    print("\n" + "=" * 80)
    print("GEOFENCING")
    print("=" * 80)

    geofence = Geofencing()

    # Create zones
    print("\nCreating geofence zones...")

    home_zone = geofence.create_zone(
        "Home",
        latitude=37.7749,
        longitude=-122.4194,
        radius_meters=100
    )
    print(f"  Created zone: {home_zone}")

    office_zone = geofence.create_zone(
        "Office",
        latitude=37.3861,
        longitude=-122.0839,
        radius_meters=200
    )
    print(f"  Created zone: {office_zone}")

    # Check point
    print("\nChecking point against zones...")
    check = geofence.check_point(home_zone, 37.7749, -122.4194)
    print(f"  Point is {'inside' if check['inside'] else 'outside'} {check['zone_name']}")
    print(f"  Distance from center: {check['distance_from_center_meters']:.2f} meters")

    # Track movement
    print("\nTracking movement...")
    result = geofence.track_movement(
        tracking_id="SUBJECT_001",
        latitude=37.7749,
        longitude=-122.4194,
        check_zones=[home_zone, office_zone]
    )

    print(f"  Current zones: {len(result['current_zones'])}")
    for zone in result['current_zones']:
        print(f"    - {zone['zone_name']}")

    print(f"  Events triggered: {len(result['events'])}")
    for event in result['events']:
        print(f"    - {event['event_type']} at {event['zone_id']}")

    # Get all zones
    all_zones = geofence.get_all_zones()
    print(f"\nTotal zones created: {len(all_zones)}")


def example_batch_processing():
    """Example: Batch Processing"""
    print("\n" + "=" * 80)
    print("BATCH PROCESSING")
    print("=" * 80)

    geoint = GEOINT()

    # Define multiple targets
    targets = [
        {
            "target_id": "TARGET_001",
            "ip": "8.8.8.8",
            "domain": "google.com"
        },
        {
            "target_id": "TARGET_002",
            "ip": "1.1.1.1",
            "domain": "cloudflare.com"
        },
        {
            "target_id": "TARGET_003",
            "phone": "+1-555-0100"
        }
    ]

    print(f"\nProcessing {len(targets)} targets...")
    results = geoint.batch_analyze(targets, output_dir="./batch_results")

    print(f"Completed: {len(results)} targets analyzed")
    for result in results:
        print(f"  {result.target_id}: Confidence {result.confidence_score:.2f}, "
              f"Locations: {len(result.locations)}")


def main():
    """Run all examples"""
    print("\n")
    print("*" * 80)
    print("GEOINT SYSTEM - EXAMPLE USAGE")
    print("*" * 80)

    try:
        example_comprehensive_analysis()
        example_ip_geolocation()
        example_phone_geolocation()
        example_photo_geolocation()
        example_address_intelligence()
        example_whois_intelligence()
        example_dns_intelligence()
        example_wifi_geolocation()
        example_geofencing()
        example_batch_processing()

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("Note: Some examples require API keys and actual data files.")

    print("\n" + "*" * 80)
    print("EXAMPLES COMPLETE")
    print("*" * 80)
    print("\nFor production use:")
    print("1. Configure API keys in config.json")
    print("2. Download MaxMind GeoIP2 database")
    print("3. Ensure all dependencies are installed: pip install -r requirements.txt")
    print("4. Review README_GEOINT.md for detailed documentation")
    print()


if __name__ == "__main__":
    main()
