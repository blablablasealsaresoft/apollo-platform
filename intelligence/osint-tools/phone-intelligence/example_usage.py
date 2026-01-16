"""
Phone Intelligence - Example Usage
Demonstrates all features of the phone intelligence toolkit
"""

import json
from phone_intel import PhoneIntelligence
from phone_validator import PhoneValidator
from phoneinfoga_integration import PhoneInfogaClient
from truecaller_integration import TrueCallerClient
from hlr_lookup import HLRLookup
from sms_intelligence import SMSIntelligence
from voip_intelligence import VoIPIntelligence
from phone_correlator import PhoneCorrelator


def example_basic_investigation():
    """Example: Basic phone investigation"""
    print("=" * 60)
    print("EXAMPLE 1: Basic Phone Investigation")
    print("=" * 60)

    # Configuration with API keys
    config = {
        'truecaller': {
            'api_key': 'YOUR_TRUECALLER_API_KEY'
        },
        'hlr': {
            'api_key': 'YOUR_HLR_API_KEY'
        }
    }

    # Initialize system
    phone_intel = PhoneIntelligence(config)

    # Investigate a phone number
    phone = "+14155552671"
    print(f"\nInvestigating: {phone}")

    result = phone_intel.investigate(phone, deep=True)

    # Print key findings
    print(f"\n--- SUMMARY ---")
    print(result['summary'])

    print(f"\n--- BASIC INFO ---")
    print(f"Carrier: {result['basic_info'].get('carrier', 'Unknown')}")
    print(f"Country: {result['basic_info'].get('country', 'Unknown')}")
    print(f"Type: {result['basic_info'].get('number_type', 'Unknown')}")

    print(f"\n--- RISK ASSESSMENT ---")
    print(f"Risk Score: {result['risk_score']}/100")

    if result['risk_score'] > 70:
        print("⚠️ HIGH RISK")
    elif result['risk_score'] > 40:
        print("⚠️ MODERATE RISK")
    else:
        print("✓ LOW RISK")

    # Export report
    report = phone_intel.export_report(result, format='txt')
    print(f"\n--- FULL REPORT ---")
    print(report[:500] + "...\n")


def example_validation():
    """Example: Phone validation"""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Phone Validation")
    print("=" * 60)

    validator = PhoneValidator()

    # Test various phone numbers
    test_numbers = [
        "+14155552671",
        "+442071234567",
        "+919876543210",
        "555-0123",
        "invalid"
    ]

    for phone in test_numbers:
        print(f"\nValidating: {phone}")
        result = validator.validate(phone, region="US")

        if result['is_valid']:
            print(f"  ✓ Valid")
            print(f"  Normalized: {result['normalized']}")
            print(f"  Type: {result['metadata'].get('number_type')}")
            print(f"  Region: {result['metadata'].get('region')}")
        else:
            print(f"  ✗ Invalid")
            print(f"  Errors: {', '.join(result['validation_errors'])}")

        if result['warnings']:
            print(f"  ⚠️ Warnings: {', '.join(result['warnings'])}")


def example_carrier_lookup():
    """Example: Carrier lookup with PhoneInfoga"""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Carrier Lookup (PhoneInfoga)")
    print("=" * 60)

    client = PhoneInfogaClient({
        'api_url': 'http://localhost:5000',
        'use_cli': False,
        'google_dork': True
    })

    phone = "+14155552671"
    print(f"\nLooking up: {phone}")

    # Note: This example shows structure - actual results depend on PhoneInfoga service
    result = client.lookup(phone)

    print(f"\n--- CARRIER INFO ---")
    if result.get('carrier'):
        print(f"Name: {result['carrier'].get('name', 'Unknown')}")
        print(f"Type: {result['carrier'].get('type', 'Unknown')}")

    print(f"\n--- LOCATION INFO ---")
    if result.get('location'):
        print(f"Country: {result['location'].get('country', 'Unknown')}")
        print(f"Region: {result['location'].get('region', 'Unknown')}")

    # Generate Google dorks
    dorks = client.google_dork_search(phone)
    if dorks:
        print(f"\n--- GOOGLE DORK QUERIES ---")
        for i, dork in enumerate(dorks[:3], 1):
            print(f"{i}. {dork['query']}")


def example_caller_id():
    """Example: Caller ID with TrueCaller"""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Caller ID Lookup (TrueCaller)")
    print("=" * 60)

    truecaller = TrueCallerClient({
        'api_key': 'YOUR_TRUECALLER_API_KEY'
    })

    phone = "+14155552671"
    print(f"\nLooking up: {phone}")

    result = truecaller.lookup(phone)

    print(f"\n--- CALLER ID ---")
    if result.get('name'):
        print(f"Name: {result['name']}")

    print(f"\n--- SPAM ANALYSIS ---")
    print(f"Spam Score: {result.get('spam_score', 0)}/100")

    if result.get('is_spam'):
        print("⚠️ WARNING: Reported as SPAM!")
        if result.get('spam_type'):
            print(f"Spam Type: {result['spam_type']}")
    else:
        print("✓ Not reported as spam")

    print(f"\n--- SOCIAL PROFILES ---")
    profiles = result.get('social_profiles', [])
    if profiles:
        for profile in profiles:
            print(f"  - {profile.get('service')}: {profile.get('url')}")
    else:
        print("  No social profiles found")


def example_hlr_lookup():
    """Example: HLR lookup"""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: HLR Lookup (Network Status)")
    print("=" * 60)

    hlr = HLRLookup({
        'provider': 'hlr-lookups',
        'api_key': 'YOUR_HLR_API_KEY',
        'username': 'YOUR_USERNAME'
    })

    phone = "+14155552671"
    print(f"\nLooking up: {phone}")

    result = hlr.lookup(phone)

    print(f"\n--- NETWORK STATUS ---")
    print(f"Status: {result.get('status', 'UNKNOWN')}")

    network = result.get('network', {})
    if network:
        print(f"\n--- NETWORK INFO ---")
        print(f"Network: {network.get('network_name', 'Unknown')}")
        print(f"Country: {network.get('country', 'Unknown')}")
        print(f"MCC/MNC: {network.get('mcc')}/{network.get('mnc')}")

    if result.get('ported'):
        print("\n⚠️ Number has been PORTED")

    roaming = result.get('roaming', {})
    if roaming.get('is_roaming'):
        print(f"\n⚠️ Currently ROAMING")
        print(f"Roaming Country: {roaming.get('roaming_country')}")


def example_voip_detection():
    """Example: VoIP detection"""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: VoIP Detection")
    print("=" * 60)

    voip = VoIPIntelligence()

    test_numbers = [
        "+14155552671",  # Regular number
        "+991234567890",  # Skype number
    ]

    for phone in test_numbers:
        print(f"\nAnalyzing: {phone}")
        result = voip.analyze(phone)

        if result['is_voip']:
            print(f"  ✓ VoIP Detected")
            print(f"  Provider: {result.get('provider', 'Unknown')}")
            print(f"  Confidence: {result['confidence']:.1%}")
            print(f"  Detection Methods: {', '.join(result['detection_methods'])}")

            if result.get('features'):
                print(f"  Features: {', '.join(result['features'])}")
        else:
            print(f"  ✗ Not VoIP")

    # Check specific providers
    print("\n--- SPECIFIC PROVIDER CHECKS ---")

    skype_number = "+991234567890"
    skype_result = voip.check_skype(skype_number)
    if skype_result['is_skype']:
        print(f"✓ {skype_number} is a Skype number")


def example_sms_intelligence():
    """Example: SMS intelligence"""
    print("\n" + "=" * 60)
    print("EXAMPLE 7: SMS Intelligence")
    print("=" * 60)

    sms = SMSIntelligence()

    phone = "+14155552671"
    print(f"\nAnalyzing SMS characteristics: {phone}")

    result = sms.analyze(phone)

    print(f"\n--- SMS ANALYSIS ---")
    print(f"SMS Gateway: {result['is_sms_gateway']}")
    print(f"Disposable: {result['is_disposable']}")
    print(f"Bulk Sender: {result['is_bulk_sender']}")
    print(f"Reputation: {result['sender_reputation']}")

    if result['warnings']:
        print(f"\n⚠️ Warnings:")
        for warning in result['warnings']:
            print(f"  - {warning}")

    # Analyze message content
    print("\n--- MESSAGE ANALYSIS ---")
    test_messages = [
        "Hi, how are you?",
        "URGENT: Click here to claim your FREE prize! Limited time!",
        "Your verification code is: 123456"
    ]

    for msg in test_messages:
        print(f"\nMessage: {msg[:50]}...")
        analysis = sms.analyze_message(msg)

        print(f"  Type: {analysis['message_type']}")
        print(f"  Spam Score: {analysis['spam_score']}/100")

        if analysis['is_likely_spam']:
            print(f"  ⚠️ LIKELY SPAM")


def example_correlation():
    """Example: Phone correlation"""
    print("\n" + "=" * 60)
    print("EXAMPLE 8: Phone Correlation")
    print("=" * 60)

    correlator = PhoneCorrelator({
        'dehashed_api_key': 'YOUR_DEHASHED_KEY',
        'snusbase_api_key': 'YOUR_SNUSBASE_KEY'
    })

    phone = "+14155552671"
    print(f"\nCorrelating: {phone}")

    result = correlator.correlate(phone)

    print(f"\n--- SOCIAL MEDIA ---")
    social = result.get('social_media', {})
    total_found = social.get('total_found', 0)

    if total_found > 0:
        print(f"Found {total_found} social media account(s):")
        for platform in ['facebook', 'twitter', 'linkedin', 'instagram']:
            if social.get(platform):
                print(f"  - {platform.title()}: {social[platform]}")
    else:
        print("No social media accounts found")

    print(f"\n--- DATA BREACHES ---")
    breaches = result.get('breaches', {})
    total_breaches = breaches.get('total_breaches', 0)

    if total_breaches > 0:
        print(f"⚠️ Found in {total_breaches} breach(es):")
        for breach in breaches.get('found_in', [])[:5]:
            print(f"  - {breach}")

        exposed = breaches.get('exposed_data', [])
        if exposed:
            print(f"\nExposed data types: {', '.join(exposed)}")
    else:
        print("✓ Not found in breach databases")

    print(f"\n--- RELATED INFORMATION ---")
    emails = result.get('related_emails', [])
    if emails:
        print(f"Related Emails: {', '.join(emails[:3])}")

    usernames = result.get('related_usernames', [])
    if usernames:
        print(f"Related Usernames: {', '.join(usernames[:3])}")

    names = result.get('related_names', [])
    if names:
        print(f"Related Names: {', '.join(names[:3])}")

    print(f"\n--- CONFIDENCE ---")
    print(f"Correlation Confidence: {result['confidence_score']:.1%}")


def example_batch_processing():
    """Example: Batch processing"""
    print("\n" + "=" * 60)
    print("EXAMPLE 9: Batch Processing")
    print("=" * 60)

    config = {}
    phone_intel = PhoneIntelligence(config)

    # Multiple numbers to investigate
    numbers = [
        "+14155552671",
        "+442071234567",
        "+919876543210"
    ]

    print(f"\nInvestigating {len(numbers)} phone numbers...")

    results = phone_intel.batch_investigate(numbers, deep=False)

    print("\n--- BATCH RESULTS ---")
    for number, data in results.items():
        print(f"\n{number}:")
        print(f"  Valid: {data.get('validation', {}).get('is_valid')}")
        print(f"  Risk: {data.get('risk_score', 0)}/100")
        print(f"  Summary: {data.get('summary', 'N/A')[:60]}...")


def example_export_reports():
    """Example: Export reports"""
    print("\n" + "=" * 60)
    print("EXAMPLE 10: Export Reports")
    print("=" * 60)

    config = {}
    phone_intel = PhoneIntelligence(config)

    phone = "+14155552671"
    result = phone_intel.investigate(phone, deep=False)

    # Export in different formats
    print(f"\nExporting reports for: {phone}")

    # JSON format
    json_report = phone_intel.export_report(result, format='json')
    print(f"\n✓ JSON report: {len(json_report)} bytes")
    # Optionally save: with open('report.json', 'w') as f: f.write(json_report)

    # Text format
    text_report = phone_intel.export_report(result, format='txt')
    print(f"✓ Text report: {len(text_report)} bytes")
    print("\nText Report Preview:")
    print(text_report[:300] + "...")

    # HTML format
    html_report = phone_intel.export_report(result, format='html')
    print(f"\n✓ HTML report: {len(html_report)} bytes")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("PHONE INTELLIGENCE TOOLKIT - EXAMPLE USAGE")
    print("=" * 60)

    examples = [
        ("Basic Investigation", example_basic_investigation),
        ("Phone Validation", example_validation),
        ("Carrier Lookup", example_carrier_lookup),
        ("Caller ID", example_caller_id),
        ("HLR Lookup", example_hlr_lookup),
        ("VoIP Detection", example_voip_detection),
        ("SMS Intelligence", example_sms_intelligence),
        ("Phone Correlation", example_correlation),
        ("Batch Processing", example_batch_processing),
        ("Export Reports", example_export_reports)
    ]

    print("\nAvailable Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")

    print("\nNOTE: These examples demonstrate the toolkit structure.")
    print("For actual results, configure API keys in the code.")

    # Run a few examples that don't require API keys
    try:
        example_validation()
        example_voip_detection()
        example_sms_intelligence()
        example_batch_processing()
        example_export_reports()
    except Exception as e:
        print(f"\nExample execution note: {e}")
        print("Configure API keys for full functionality.")

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
