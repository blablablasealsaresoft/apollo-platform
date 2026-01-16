#!/usr/bin/env python3
"""
Phone Intelligence - Quick Start Script
Simple script to get started with phone intelligence quickly
"""

from phone_intel import PhoneIntelligence
from phone_validator import PhoneValidator


def quick_investigate(phone_number: str):
    """
    Quick phone investigation without API keys
    Uses basic features that don't require external APIs
    """
    print("=" * 70)
    print("PHONE INTELLIGENCE - QUICK START")
    print("=" * 70)
    print(f"\nInvestigating: {phone_number}\n")

    # Step 1: Validation
    print("Step 1: Validating phone number...")
    print("-" * 70)

    validator = PhoneValidator()
    validation = validator.validate(phone_number)

    if not validation['is_valid']:
        print("❌ Invalid phone number!")
        print(f"Errors: {', '.join(validation['validation_errors'])}")
        return

    print("✅ Valid phone number")
    print(f"   Normalized: {validation['normalized']}")
    print(f"   Type: {validation['metadata'].get('number_type', 'Unknown')}")
    print(f"   Region: {validation['metadata'].get('region', 'Unknown')}")
    print(f"   Country: {validation['metadata'].get('country', 'Unknown')}")

    if validation['warnings']:
        print(f"\n⚠️  Warnings:")
        for warning in validation['warnings']:
            print(f"   - {warning}")

    # Step 2: Basic Investigation
    print("\n\nStep 2: Basic investigation (no API keys required)...")
    print("-" * 70)

    phone_intel = PhoneIntelligence()
    result = phone_intel.investigate(phone_number, deep=False)

    print(f"📱 Basic Information:")
    basic = result.get('basic_info', {})
    print(f"   Carrier: {basic.get('carrier', 'Unknown')}")
    print(f"   Country: {basic.get('country', 'Unknown')}")
    print(f"   Number Type: {basic.get('number_type', 'Unknown')}")

    if basic.get('timezones'):
        print(f"   Timezones: {', '.join(basic['timezones'])}")

    # Step 3: VoIP Detection
    print(f"\n🔍 VoIP Detection:")
    voip = result.get('voip_analysis', {})
    if voip.get('is_voip'):
        print(f"   ✅ VoIP Detected")
        print(f"   Provider: {voip.get('provider', 'Unknown')}")
        print(f"   Confidence: {voip.get('confidence', 0):.1%}")
    else:
        print(f"   ❌ Not detected as VoIP")

    # Step 4: Risk Assessment
    print(f"\n⚠️  Risk Assessment:")
    risk = result.get('risk_score', 0)
    print(f"   Risk Score: {risk}/100")

    if risk > 70:
        print(f"   Level: 🔴 HIGH RISK")
    elif risk > 40:
        print(f"   Level: 🟡 MODERATE RISK")
    else:
        print(f"   Level: 🟢 LOW RISK")

    # Summary
    print(f"\n📊 Summary:")
    print(f"   {result.get('summary', 'No summary available')}")

    # Next Steps
    print("\n" + "=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print("""
For more comprehensive intelligence, configure API keys:

1. TrueCaller API - Caller ID and spam detection
2. HLR Lookup API - Network status and carrier info
3. Dehashed/SnusBase - Data breach searches
4. PhoneInfoga - Advanced carrier lookup

See README_PHONE_INTEL.md for detailed setup instructions.
    """)

    # Export option
    print("\nWould you like to export this report? (y/n): ", end="")
    try:
        choice = input().lower()
        if choice == 'y':
            filename = f"phone_report_{validation['normalized'].replace('+', '').replace('-', '')}.txt"
            report = phone_intel.export_report(result, format='txt')

            with open(filename, 'w') as f:
                f.write(report)

            print(f"✅ Report saved to: {filename}")
    except:
        pass

    print("\n" + "=" * 70)


def main():
    """Main entry point"""
    print("\n" + "=" * 70)
    print(" " * 15 + "PHONE INTELLIGENCE TOOLKIT")
    print(" " * 20 + "Quick Start Guide")
    print("=" * 70)

    # Example usage
    print("\nThis script provides basic phone intelligence without API keys.")
    print("For full functionality, configure API keys in config.json\n")

    # Get phone number
    print("Enter a phone number to investigate (include country code):")
    print("Examples: +14155552671, +442071234567, +919876543210")
    print("\nPhone number: ", end="")

    try:
        phone = input().strip()

        if not phone:
            # Use example number
            phone = "+14155552671"
            print(f"Using example: {phone}")

        # Investigate
        quick_investigate(phone)

    except KeyboardInterrupt:
        print("\n\nOperation cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
