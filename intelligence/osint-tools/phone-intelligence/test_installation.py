#!/usr/bin/env python3
"""
Phone Intelligence - Installation Test
Test script to verify installation and dependencies
"""

import sys
import importlib


def test_imports():
    """Test if all required modules can be imported"""
    print("=" * 70)
    print("TESTING MODULE IMPORTS")
    print("=" * 70)

    modules = [
        ('phone_intel', 'PhoneIntelligence'),
        ('phone_validator', 'PhoneValidator'),
        ('phoneinfoga_integration', 'PhoneInfogaClient'),
        ('truecaller_integration', 'TrueCallerClient'),
        ('hlr_lookup', 'HLRLookup'),
        ('sms_intelligence', 'SMSIntelligence'),
        ('voip_intelligence', 'VoIPIntelligence'),
        ('phone_correlator', 'PhoneCorrelator')
    ]

    success_count = 0
    fail_count = 0

    for module_name, class_name in modules:
        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
            print(f"✅ {module_name}.{class_name}")
            success_count += 1
        except Exception as e:
            print(f"❌ {module_name}.{class_name} - Error: {e}")
            fail_count += 1

    print(f"\nResults: {success_count} passed, {fail_count} failed")
    return fail_count == 0


def test_dependencies():
    """Test if all required dependencies are installed"""
    print("\n" + "=" * 70)
    print("TESTING DEPENDENCIES")
    print("=" * 70)

    dependencies = [
        'phonenumbers',
        'requests',
        'logging',
        'json',
        'concurrent.futures',
        're',
        'typing',
        'datetime',
        'hashlib',
        'collections'
    ]

    success_count = 0
    fail_count = 0

    for dep in dependencies:
        try:
            importlib.import_module(dep.split('.')[0])
            print(f"✅ {dep}")
            success_count += 1
        except ImportError:
            print(f"❌ {dep} - Not installed")
            fail_count += 1

    print(f"\nResults: {success_count} passed, {fail_count} failed")

    if fail_count > 0:
        print("\n⚠️  Install missing dependencies with:")
        print("   pip install -r requirements.txt")

    return fail_count == 0


def test_basic_functionality():
    """Test basic functionality without API keys"""
    print("\n" + "=" * 70)
    print("TESTING BASIC FUNCTIONALITY")
    print("=" * 70)

    tests_passed = 0
    tests_failed = 0

    # Test 1: Phone Validation
    print("\nTest 1: Phone Validation")
    try:
        from phone_validator import PhoneValidator

        validator = PhoneValidator()
        result = validator.validate("+14155552671", "US")

        if result['is_valid']:
            print("✅ Phone validation working")
            tests_passed += 1
        else:
            print("❌ Phone validation failed unexpectedly")
            tests_failed += 1
    except Exception as e:
        print(f"❌ Phone validation error: {e}")
        tests_failed += 1

    # Test 2: VoIP Detection
    print("\nTest 2: VoIP Detection")
    try:
        from voip_intelligence import VoIPIntelligence

        voip = VoIPIntelligence()
        result = voip.analyze("+14155552671")

        if 'is_voip' in result:
            print("✅ VoIP detection working")
            tests_passed += 1
        else:
            print("❌ VoIP detection failed")
            tests_failed += 1
    except Exception as e:
        print(f"❌ VoIP detection error: {e}")
        tests_failed += 1

    # Test 3: SMS Intelligence
    print("\nTest 3: SMS Intelligence")
    try:
        from sms_intelligence import SMSIntelligence

        sms = SMSIntelligence()
        result = sms.analyze("+14155552671")

        if 'is_sms_gateway' in result:
            print("✅ SMS intelligence working")
            tests_passed += 1
        else:
            print("❌ SMS intelligence failed")
            tests_failed += 1
    except Exception as e:
        print(f"❌ SMS intelligence error: {e}")
        tests_failed += 1

    # Test 4: Main Phone Intelligence
    print("\nTest 4: Main Phone Intelligence Module")
    try:
        from phone_intel import PhoneIntelligence

        phone_intel = PhoneIntelligence()
        result = phone_intel.investigate("+14155552671", deep=False)

        if 'phone_number' in result and 'summary' in result:
            print("✅ Phone intelligence working")
            tests_passed += 1
        else:
            print("❌ Phone intelligence failed")
            tests_failed += 1
    except Exception as e:
        print(f"❌ Phone intelligence error: {e}")
        tests_failed += 1

    # Test 5: Message Analysis
    print("\nTest 5: SMS Message Analysis")
    try:
        from sms_intelligence import SMSIntelligence

        sms = SMSIntelligence()
        result = sms.analyze_message("Test message")

        if 'spam_score' in result:
            print("✅ Message analysis working")
            tests_passed += 1
        else:
            print("❌ Message analysis failed")
            tests_failed += 1
    except Exception as e:
        print(f"❌ Message analysis error: {e}")
        tests_failed += 1

    # Test 6: Number Formatting
    print("\nTest 6: Number Formatting")
    try:
        from phone_validator import PhoneValidator

        validator = PhoneValidator()
        formatted = validator.format_number("+14155552671", "INTERNATIONAL")

        if formatted:
            print(f"✅ Number formatting working: {formatted}")
            tests_passed += 1
        else:
            print("❌ Number formatting failed")
            tests_failed += 1
    except Exception as e:
        print(f"❌ Number formatting error: {e}")
        tests_failed += 1

    print(f"\nResults: {tests_passed} passed, {tests_failed} failed")
    return tests_failed == 0


def test_api_configuration():
    """Test API configuration (without making actual API calls)"""
    print("\n" + "=" * 70)
    print("TESTING API CONFIGURATION")
    print("=" * 70)

    print("\nChecking for config.json...")
    try:
        import json
        from pathlib import Path

        config_file = Path("config.json")

        if config_file.exists():
            print("✅ config.json found")

            with open(config_file, 'r') as f:
                config = json.load(f)

            print("\nAPI Keys Status:")

            # Check TrueCaller
            if config.get('truecaller', {}).get('api_key', '').startswith('YOUR_'):
                print("❌ TrueCaller API key not configured")
            else:
                print("✅ TrueCaller API key configured")

            # Check HLR
            if config.get('hlr', {}).get('api_key', '').startswith('YOUR_'):
                print("❌ HLR API key not configured")
            else:
                print("✅ HLR API key configured")

            # Check Dehashed
            if config.get('correlator', {}).get('dehashed_api_key', '').startswith('YOUR_'):
                print("❌ Dehashed API key not configured")
            else:
                print("✅ Dehashed API key configured")

            print("\nNote: Unconfigured API keys will limit functionality.")
            print("      Basic features will still work without API keys.")

        else:
            print("⚠️  config.json not found")
            print("   Copy config.template.json to config.json and add your API keys")

    except Exception as e:
        print(f"❌ Error checking configuration: {e}")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 70)
    print(" " * 15 + "PHONE INTELLIGENCE TOOLKIT")
    print(" " * 18 + "Installation Test")
    print("=" * 70)

    results = {}

    # Run tests
    results['imports'] = test_imports()
    results['dependencies'] = test_dependencies()
    results['functionality'] = test_basic_functionality()
    test_api_configuration()

    # Summary
    print("\n" + "=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)

    all_passed = all(results.values())

    if all_passed:
        print("\n✅ All tests passed! Installation is successful.")
        print("\nYou can now use the toolkit:")
        print("  - Run: python quick_start.py")
        print("  - Run: python phone_cli.py investigate +14155552671")
        print("  - See: README_PHONE_INTEL.md for documentation")
    else:
        print("\n❌ Some tests failed. Please fix the issues above.")

        if not results['imports']:
            print("\n⚠️  Module import errors - check if all files are present")

        if not results['dependencies']:
            print("\n⚠️  Dependency errors - run: pip install -r requirements.txt")

        if not results['functionality']:
            print("\n⚠️  Functionality errors - check error messages above")

    print("\n" + "=" * 70)

    return all_passed


def main():
    """Main entry point"""
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
