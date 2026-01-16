"""
Installation Test - People Search & Background Intelligence
Verify all modules can be imported and basic functionality works
"""

import sys
import asyncio


def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")

    try:
        from people_search import PeopleSearch, PersonProfile
        print("✓ people_search")
    except ImportError as e:
        print(f"✗ people_search: {e}")
        return False

    try:
        from spokeo_integration import SpokeoIntegration, SpokeoProfile
        print("✓ spokeo_integration")
    except ImportError as e:
        print(f"✗ spokeo_integration: {e}")
        return False

    try:
        from pipl_integration import PiplIntegration, PiplPerson
        print("✓ pipl_integration")
    except ImportError as e:
        print(f"✗ pipl_integration: {e}")
        return False

    try:
        from truepeoplesearch import TruePeopleSearch, TruePeopleProfile
        print("✓ truepeoplesearch")
    except ImportError as e:
        print(f"✗ truepeoplesearch: {e}")
        return False

    try:
        from background_checker import BackgroundChecker, BackgroundReport
        print("✓ background_checker")
    except ImportError as e:
        print(f"✗ background_checker: {e}")
        return False

    try:
        from voter_records import VoterRecordsSearch, VoterRecord
        print("✓ voter_records")
    except ImportError as e:
        print(f"✗ voter_records: {e}")
        return False

    try:
        from social_profile_aggregator import SocialProfileAggregator, SocialNetwork
        print("✓ social_profile_aggregator")
    except ImportError as e:
        print(f"✗ social_profile_aggregator: {e}")
        return False

    try:
        from utils import NameParser, PhoneParser, EmailParser, AddressParser
        print("✓ utils")
    except ImportError as e:
        print(f"✗ utils: {e}")
        return False

    return True


def test_dependencies():
    """Test that required dependencies are installed"""
    print("\nTesting dependencies...")

    dependencies = {
        'aiohttp': 'aiohttp',
        'beautifulsoup4': 'bs4',
        'lxml': 'lxml',
    }

    all_ok = True
    for name, import_name in dependencies.items():
        try:
            __import__(import_name)
            print(f"✓ {name}")
        except ImportError:
            print(f"✗ {name} - NOT INSTALLED")
            all_ok = False

    return all_ok


async def test_basic_functionality():
    """Test basic functionality of each module"""
    print("\nTesting basic functionality...")

    # Test utils
    try:
        from utils import NameParser, PhoneParser, EmailParser

        # Test name parsing
        parsed = NameParser.parse_full_name("John Doe")
        assert parsed['first'] == 'John'
        assert parsed['last'] == 'Doe'
        print("✓ Name parsing")

        # Test phone normalization
        normalized = PhoneParser.normalize_phone("(555) 123-4567")
        assert normalized == "5551234567"
        print("✓ Phone parsing")

        # Test email validation
        valid = EmailParser.is_valid_email("test@example.com")
        assert valid == True
        print("✓ Email validation")

    except Exception as e:
        print(f"✗ Utils functionality: {e}")
        return False

    # Test PersonProfile creation
    try:
        from people_search import PersonProfile

        profile = PersonProfile(name="Test User")
        profile.email_addresses.append("test@example.com")
        profile.phone_numbers.append({"number": "555-1234", "type": "mobile"})

        data = profile.to_dict()
        assert data['name'] == "Test User"
        assert len(data['contact']['email_addresses']) == 1
        print("✓ PersonProfile")

    except Exception as e:
        print(f"✗ PersonProfile: {e}")
        return False

    # Test async context managers
    try:
        from people_search import PeopleSearch

        async with PeopleSearch() as search:
            assert search.session is not None
        print("✓ Async context manager")

    except Exception as e:
        print(f"✗ Async functionality: {e}")
        return False

    return True


def test_configuration():
    """Test configuration file"""
    print("\nTesting configuration...")

    import os
    import json

    # Check for example config
    if os.path.exists('config.example.json'):
        print("✓ config.example.json exists")

        try:
            with open('config.example.json', 'r') as f:
                config = json.load(f)
            print("✓ config.example.json is valid JSON")
        except json.JSONDecodeError as e:
            print(f"✗ config.example.json invalid: {e}")
            return False
    else:
        print("✗ config.example.json not found")
        return False

    # Check for user config
    if os.path.exists('config.json'):
        print("✓ config.json exists")
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
            print("✓ config.json is valid JSON")
        except json.JSONDecodeError as e:
            print(f"✗ config.json invalid: {e}")
    else:
        print("⚠ config.json not found (using defaults)")

    return True


def test_documentation():
    """Test that documentation exists"""
    print("\nTesting documentation...")

    import os

    docs = {
        'README_PEOPLE_SEARCH.md': 'Main documentation',
        'QUICKSTART.md': 'Quick start guide',
        'PROJECT_SUMMARY.md': 'Project summary',
        'requirements.txt': 'Dependencies',
        'example_usage.py': 'Usage examples'
    }

    all_exist = True
    for filename, description in docs.items():
        if os.path.exists(filename):
            print(f"✓ {filename}")
        else:
            print(f"✗ {filename} - NOT FOUND")
            all_exist = False

    return all_exist


def main():
    """Run all tests"""
    print("="*80)
    print("PEOPLE SEARCH & BACKGROUND INTELLIGENCE - Installation Test")
    print("="*80)
    print()

    results = {}

    # Test imports
    results['imports'] = test_imports()

    # Test dependencies
    results['dependencies'] = test_dependencies()

    # Test functionality
    results['functionality'] = asyncio.run(test_basic_functionality())

    # Test configuration
    results['configuration'] = test_configuration()

    # Test documentation
    results['documentation'] = test_documentation()

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)

    all_passed = True
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test_name.capitalize()}: {status}")
        if not passed:
            all_passed = False

    print("="*80)

    if all_passed:
        print("\n🎉 All tests passed! Installation is successful.")
        print("\nNext steps:")
        print("1. Copy config.example.json to config.json")
        print("2. Add your API keys to config.json")
        print("3. Run: python example_usage.py")
        print("4. Read QUICKSTART.md for usage examples")
        return 0
    else:
        print("\n⚠ Some tests failed. Please fix the issues above.")
        print("\nCommon fixes:")
        print("- Install missing dependencies: pip install -r requirements.txt")
        print("- Ensure all Python files are in the same directory")
        print("- Check Python version: python --version (requires 3.8+)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
