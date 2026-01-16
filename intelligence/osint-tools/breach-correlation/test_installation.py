"""
Installation Test Suite
Verify that the breach correlation system is properly installed and configured
"""

import sys
import json
import asyncio
from pathlib import Path


def test_imports():
    """Test that all required modules can be imported"""
    print("\n[1/6] Testing module imports...")

    try:
        import aiohttp
        print("  ✓ aiohttp installed")
    except ImportError:
        print("  ✗ aiohttp not found - run: pip install aiohttp")
        return False

    try:
        import networkx
        print("  ✓ networkx installed")
    except ImportError:
        print("  ✗ networkx not found - run: pip install networkx")
        return False

    try:
        from breach_search import BreachSearch
        print("  ✓ breach_search module")
    except ImportError as e:
        print(f"  ✗ breach_search import failed: {e}")
        return False

    try:
        from dehashed_integration import DeHashedIntegration
        print("  ✓ dehashed_integration module")
    except ImportError as e:
        print(f"  ✗ dehashed_integration import failed: {e}")
        return False

    try:
        from hibp_integration import HaveIBeenPwnedIntegration
        print("  ✓ hibp_integration module")
    except ImportError as e:
        print(f"  ✗ hibp_integration import failed: {e}")
        return False

    try:
        from snusbase_integration import SnusbaseIntegration
        print("  ✓ snusbase_integration module")
    except ImportError as e:
        print(f"  ✗ snusbase_integration import failed: {e}")
        return False

    try:
        from breach_correlator import BreachCorrelator
        print("  ✓ breach_correlator module")
    except ImportError as e:
        print(f"  ✗ breach_correlator import failed: {e}")
        return False

    try:
        from credential_analyzer import CredentialAnalyzer
        print("  ✓ credential_analyzer module")
    except ImportError as e:
        print(f"  ✗ credential_analyzer import failed: {e}")
        return False

    try:
        from breach_monitor import BreachMonitor
        print("  ✓ breach_monitor module")
    except ImportError as e:
        print(f"  ✗ breach_monitor import failed: {e}")
        return False

    return True


def test_configuration():
    """Test that configuration file exists and is valid"""
    print("\n[2/6] Testing configuration...")

    config_file = Path('breach_config.json')

    if not config_file.exists():
        print("  ✗ breach_config.json not found")
        print("    Create it from: cp breach_config_template.json breach_config.json")
        return False

    print("  ✓ breach_config.json exists")

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        print("  ✓ Configuration is valid JSON")
    except json.JSONDecodeError as e:
        print(f"  ✗ Invalid JSON in configuration: {e}")
        return False

    # Check for API keys
    api_keys = {
        'dehashed_email': config.get('dehashed_email'),
        'dehashed_api_key': config.get('dehashed_api_key'),
        'hibp_api_key': config.get('hibp_api_key'),
        'snusbase_api_key': config.get('snusbase_api_key')
    }

    configured_apis = []
    for key, value in api_keys.items():
        if value and not value.startswith('your-'):
            configured_apis.append(key)

    if configured_apis:
        print(f"  ✓ Configured APIs: {len(configured_apis)}/4")
        for key in configured_apis:
            print(f"    - {key}")
    else:
        print("  ⚠ No API keys configured (using template values)")
        print("    Edit breach_config.json to add your API keys")

    return True


def test_class_initialization():
    """Test that classes can be initialized"""
    print("\n[3/6] Testing class initialization...")

    try:
        from breach_search import BreachSearch
        searcher = BreachSearch()
        print("  ✓ BreachSearch initialized")
    except Exception as e:
        print(f"  ✗ BreachSearch initialization failed: {e}")
        return False

    try:
        from dehashed_integration import DeHashedIntegration
        dehashed = DeHashedIntegration()
        print("  ✓ DeHashedIntegration initialized")
    except Exception as e:
        print(f"  ✗ DeHashedIntegration initialization failed: {e}")
        return False

    try:
        from hibp_integration import HaveIBeenPwnedIntegration
        hibp = HaveIBeenPwnedIntegration()
        print("  ✓ HaveIBeenPwnedIntegration initialized")
    except Exception as e:
        print(f"  ✗ HaveIBeenPwnedIntegration initialization failed: {e}")
        return False

    try:
        from snusbase_integration import SnusbaseIntegration
        snusbase = SnusbaseIntegration()
        print("  ✓ SnusbaseIntegration initialized")
    except Exception as e:
        print(f"  ✗ SnusbaseIntegration initialization failed: {e}")
        return False

    try:
        from breach_correlator import BreachCorrelator
        correlator = BreachCorrelator()
        print("  ✓ BreachCorrelator initialized")
    except Exception as e:
        print(f"  ✗ BreachCorrelator initialization failed: {e}")
        return False

    try:
        from credential_analyzer import CredentialAnalyzer
        analyzer = CredentialAnalyzer()
        print("  ✓ CredentialAnalyzer initialized")
    except Exception as e:
        print(f"  ✗ CredentialAnalyzer initialization failed: {e}")
        return False

    return True


def test_data_structures():
    """Test that data structures work correctly"""
    print("\n[4/6] Testing data structures...")

    try:
        from breach_search import BreachRecord, SearchResults, SearchType
        from datetime import datetime

        # Test BreachRecord
        record = BreachRecord(
            source='Test',
            database='TestDB',
            breach_date=datetime.now(),
            email='test@example.com',
            password='test123'
        )
        record_dict = record.to_dict()
        print("  ✓ BreachRecord creation and serialization")

        # Test SearchResults
        results = SearchResults(
            query='test@example.com',
            search_type=SearchType.EMAIL,
            timestamp=datetime.now(),
            total_records=1,
            sources=['Test'],
            records=[record]
        )
        results_dict = results.to_dict()
        print("  ✓ SearchResults creation and serialization")

        return True
    except Exception as e:
        print(f"  ✗ Data structure test failed: {e}")
        return False


def test_analyzers():
    """Test analyzer functionality"""
    print("\n[5/6] Testing analyzer functionality...")

    try:
        from credential_analyzer import CredentialAnalyzer
        from dataclasses import dataclass

        @dataclass
        class MockRecord:
            email: str = None
            username: str = None
            password: str = None
            name: str = None
            database: str = None

        analyzer = CredentialAnalyzer()

        # Test with mock data
        records = [
            MockRecord(
                email='test@example.com',
                username='testuser',
                password='password123',
                database='TestDB'
            )
        ]

        analysis = analyzer.analyze_credentials(records)

        if 'password_analysis' in analysis:
            print("  ✓ Password analysis")
        if 'security_analysis' in analysis:
            print("  ✓ Security analysis")
        if 'pattern_analysis' in analysis:
            print("  ✓ Pattern analysis")
        if 'personal_info' in analysis:
            print("  ✓ Personal information extraction")

        return True
    except Exception as e:
        print(f"  ✗ Analyzer test failed: {e}")
        return False


def test_correlation():
    """Test correlation functionality"""
    print("\n[6/6] Testing correlation functionality...")

    try:
        from breach_correlator import BreachCorrelator
        from dataclasses import dataclass
        from datetime import datetime

        @dataclass
        class MockRecord:
            source: str
            database: str
            breach_date: datetime
            email: str = None
            username: str = None
            password: str = None
            ip_address: str = None
            name: str = None

        correlator = BreachCorrelator()

        # Test with mock data
        records = [
            MockRecord(
                source='Test',
                database='DB1',
                breach_date=datetime.now(),
                email='test@example.com',
                username='testuser',
                password='password123'
            ),
            MockRecord(
                source='Test',
                database='DB2',
                breach_date=datetime.now(),
                email='test@example.com',
                username='testuser2',
                password='password123'
            )
        ]

        results = correlator.correlate_records(records)

        if 'password_reuse' in results:
            print("  ✓ Password reuse detection")
        if 'related_accounts' in results:
            print("  ✓ Related accounts detection")
        if 'attack_surface' in results:
            print("  ✓ Attack surface mapping")

        return True
    except Exception as e:
        print(f"  ✗ Correlation test failed: {e}")
        return False


async def test_async_functionality():
    """Test async functionality"""
    print("\n[BONUS] Testing async functionality...")

    try:
        from hibp_integration import HaveIBeenPwnedIntegration

        hibp = HaveIBeenPwnedIntegration()

        # Test password checking (doesn't require API key)
        count = await hibp.check_password("password123")
        print(f"  ✓ Async password check (password123 seen {count:,} times)")

        return True
    except Exception as e:
        print(f"  ✗ Async test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("="*60)
    print("BREACH CORRELATION SYSTEM - INSTALLATION TEST")
    print("="*60)

    results = {
        'imports': test_imports(),
        'configuration': test_configuration(),
        'initialization': test_class_initialization(),
        'data_structures': test_data_structures(),
        'analyzers': test_analyzers(),
        'correlation': test_correlation()
    }

    # Run async test
    try:
        async_result = asyncio.run(test_async_functionality())
        results['async'] = async_result
    except Exception as e:
        print(f"\n[BONUS] Async test error: {e}")
        results['async'] = False

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {test_name.replace('_', ' ').title():25} {status}")

    print("\n" + "-"*60)
    print(f"Results: {passed}/{total} tests passed")
    print("-"*60)

    if passed == total:
        print("\n✓ All tests passed! System is ready to use.")
        print("\nNext steps:")
        print("  1. Configure API keys in breach_config.json")
        print("  2. Run example_usage.py to see features")
        print("  3. Read QUICKSTART.md for usage guide")
        return 0
    else:
        print("\n✗ Some tests failed. Please review errors above.")
        print("\nCommon fixes:")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("  - Create config: cp breach_config_template.json breach_config.json")
        print("  - Check Python version (requires 3.7+)")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
