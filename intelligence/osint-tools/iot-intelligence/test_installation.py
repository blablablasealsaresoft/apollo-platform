"""
Test Installation Script
Verify all IoT Intelligence components are working
"""

import sys


def test_imports():
    """Test all module imports"""
    print("[*] Testing module imports...")

    try:
        from iot_intel import IoTIntelligence, IoTDevice, IoTNetwork
        print("  [+] iot_intel - OK")
    except Exception as e:
        print(f"  [!] iot_intel - FAILED: {e}")
        return False

    try:
        from shodan_iot import ShodanIoT, ShodanIoTDevice
        print("  [+] shodan_iot - OK")
    except Exception as e:
        print(f"  [!] shodan_iot - FAILED: {e}")
        return False

    try:
        from censys_iot import CensysIoT, CensysDevice, Certificate
        print("  [+] censys_iot - OK")
    except Exception as e:
        print(f"  [!] censys_iot - FAILED: {e}")
        return False

    try:
        from insecam_integration import InsecamIntegration, Camera, CameraFeed
        print("  [+] insecam_integration - OK")
    except Exception as e:
        print(f"  [!] insecam_integration - FAILED: {e}")
        return False

    try:
        from device_fingerprinter import DeviceFingerprinter, DeviceFingerprint
        print("  [+] device_fingerprinter - OK")
    except Exception as e:
        print(f"  [!] device_fingerprinter - FAILED: {e}")
        return False

    try:
        from iot_vulnerability_scanner import IoTVulnerabilityScanner, Vulnerability, ScanResult
        print("  [+] iot_vulnerability_scanner - OK")
    except Exception as e:
        print(f"  [!] iot_vulnerability_scanner - FAILED: {e}")
        return False

    try:
        from network_mapper import NetworkMapper, NetworkDevice, NetworkSegment, NetworkTopology
        print("  [+] network_mapper - OK")
    except Exception as e:
        print(f"  [!] network_mapper - FAILED: {e}")
        return False

    return True


def test_basic_functionality():
    """Test basic functionality of each module"""
    print("\n[*] Testing basic functionality...")

    try:
        from iot_intel import IoTIntelligence
        iot = IoTIntelligence()
        devices = iot.discover_devices(target_org="Test", max_devices=5)
        print(f"  [+] IoTIntelligence.discover_devices() - OK ({len(devices)} devices)")
    except Exception as e:
        print(f"  [!] IoTIntelligence - FAILED: {e}")
        return False

    try:
        from shodan_iot import ShodanIoT
        shodan = ShodanIoT()
        stats = shodan.generate_statistics()
        print(f"  [+] ShodanIoT.generate_statistics() - OK")
    except Exception as e:
        print(f"  [!] ShodanIoT - FAILED: {e}")
        return False

    try:
        from censys_iot import CensysIoT
        censys = CensysIoT()
        devices = censys.search_by_service('http', max_results=5)
        print(f"  [+] CensysIoT.search_by_service() - OK ({len(devices)} devices)")
    except Exception as e:
        print(f"  [!] CensysIoT - FAILED: {e}")
        return False

    try:
        from insecam_integration import InsecamIntegration
        insecam = InsecamIntegration()
        cameras = insecam.search_cameras(country="US", max_results=5)
        print(f"  [+] InsecamIntegration.search_cameras() - OK ({len(cameras)} cameras)")
    except Exception as e:
        print(f"  [!] InsecamIntegration - FAILED: {e}")
        return False

    try:
        from device_fingerprinter import DeviceFingerprinter
        fingerprinter = DeviceFingerprinter()
        print(f"  [+] DeviceFingerprinter initialization - OK")
    except Exception as e:
        print(f"  [!] DeviceFingerprinter - FAILED: {e}")
        return False

    try:
        from iot_vulnerability_scanner import IoTVulnerabilityScanner
        scanner = IoTVulnerabilityScanner()
        print(f"  [+] IoTVulnerabilityScanner initialization - OK")
    except Exception as e:
        print(f"  [!] IoTVulnerabilityScanner - FAILED: {e}")
        return False

    try:
        from network_mapper import NetworkMapper
        mapper = NetworkMapper()
        mapper.add_device(ip="192.168.1.1", device_type="router")
        print(f"  [+] NetworkMapper.add_device() - OK")
    except Exception as e:
        print(f"  [!] NetworkMapper - FAILED: {e}")
        return False

    return True


def test_data_structures():
    """Test data structure creation"""
    print("\n[*] Testing data structures...")

    try:
        from iot_intel import IoTDevice
        device = IoTDevice(ip="192.168.1.1", port=80, device_type="webcam")
        print(f"  [+] IoTDevice creation - OK")
    except Exception as e:
        print(f"  [!] IoTDevice - FAILED: {e}")
        return False

    try:
        from iot_vulnerability_scanner import Vulnerability
        vuln = Vulnerability(
            vuln_id="CVE-2021-12345",
            title="Test Vulnerability",
            severity="HIGH",
            description="Test description",
            affected_device="Test Device"
        )
        print(f"  [+] Vulnerability creation - OK")
    except Exception as e:
        print(f"  [!] Vulnerability - FAILED: {e}")
        return False

    try:
        from network_mapper import NetworkDevice
        net_device = NetworkDevice(ip="192.168.1.1")
        print(f"  [+] NetworkDevice creation - OK")
    except Exception as e:
        print(f"  [!] NetworkDevice - FAILED: {e}")
        return False

    return True


def test_package_import():
    """Test package-level import"""
    print("\n[*] Testing package import...")

    try:
        import iot_intelligence
        print(f"  [+] Package import - FAILED (should be separate modules)")
        return True  # This is expected to work differently
    except:
        pass

    try:
        from iot_intel import IoTIntelligence
        from shodan_iot import ShodanIoT
        from censys_iot import CensysIoT
        print(f"  [+] Individual module imports - OK")
        return True
    except Exception as e:
        print(f"  [!] Module imports - FAILED: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("IoT Intelligence - Installation Test")
    print("=" * 70)

    tests = [
        ("Module Imports", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Data Structures", test_data_structures),
        ("Package Import", test_package_import),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[!] {test_name} crashed: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n[+] All tests passed! Installation successful.")
        return 0
    else:
        print(f"\n[!] {total - passed} test(s) failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
