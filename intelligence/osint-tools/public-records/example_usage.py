"""
Public Records Intelligence System - Example Usage
Demonstrates all features and capabilities
"""

import asyncio
from datetime import datetime
from public_records import PublicRecords
from court_records import CourtRecordsSearch
from criminal_records import CriminalRecordsSearch
from property_records import PropertyRecordsSearch
from business_records import BusinessRecordsSearch
from government_records import GovernmentRecordsSearch
from offshore_leaks import OffshoreLeaksSearch


def example_1_basic_search():
    """Example 1: Basic person search across all databases"""
    print("=" * 80)
    print("EXAMPLE 1: Basic Person Search")
    print("=" * 80)

    # Configuration with API keys
    config = {
        'court': {
            'judy_records_api_key': 'your_key_here',
            'court_listener_token': 'your_token',
            'pacer_username': 'username',
            'pacer_password': 'password'
        },
        'property': {
            'attom_api_key': 'your_key',
            'zillow_api_key': 'your_key'
        },
        'business': {
            'opencorporates_token': 'your_token'
        },
        'government': {
            'fec_api_key': 'your_key',
            'propublica_api_key': 'your_key'
        }
    }

    # Initialize
    records = PublicRecords(config)

    # Search all record types
    results = records.search(
        name="John Doe",
        state="NY",
        record_types=["court", "criminal", "property", "business"]
    )

    # Display summary
    print(f"\nSubject: {results['query']['name']}")
    print(f"Total Records Found: {results['summary']['total_records']}")
    print(f"Execution Time: {results['execution_time']:.2f} seconds")

    print("\nRecords by Type:")
    for record_type, count in results['summary']['records_by_type'].items():
        print(f"  {record_type.title()}: {count}")

    if results['summary']['risk_indicators']:
        print("\nRisk Indicators:")
        for indicator in results['summary']['risk_indicators']:
            print(f"  [{indicator['severity']}] {indicator['type']}: {indicator['count']}")

    # Export results
    records.export_results(results, 'example1_report.json', format='json')
    print("\nReport saved to: example1_report.json")


def example_2_court_records():
    """Example 2: Detailed court records search"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Court Records Search")
    print("=" * 80)

    court_search = CourtRecordsSearch({
        'judy_records_api_key': 'your_key',
        'court_listener_token': 'your_token'
    })

    query = {
        'name': 'John Doe',
        'state': 'NY'
    }

    results = asyncio.run(court_search.search_async(query))

    print(f"\nFound {len(results)} court records:")
    for i, record in enumerate(results[:5], 1):
        print(f"\n{i}. {record['source']}")
        print(f"   Case Number: {record.get('case_number', 'N/A')}")
        print(f"   Court: {record.get('court', 'N/A')}")
        print(f"   Type: {record.get('case_type', 'N/A')}")
        print(f"   Status: {record.get('status', 'N/A')}")
        print(f"   URL: {record.get('url', 'N/A')}")


def example_3_criminal_background():
    """Example 3: Criminal background check"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Criminal Background Check")
    print("=" * 80)

    criminal_search = CriminalRecordsSearch()

    query = {
        'name': 'John Doe',
        'state': 'FL',
        'dob': '1980-01-01'
    }

    # Get comprehensive background check
    background = criminal_search.get_background_check(query)

    print(f"\nSubject: {background['subject']['name']}")
    print(f"Check Date: {background['check_date']}")
    print(f"Total Records: {background['total_records']}")
    print(f"Risk Assessment: {background['risk_assessment']}")

    print("\nSummary:")
    print(f"  Sex Offender Registry: {'YES' if background['summary']['sex_offender'] else 'NO'}")
    print(f"  Federal Custody: {'YES' if background['summary']['federal_custody'] else 'NO'}")
    print(f"  Most Wanted: {'YES' if background['summary']['most_wanted'] else 'NO'}")
    print(f"  State Records: {background['summary']['state_records']}")

    if background['records']:
        print("\nRecords Found:")
        for record in background['records'][:3]:
            print(f"  - {record['source']} [{record['severity']}]")


def example_4_property_history():
    """Example 4: Property ownership and history"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Property History")
    print("=" * 80)

    property_search = PropertyRecordsSearch({
        'attom_api_key': 'your_key',
        'zillow_api_key': 'your_key'
    })

    # Get complete property history
    history = property_search.get_property_history(
        address="123 Main Street",
        city="New York",
        state="NY",
        zip_code="10001"
    )

    print(f"\nProperty: {history['address']}")
    print(f"Total Records: {history['total_records']}")

    if history['ownership_history']:
        print("\nOwnership History:")
        for owner in history['ownership_history'][:3]:
            print(f"  - {owner.get('name', 'N/A')}")

    if history['value_history']:
        print("\nValue History:")
        for value in history['value_history'][:3]:
            print(f"  {value.get('year', 'Current')}: ${value.get('assessed_value', value.get('estimate', 'N/A'))}")

    if history['timeline']:
        print("\nTransaction Timeline:")
        for event in history['timeline'][:5]:
            print(f"  {event['date']}: {event['event']} - {event['details']}")


def example_5_business_intelligence():
    """Example 5: Business records and corporate intelligence"""
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Business Intelligence")
    print("=" * 80)

    business_search = BusinessRecordsSearch({
        'opencorporates_token': 'your_token'
    })

    # Get company profile
    profile = business_search.get_company_profile('Tesla Inc', 'DE')

    print(f"\nCompany: {profile['company_name']}")
    print(f"Total Records: {profile['total_records']}")
    print(f"Jurisdictions: {', '.join(profile['jurisdictions'])}")

    print("\nRegistrations:")
    for reg in profile['registrations'][:3]:
        print(f"  - {reg['name']}")
        print(f"    Type: {reg['type']}")
        print(f"    Status: {reg['status']}")
        print(f"    Jurisdiction: {reg['jurisdiction']}")

    # Get company officers
    print("\nSearching for officers...")
    # officers = asyncio.run(business_search.get_company_officers('5200726', 'us_de'))
    # for officer in officers[:5]:
    #     print(f"  {officer['name']} - {officer['position']}")


def example_6_government_connections():
    """Example 6: Government contracts and campaign finance"""
    print("\n" + "=" * 80)
    print("EXAMPLE 6: Government Connections")
    print("=" * 80)

    gov_search = GovernmentRecordsSearch({
        'fec_api_key': 'your_key',
        'propublica_api_key': 'your_key'
    })

    # Get government profile
    profile = gov_search.get_government_profile('Lockheed Martin')

    print(f"\nSubject: {profile['subject']}")
    print(f"Total Records: {profile['total_records']}")

    print("\nSummary:")
    print(f"  Government Contracts: {profile['summary']['government_contracts']}")
    print(f"  Total Contract Value: ${profile['summary']['total_contract_value']:,.2f}")
    print(f"  Campaign Contributions: {profile['summary']['campaign_contributions']}")
    print(f"  Total Contributions: ${profile['summary']['total_contributions']:,.2f}")
    print(f"  Lobbying Activities: {profile['summary']['lobbying_activities']}")

    if profile['records']:
        print("\nTop Records:")
        for record in profile['records'][:5]:
            print(f"  - {record['source']}")
            if 'award_amount' in record:
                print(f"    Contract: ${record['award_amount']:,.2f}")
            if 'contribution_amount' in record:
                print(f"    Contribution: ${record['contribution_amount']}")


def example_7_offshore_investigation():
    """Example 7: Offshore entities and hidden assets"""
    print("\n" + "=" * 80)
    print("EXAMPLE 7: Offshore Investigation")
    print("=" * 80)

    offshore_search = OffshoreLeaksSearch()

    # Get offshore profile
    profile = offshore_search.get_offshore_profile('John Doe')

    print(f"\nSubject: {profile['subject']}")
    print(f"Total Records: {profile['total_records']}")
    print(f"Risk Assessment: {profile['risk_assessment']}")

    print("\nSummary:")
    print(f"  Entities: {profile['summary']['entities']}")
    print(f"  Officer Positions: {profile['summary']['officer_positions']}")
    print(f"  Intermediaries: {profile['summary']['intermediaries']}")
    print(f"  Jurisdictions: {', '.join(profile['summary']['jurisdictions']) if profile['summary']['jurisdictions'] else 'None'}")
    print(f"  Data Sources: {', '.join(profile['summary']['data_sources']) if profile['summary']['data_sources'] else 'None'}")

    if profile['records']:
        print("\nRecords Found:")
        for record in profile['records'][:5]:
            print(f"  - {record['type'].title()}: {record['name']}")
            print(f"    Jurisdiction: {record.get('jurisdiction', 'N/A')}")
            print(f"    Source: {record['data_source']}")

    # Jurisdiction risk analysis
    print("\nJurisdiction Risk Analysis:")
    for jurisdiction in ['BVI', 'PAN', 'CYM']:
        risk = offshore_search.analyze_jurisdiction_risk(jurisdiction)
        print(f"  {jurisdiction}: {risk['risk_level']} - {risk['analysis']}")


def example_8_comprehensive_investigation():
    """Example 8: Comprehensive investigation combining all sources"""
    print("\n" + "=" * 80)
    print("EXAMPLE 8: Comprehensive Investigation")
    print("=" * 80)

    config = {
        'court': {'judy_records_api_key': 'your_key'},
        'property': {'attom_api_key': 'your_key'},
        'business': {'opencorporates_token': 'your_token'},
        'government': {'fec_api_key': 'your_key'}
    }

    records = PublicRecords(config)

    # Full investigation
    target_name = "John Doe"
    target_state = "NY"

    print(f"\nInitiating comprehensive investigation:")
    print(f"Target: {target_name}")
    print(f"State: {target_state}")
    print(f"Timestamp: {datetime.now().isoformat()}\n")

    # Search all databases
    results = records.search(
        name=target_name,
        state=target_state,
        record_types=['court', 'criminal', 'property', 'business', 'government', 'offshore']
    )

    # Comprehensive analysis
    print("=" * 80)
    print("INVESTIGATION RESULTS")
    print("=" * 80)

    print(f"\nTotal Records: {results['summary']['total_records']}")
    print(f"Search Time: {results['execution_time']:.2f}s")

    print("\nDatabase Coverage:")
    for record_type, count in results['summary']['records_by_type'].items():
        print(f"  {record_type.title():.<30} {count} records")

    # Risk assessment
    if results['summary']['risk_indicators']:
        print("\n" + "!" * 80)
        print("RISK INDICATORS DETECTED")
        print("!" * 80)
        for indicator in results['summary']['risk_indicators']:
            severity_symbol = "🔴" if indicator['severity'] == 'high' else "🟡"
            print(f"\n{severity_symbol} {indicator['type'].upper()}")
            print(f"   Severity: {indicator['severity']}")
            print(f"   Count: {indicator['count']}")
    else:
        print("\n✓ No risk indicators found")

    # Generate detailed reports
    print("\n" + "=" * 80)
    print("GENERATING REPORTS")
    print("=" * 80)

    records.export_results(results, 'comprehensive_report.json', format='json')
    records.export_results(results, 'comprehensive_report.html', format='html')
    records.export_results(results, 'comprehensive_report.csv', format='csv')

    print("\nReports generated:")
    print("  ✓ comprehensive_report.json (Machine-readable)")
    print("  ✓ comprehensive_report.html (Human-readable)")
    print("  ✓ comprehensive_report.csv (Spreadsheet)")

    print("\n" + "=" * 80)
    print("INVESTIGATION COMPLETE")
    print("=" * 80)


def example_9_batch_processing():
    """Example 9: Batch processing multiple targets"""
    print("\n" + "=" * 80)
    print("EXAMPLE 9: Batch Processing")
    print("=" * 80)

    records = PublicRecords()

    # Multiple targets
    targets = [
        {'name': 'John Doe', 'state': 'NY'},
        {'name': 'Jane Smith', 'state': 'CA'},
        {'business_name': 'Acme Corp', 'state': 'DE'}
    ]

    print(f"\nProcessing {len(targets)} targets...\n")

    for i, target in enumerate(targets, 1):
        print(f"Target {i}: {target}")
        results = records.search(**target)
        print(f"  Found {results['summary']['total_records']} records")
        print(f"  Time: {results['execution_time']:.2f}s\n")


def example_10_risk_scoring():
    """Example 10: Custom risk scoring system"""
    print("\n" + "=" * 80)
    print("EXAMPLE 10: Risk Scoring System")
    print("=" * 80)

    def calculate_risk_score(results):
        """Calculate comprehensive risk score"""
        score = 0
        factors = []

        # Criminal records (0-50 points)
        criminal_count = len(results['records'].get('criminal', []))
        if criminal_count > 0:
            score += min(50, criminal_count * 10)
            factors.append(f"Criminal records: {criminal_count}")

        # Court cases (0-30 points)
        court_count = len(results['records'].get('court', []))
        if court_count > 5:
            score += min(30, (court_count - 5) * 3)
            factors.append(f"Court cases: {court_count}")

        # Offshore entities (0-40 points)
        offshore_count = len(results['records'].get('offshore', []))
        if offshore_count > 0:
            score += min(40, offshore_count * 20)
            factors.append(f"Offshore entities: {offshore_count}")

        # Government contracts (reduces risk by up to -20 points)
        gov_count = len(results['records'].get('government', []))
        if gov_count > 5:
            score -= min(20, (gov_count - 5) * 2)
            factors.append(f"Government contracts: {gov_count} (legitimate business)")

        # Normalize score (0-100)
        score = max(0, min(100, score))

        # Risk level
        if score >= 70:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            'score': score,
            'level': level,
            'factors': factors
        }

    # Example risk calculation
    records = PublicRecords()
    results = records.search(name="John Doe", state="NY")

    risk = calculate_risk_score(results)

    print(f"\nRisk Assessment:")
    print(f"  Score: {risk['score']}/100")
    print(f"  Level: {risk['level']}")
    print(f"\nFactors:")
    for factor in risk['factors']:
        print(f"  • {factor}")


def main():
    """Run all examples"""
    print("\n" + "=" * 80)
    print("PUBLIC RECORDS INTELLIGENCE SYSTEM - EXAMPLES")
    print("=" * 80)
    print("\nThis demonstrates all features of the public records system.")
    print("Note: API keys are required for full functionality.\n")

    try:
        # Run examples
        example_1_basic_search()
        example_2_court_records()
        example_3_criminal_background()
        example_4_property_history()
        example_5_business_intelligence()
        example_6_government_connections()
        example_7_offshore_investigation()
        example_8_comprehensive_investigation()
        example_9_batch_processing()
        example_10_risk_scoring()

        print("\n" + "=" * 80)
        print("ALL EXAMPLES COMPLETED")
        print("=" * 80)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("Note: Some examples require valid API keys to function.")


if __name__ == '__main__':
    main()
