"""
Breach Correlation System - Example Usage
Demonstrates all major features of the breach correlation system
"""

import asyncio
import logging
from datetime import datetime

from breach_search import BreachSearch
from breach_correlator import BreachCorrelator
from credential_analyzer import CredentialAnalyzer
from breach_monitor import BreachMonitor


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def example_1_basic_email_search():
    """Example 1: Basic email search across all databases"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Email Search")
    print("="*60)

    # Initialize search engine
    searcher = BreachSearch(config_file='breach_config.json')

    # Search for email
    email = "target@example.com"
    results = await searcher.search_email(email)

    print(f"\nSearch Results for: {email}")
    print(f"Total Records: {results.total_records}")
    print(f"Sources: {', '.join(results.sources)}")

    # Display first 5 records
    print(f"\nFirst 5 Records:")
    for i, record in enumerate(results.records[:5], 1):
        print(f"\n{i}. Database: {record.database}")
        print(f"   Source: {record.source}")
        print(f"   Email: {record.email}")
        print(f"   Username: {record.username}")
        print(f"   Password: {record.password}")
        print(f"   Breach Date: {record.breach_date}")

    # Export results
    searcher.export_results(results, f'{email}_results.html', format='html')
    print(f"\nResults exported to {email}_results.html")


async def example_2_multi_search():
    """Example 2: Search multiple identifiers simultaneously"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Multi-Identifier Search")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')

    # Search multiple identifiers at once
    results = await searcher.multi_search(
        email="target@example.com",
        username="target_user",
        phone="+1234567890"
    )

    print("\nMulti-Search Results:")
    for search_type, search_results in results.items():
        print(f"\n{search_type.upper()}:")
        print(f"  Records found: {search_results.total_records}")
        print(f"  Sources: {', '.join(search_results.sources)}")


async def example_3_correlation_analysis():
    """Example 3: Cross-breach correlation analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Correlation Analysis")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')

    # Search with correlation enabled
    results = await searcher.search_email("target@example.com", correlate=True)

    print("\nCorrelation Analysis:")

    # Password reuse
    pwd_reuse = results.correlations['password_reuse']
    print(f"\nPassword Reuse:")
    print(f"  Total unique passwords: {pwd_reuse['total_unique_passwords']}")
    print(f"  Reused passwords: {pwd_reuse['reused_passwords']}")
    print(f"  Reuse percentage: {pwd_reuse['reuse_percentage']:.1f}%")

    if pwd_reuse['most_reused']:
        print(f"\n  Most reused passwords:")
        for item in pwd_reuse['most_reused'][:3]:
            print(f"    - '{item['password']}' used in {item['account_count']} accounts")

    # Related accounts
    related = results.correlations['related_accounts']
    print(f"\nRelated Accounts:")
    print(f"  Unique emails: {related['total_unique_emails']}")
    print(f"  Unique usernames: {related['total_unique_usernames']}")

    # Credential clusters
    clusters = results.correlations['credential_clusters']
    print(f"\nCredential Clusters: {len(clusters)}")
    for i, cluster in enumerate(clusters[:3], 1):
        print(f"\n  Cluster {i}:")
        print(f"    Emails: {len(cluster['emails'])}")
        print(f"    Usernames: {len(cluster['usernames'])}")
        print(f"    Passwords: {len(cluster['passwords'])}")
        print(f"    Databases: {', '.join(cluster['databases'][:3])}")

    # Attack surface
    attack_surface = results.correlations['attack_surface']
    print(f"\nAttack Surface:")
    print(f"  Entry points: {attack_surface['recon_data']['total_entry_points']}")
    print(f"  Credential pairs: {attack_surface['credential_pairs_count']}")
    print(f"  Vulnerable services: {attack_surface['recon_data']['total_vulnerable_services']}")


async def example_4_credential_analysis():
    """Example 4: Credential intelligence analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Credential Analysis")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')
    results = await searcher.search_email("target@example.com", correlate=True)

    # Credential analysis
    cred_analysis = results.credential_analysis

    print("\nPassword Analysis:")
    pwd_analysis = cred_analysis['password_analysis']
    print(f"  Total passwords: {pwd_analysis['total_passwords']}")
    print(f"  Unique passwords: {pwd_analysis['unique_passwords']}")
    print(f"  Average length: {pwd_analysis['length_stats']['average']:.1f}")
    print(f"  Average entropy: {pwd_analysis['average_entropy']:.2f}")

    print("\n  Composition:")
    comp = pwd_analysis['composition']
    print(f"    With uppercase: {comp['percentage_uppercase']:.1f}%")
    print(f"    With lowercase: {comp['percentage_lowercase']:.1f}%")
    print(f"    With digits: {comp['percentage_digits']:.1f}%")
    print(f"    With special chars: {comp['percentage_special']:.1f}%")

    # Security analysis
    security = cred_analysis['security_analysis']
    print("\nSecurity Distribution:")
    for level, count in security['strength_distribution'].items():
        pct = security['strength_percentages'][level]
        print(f"  {level}: {count} ({pct:.1f}%)")

    print("\nCrackability:")
    for level, count in security['crackability'].items():
        pct = security['crackability_percentages'][level]
        print(f"  {level}: {count} ({pct:.1f}%)")

    # Pattern analysis
    patterns = cred_analysis['pattern_analysis']
    print(f"\nPattern Analysis:")
    print(f"  Keyboard walks: {patterns['keyboard_walks']}")
    print(f"  Sequential chars: {patterns['sequential_chars']}")

    if patterns.get('years_found'):
        years = patterns['years_found']
        print(f"  Years found: {years['unique_years'][:5]}")

    # Personal information
    personal = cred_analysis['personal_info']
    if personal.get('names'):
        print(f"\nPersonal Information:")
        print(f"  Names: {personal['names'][:5]}")
    if personal.get('years'):
        print(f"  Years: {personal['years'][:10]}")

    # Recommendations
    print("\nSecurity Recommendations:")
    for rec in cred_analysis['recommendations']:
        print(f"  - {rec}")


async def example_5_password_checking():
    """Example 5: Check if passwords are compromised"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Password Compromise Checking")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')

    passwords_to_check = [
        "password123",
        "MySecureP@ssw0rd!",
        "qwerty",
        "Summer2024!"
    ]

    print("\nChecking passwords:")
    for password in passwords_to_check:
        results = await searcher.search_password(password)
        count = results.total_records

        if count > 0:
            status = "COMPROMISED"
            severity = "CRITICAL" if count > 100 else "HIGH"
        else:
            status = "SAFE"
            severity = "OK"

        print(f"  Password: {'*' * len(password):15} [{severity}] {status}")
        if count > 0:
            print(f"    Found {count} times in breaches")


async def example_6_domain_assessment():
    """Example 6: Assess all breaches for a domain"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Domain Breach Assessment")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')

    domain = "example.com"
    results = await searcher.search_domain(domain)

    print(f"\nDomain Assessment: {domain}")
    print(f"Total breach records: {results.total_records}")

    # Analyze exposed data types
    data_types = set()
    databases = set()

    for record in results.records:
        databases.add(record.database)
        if 'data_classes' in record.additional_data:
            data_types.update(record.additional_data['data_classes'])

    print(f"\nBreached Services: {len(databases)}")
    for db in list(databases)[:10]:
        print(f"  - {db}")

    if data_types:
        print(f"\nExposed Data Types:")
        for dt in sorted(data_types):
            print(f"  - {dt}")


async def example_7_hash_cracking():
    """Example 7: Crack password hashes"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Password Hash Cracking")
    print("="*60)

    from snusbase_integration import SnusbaseIntegration

    snusbase = SnusbaseIntegration(api_key="your-api-key")

    # Example hashes (common passwords)
    hashes_to_crack = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # password
        "482c811da5d5b4bc6d497ffa98491e38",  # password123
        "e10adc3949ba59abbe56e057f20f883e"   # 123456
    ]

    print("\nAttempting to crack hashes:")
    cracked = await snusbase.hash_lookup(hashes_to_crack)

    for hash_value, password in cracked.items():
        print(f"  {hash_value[:16]}... => {password}")


async def example_8_continuous_monitoring():
    """Example 8: Set up continuous breach monitoring"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Continuous Monitoring Setup")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')

    # Configure notifications
    notification_config = {
        'email_enabled': False,  # Set to True to enable
        'webhook_url': None      # Add webhook URL if needed
    }

    monitor = BreachMonitor(
        breach_search=searcher,
        notification_config=notification_config
    )

    # Add monitoring targets
    print("\nAdding monitoring targets:")

    # Monitor specific emails
    emails = [
        'ceo@company.com',
        'admin@company.com',
        'security@company.com'
    ]

    target_ids = monitor.add_email_watchlist(emails, check_interval=3600)
    print(f"  Added {len(emails)} email targets")

    # Monitor domains
    domains = ['company.com', 'example.com']
    domain_ids = monitor.add_domain_watchlist(domains, check_interval=7200)
    print(f"  Added {len(domains)} domain targets")

    # Register custom alert handler
    async def custom_alert_handler(alert):
        print(f"\n  ALERT: [{alert.severity.upper()}] {alert.message}")

    monitor.register_notification_callback(custom_alert_handler)

    # Get statistics
    stats = monitor.get_statistics()
    print(f"\nMonitoring Statistics:")
    print(f"  Total targets: {stats['total_targets']}")
    print(f"  Enabled targets: {stats['enabled_targets']}")

    print("\nMonitoring configured (not started in example)")
    # To start: await monitor.start_monitoring()


async def example_9_comprehensive_investigation():
    """Example 9: Complete target investigation"""
    print("\n" + "="*60)
    print("EXAMPLE 9: Comprehensive Target Investigation")
    print("="*60)

    searcher = BreachSearch(config_file='breach_config.json')
    target_email = "target@example.com"

    print(f"\nInvestigating: {target_email}\n")

    # Phase 1: Initial search
    print("Phase 1: Initial Breach Search")
    results = await searcher.search_email(target_email, correlate=True)

    print(f"  Found {results.total_records} records across {len(results.sources)} sources")

    # Phase 2: Extract intelligence
    print("\nPhase 2: Intelligence Extraction")

    # Get all usernames
    usernames = set(r.username for r in results.records if r.username)
    print(f"  Usernames discovered: {len(usernames)}")
    for username in list(usernames)[:5]:
        print(f"    - {username}")

    # Get all passwords
    passwords = set(r.password for r in results.records if r.password)
    print(f"  Passwords exposed: {len(passwords)}")

    # Get all databases
    databases = set(r.database for r in results.records)
    print(f"  Breached services: {len(databases)}")
    for db in list(databases)[:5]:
        print(f"    - {db}")

    # Phase 3: Correlation analysis
    print("\nPhase 3: Correlation Analysis")
    correlation_strength = results.correlations.get('correlation_strength', 0)
    print(f"  Correlation strength: {correlation_strength:.1%}")

    # Phase 4: Risk assessment
    print("\nPhase 4: Risk Assessment")
    cred_analysis = results.credential_analysis

    if 'security_analysis' in cred_analysis:
        avg_score = cred_analysis['security_analysis']['average_score']
        print(f"  Average password security: {avg_score:.1f}/100")

        # Calculate overall risk
        risk_factors = []

        if results.total_records > 10:
            risk_factors.append("Multiple breach exposure")

        if correlation_strength > 0.5:
            risk_factors.append("High credential correlation")

        if avg_score < 50:
            risk_factors.append("Weak password patterns")

        if len(passwords) < len(results.records) * 0.5:
            risk_factors.append("Password reuse detected")

        print(f"\n  Risk Factors Identified: {len(risk_factors)}")
        for factor in risk_factors:
            print(f"    - {factor}")

    # Phase 5: Generate report
    print("\nPhase 5: Report Generation")
    report_file = f"{target_email.replace('@', '_at_')}_investigation.html"
    searcher.export_results(results, report_file, format='html')
    print(f"  Investigation report: {report_file}")

    # Summary
    print("\n" + "-"*60)
    print("Investigation Summary:")
    print(f"  Target: {target_email}")
    print(f"  Breach Records: {results.total_records}")
    print(f"  Unique Passwords: {len(passwords)}")
    print(f"  Unique Usernames: {len(usernames)}")
    print(f"  Breached Services: {len(databases)}")
    print(f"  Risk Level: {'HIGH' if len(risk_factors) > 2 else 'MEDIUM' if len(risk_factors) > 0 else 'LOW'}")
    print("-"*60)


async def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("BREACH CORRELATION SYSTEM - EXAMPLE USAGE")
    print("="*60)

    try:
        # Run examples
        await example_1_basic_email_search()
        await example_2_multi_search()
        await example_3_correlation_analysis()
        await example_4_credential_analysis()
        await example_5_password_checking()
        await example_6_domain_assessment()
        # await example_7_hash_cracking()  # Requires Snusbase API key
        await example_8_continuous_monitoring()
        await example_9_comprehensive_investigation()

        print("\n" + "="*60)
        print("All examples completed successfully!")
        print("="*60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("\nNote: Make sure breach_config.json is configured with valid API keys")


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())
