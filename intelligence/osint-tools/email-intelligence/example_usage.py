"""
Email Intelligence System - Complete Usage Example
Demonstrates all features of the email OSINT toolkit
"""

import json
from datetime import datetime

# Import all modules
from email_intel import EmailIntelligence
from email_validator import EmailValidator
from email_reputation import EmailReputation
from holehe_integration import HoleheIntegration
from email_hunter import EmailHunter
from email_format import EmailFormatFinder, PermutationGenerator
from email_header_analyzer import EmailHeaderAnalyzer
from email_correlator import EmailCorrelator


def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*70}")
    print(f"{title.center(70)}")
    print(f"{'='*70}\n")


def example_1_basic_validation():
    """Example 1: Basic Email Validation"""
    print_section("Example 1: Basic Email Validation")

    validator = EmailValidator(verify_smtp=False)

    emails = [
        "john.doe@company.com",
        "invalid@email",
        "temp@10minutemail.com",
        "admin@example.com"
    ]

    for email in emails:
        result = validator.validate(email)
        print(f"Email: {email}")
        print(f"  Valid: {result['valid']}")
        print(f"  Disposable: {result['disposable']}")
        print(f"  Role-based: {result['role_based']}")
        print(f"  MX Valid: {result['mx_valid']}")
        if result['errors']:
            print(f"  Errors: {', '.join(result['errors'])}")
        print()


def example_2_reputation_check():
    """Example 2: Email Reputation Analysis"""
    print_section("Example 2: Email Reputation Analysis")

    # Note: Requires API key for full functionality
    reputation = EmailReputation(api_key=None)

    email = "test@example.com"
    result = reputation.check(email)

    print(f"Email: {email}")
    print(f"Reputation: {result.get('reputation', 'unknown')}")
    print(f"Spam Score: {result.get('spam_score', 0)}/100")
    print(f"Malicious: {result.get('malicious', False)}")
    print(f"Suspicious: {result.get('suspicious', False)}")
    print(f"Blacklisted: {result.get('blacklisted', False)}")

    # Get risk assessment
    assessment = reputation.get_risk_assessment(email)
    print(f"\nRisk Assessment:")
    print(f"  Level: {assessment['risk_level']}")
    print(f"  Score: {assessment['risk_score']}/100")
    print(f"  Recommendation: {assessment['recommendation']}")


def example_3_account_enumeration():
    """Example 3: Account Enumeration with Holehe"""
    print_section("Example 3: Account Enumeration")

    holehe = HoleheIntegration(timeout=5, max_concurrent=10)

    email = "test@example.com"

    print(f"Checking {email} across platforms...")
    print("(This is a demo - actual checks would contact real services)\n")

    # Get available categories
    categories = holehe.get_categories()
    print(f"Available categories: {', '.join(categories)}")

    # Check specific category (demo - won't actually make requests)
    print(f"\nDemo: Checking social media platforms...")
    social_platforms = holehe.get_platforms_by_category('social_media')
    print(f"Would check: {', '.join(social_platforms[:5])}...")


def example_4_email_hunter():
    """Example 4: Email Discovery with Hunter"""
    print_section("Example 4: Email Discovery")

    # Note: Requires API key for full functionality
    hunter = EmailHunter(api_key=None)

    domain = "example.com"

    # Detect email pattern
    pattern = hunter.get_email_pattern(domain)
    print(f"Domain: {domain}")
    print(f"Pattern: {pattern.pattern}")
    print(f"Confidence: {pattern.confidence:.2%}")
    print(f"Example: {pattern.example}")

    # Generate email
    email = hunter.generate_email("John", "Doe", domain)
    print(f"\nGenerated email: {email}")

    # Generate variations
    print(f"\nEmail variations:")
    variations = hunter.generate_email_variations("John", "Doe", domain)
    for i, var in enumerate(variations[:5], 1):
        print(f"  {i}. {var}")


def example_5_format_detection():
    """Example 5: Email Format Detection"""
    print_section("Example 5: Email Format Detection")

    finder = EmailFormatFinder()

    # Sample emails from company
    sample_emails = [
        "john.doe@company.com",
        "jane.smith@company.com",
        "bob.johnson@company.com"
    ]

    print("Sample emails:")
    for email in sample_emails:
        print(f"  - {email}")

    # Detect pattern
    pattern = finder.detect_pattern(sample_emails)
    if pattern:
        print(f"\nDetected Pattern: {pattern.pattern}")
        print(f"Confidence: {pattern.confidence:.2%}")
        print(f"Description: {finder.get_pattern_description(pattern.pattern)}")

    # Generate all variations
    print(f"\nAll possible variations for 'John Doe' at 'company.com':")
    variations = finder.generate_all_variations("John", "Doe", "company.com")
    for var in variations[:8]:
        print(f"  - {var['email']}")

    # Generate permutations
    print(f"\nPermutations (including numbers):")
    gen = PermutationGenerator()
    perms = gen.generate_permutations("John", "Doe", "company.com",
                                     include_numbers=True)
    for perm in perms[:10]:
        print(f"  - {perm}")
    print(f"  ... and {len(perms) - 10} more")


def example_6_header_analysis():
    """Example 6: Email Header Analysis"""
    print_section("Example 6: Email Header Analysis")

    analyzer = EmailHeaderAnalyzer()

    # Sample email headers
    sample_headers = """From: sender@example.com
To: recipient@company.com
Subject: Important Business Matter
Date: Mon, 14 Jan 2026 10:30:00 +0000
Message-ID: <abc123@example.com>
Return-Path: <sender@example.com>
Received: from mail.example.com ([192.0.2.1])
    by mx.company.com with ESMTPS id xyz789
    for <recipient@company.com>; Mon, 14 Jan 2026 10:30:00 +0000
Received: from client.example.com ([198.51.100.42])
    by mail.example.com with SMTP id def456
    Mon, 14 Jan 2026 10:29:55 +0000
Authentication-Results: company.com; spf=pass; dkim=pass; dmarc=pass
"""

    analysis = analyzer.analyze(sample_headers)

    print(f"From: {analysis['from_address']}")
    print(f"To: {', '.join(analysis['to_addresses'])}")
    print(f"Subject: {analysis['subject']}")
    print(f"\nAuthentication:")
    print(f"  SPF: {analysis['spf_result']}")
    print(f"  DKIM: {analysis['dkim_result']}")
    print(f"  DMARC: {analysis['dmarc_result']}")
    print(f"\nRouting:")
    print(f"  Total Hops: {analysis['hop_count']}")
    print(f"  IP Addresses: {', '.join(analysis['ip_addresses'])}")

    if analysis['suspicious_indicators']:
        print(f"\nSuspicious Indicators:")
        for indicator in analysis['suspicious_indicators']:
            print(f"  - {indicator}")
    else:
        print(f"\nNo suspicious indicators found")


def example_7_correlation():
    """Example 7: Cross-Source Correlation"""
    print_section("Example 7: Cross-Source Correlation")

    correlator = EmailCorrelator()

    # Sample data from various sources
    sample_data = {
        'accounts': [
            {'platform': 'twitter', 'username': 'johndoe', 'exists': True},
            {'platform': 'github', 'username': 'john.doe', 'exists': True},
            {'platform': 'linkedin', 'username': 'johndoe', 'exists': True},
        ],
        'breaches': [],
        'social_media': []
    }

    email = "john.doe@example.com"
    result = correlator.correlate(email, sample_data)

    print(f"Email: {email}")
    print(f"Username: {result['username']}")
    print(f"Confidence Score: {result['confidence_score']:.2%}")

    print(f"\nRelated Usernames:")
    for username in result['related_usernames'][:5]:
        print(f"  - {username}")

    print(f"\nSocial Media Accounts:")
    for account in result['social_media_accounts']:
        status = "✓" if account.get('exists') else "?"
        print(f"  {status} {account['platform'].title()}: {account.get('url', 'N/A')}")

    # Link multiple accounts
    print(f"\n{'─'*70}")
    print("Linking multiple email accounts...")

    emails = [
        "john.doe@example.com",
        "johndoe@gmail.com",
        "j.doe@company.com"
    ]

    linked = correlator.link_accounts(emails)
    print(f"\nEmails to link:")
    for e in emails:
        print(f"  - {e}")

    print(f"\nUnique Usernames: {', '.join(linked['usernames'])}")
    print(f"Domains: {', '.join(linked['domains'])}")
    print(f"Same Person Probability: {linked['likely_same_person']:.2%}")


def example_8_complete_investigation():
    """Example 8: Complete Email Investigation"""
    print_section("Example 8: Complete Email Investigation")

    # Initialize with configuration
    config = {
        'emailrep_api_key': None,  # Add your API key here
        'hunter_api_key': None,     # Add your API key here
    }

    intel = EmailIntelligence(config)

    email = "test@example.com"

    print(f"Investigating: {email}")
    print("(Running comprehensive analysis...)\n")

    # Perform investigation
    profile = intel.investigate(email, deep=True)

    # Display results
    print(f"{'─'*70}")
    print("INVESTIGATION RESULTS")
    print(f"{'─'*70}\n")

    print(f"Risk Assessment:")
    print(f"  Level: {profile.summary['risk_level']}")
    print(f"  Score: {profile.risk_score}/100")

    print(f"\nValidation:")
    print(f"  Valid: {profile.validation['valid']}")
    print(f"  Syntax: {profile.validation['syntax_valid']}")
    print(f"  Domain: {profile.validation['domain_valid']}")
    print(f"  MX Records: {profile.validation['mx_valid']}")
    print(f"  Disposable: {profile.validation['disposable']}")
    print(f"  Role-based: {profile.validation['role_based']}")

    print(f"\nDomain Information:")
    domain_info = profile.domain_info
    print(f"  Domain: {domain_info.get('domain', 'N/A')}")
    if domain_info.get('mx_records'):
        print(f"  MX Records: {', '.join(domain_info['mx_records'][:3])}")

    print(f"\nFindings:")
    print(f"  Total Accounts: {len(profile.accounts)}")
    print(f"  Total Breaches: {len(profile.breaches)}")
    print(f"  Social Media Profiles: {len(profile.social_media)}")
    print(f"  Related Emails: {len(profile.related_emails)}")
    print(f"  Related Usernames: {len(profile.related_usernames)}")

    if profile.summary['key_findings']:
        print(f"\nKey Findings:")
        for finding in profile.summary['key_findings']:
            print(f"  - {finding}")

    # Export demonstration
    print(f"\n{'─'*70}")
    print("Export Examples:")
    print(f"{'─'*70}\n")

    # JSON export
    json_output = intel.export_profile(profile, format='json')
    print(f"JSON export: {len(json_output)} characters")

    # CSV export
    csv_output = intel.export_profile(profile, format='csv')
    print(f"CSV export: {len(csv_output)} characters")

    print("\nInvestigation complete!")


def example_9_batch_processing():
    """Example 9: Batch Email Processing"""
    print_section("Example 9: Batch Email Processing")

    config = {
        'emailrep_api_key': None,
        'hunter_api_key': None,
    }

    intel = EmailIntelligence(config)

    # Sample email list
    emails = [
        "user1@example.com",
        "user2@example.com",
        "user3@example.com",
        "admin@company.com",
        "test@test.com"
    ]

    print(f"Processing {len(emails)} emails in batch...\n")

    # Batch investigate
    profiles = intel.batch_investigate(emails, workers=3)

    # Summary statistics
    print(f"Results Summary:")
    print(f"  Total Processed: {len(profiles)}")

    valid_count = sum(1 for p in profiles if p.validation['valid'])
    print(f"  Valid Emails: {valid_count}")

    high_risk = [p for p in profiles if p.risk_score >= 50]
    print(f"  High Risk: {len(high_risk)}")

    medium_risk = [p for p in profiles if 25 <= p.risk_score < 50]
    print(f"  Medium Risk: {len(medium_risk)}")

    low_risk = [p for p in profiles if p.risk_score < 25]
    print(f"  Low Risk: {len(low_risk)}")

    if high_risk:
        print(f"\nHigh Risk Emails:")
        for profile in high_risk:
            print(f"  - {profile.email} (Score: {profile.risk_score}/100)")


def main():
    """Run all examples"""
    print_section("EMAIL INTELLIGENCE SYSTEM - COMPLETE EXAMPLES")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        example_1_basic_validation()
        input("\nPress Enter to continue to Example 2...")

        example_2_reputation_check()
        input("\nPress Enter to continue to Example 3...")

        example_3_account_enumeration()
        input("\nPress Enter to continue to Example 4...")

        example_4_email_hunter()
        input("\nPress Enter to continue to Example 5...")

        example_5_format_detection()
        input("\nPress Enter to continue to Example 6...")

        example_6_header_analysis()
        input("\nPress Enter to continue to Example 7...")

        example_7_correlation()
        input("\nPress Enter to continue to Example 8...")

        example_8_complete_investigation()
        input("\nPress Enter to continue to Example 9...")

        example_9_batch_processing()

        print_section("ALL EXAMPLES COMPLETED")
        print("Thank you for exploring the Email Intelligence System!")

    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user.")
    except Exception as e:
        print(f"\n\nError running examples: {str(e)}")


if __name__ == "__main__":
    main()
