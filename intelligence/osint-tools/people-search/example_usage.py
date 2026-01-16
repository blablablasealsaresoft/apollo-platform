"""
Example Usage - People Search & Background Intelligence
Demonstrates all features of the people search system
"""

import asyncio
import json
from datetime import datetime

from people_search import PeopleSearch, PersonProfile
from spokeo_integration import SpokeoIntegration
from pipl_integration import PiplIntegration
from truepeoplesearch import TruePeopleSearch
from background_checker import BackgroundChecker
from voter_records import VoterRecordsSearch
from social_profile_aggregator import SocialProfileAggregator


async def example_basic_search():
    """Example 1: Basic people search"""
    print("="*80)
    print("Example 1: Basic People Search")
    print("="*80)

    config = json.load(open('config.json')) if os.path.exists('config.json') else {}

    async with PeopleSearch(config) as search:
        profile = await search.investigate(
            name="John Doe",
            location="New York, NY"
        )

        # Print text report
        print(search.export_report(profile, format='text'))

        # Save JSON report
        with open('basic_search_report.json', 'w') as f:
            f.write(search.export_report(profile, format='json'))


async def example_multi_source_search():
    """Example 2: Search with multiple identifiers"""
    print("="*80)
    print("Example 2: Multi-Source Search")
    print("="*80)

    config = json.load(open('config.json'))

    async with PeopleSearch(config) as search:
        profile = await search.investigate(
            name="John Doe",
            email="john.doe@example.com",
            phone="555-123-4567",
            address="123 Main St, New York, NY",
            location="New York, NY",
            deep_search=True
        )

        print(f"Confidence Score: {profile.confidence_score:.1f}/100")
        print(f"Data Sources: {len(profile.sources)}")
        print(f"Addresses Found: {len(profile.addresses)}")
        print(f"Phone Numbers: {len(profile.phone_numbers)}")
        print(f"Email Addresses: {len(profile.email_addresses)}")
        print(f"Relatives: {len(profile.relatives)}")


async def example_spokeo_search():
    """Example 3: Spokeo commercial search"""
    print("="*80)
    print("Example 3: Spokeo Search")
    print("="*80)

    api_key = "your_spokeo_api_key"

    async with SpokeoIntegration(api_key) as spokeo:
        # Name search
        profiles = await spokeo.search_person(
            first_name="John",
            last_name="Doe",
            city="New York",
            state="NY",
            age_min=30,
            age_max=40
        )

        print(f"Found {len(profiles)} matching profiles")

        for profile in profiles[:3]:
            print(spokeo.export_profile(profile, format='text'))

        # Reverse phone lookup
        if len(profiles) > 0 and profiles[0].phones:
            phone = profiles[0].phones[0]
            phone_profile = await spokeo.reverse_phone_lookup(phone)
            if phone_profile:
                print("Phone lookup successful!")


async def example_pipl_search():
    """Example 4: Pipl deep web search"""
    print("="*80)
    print("Example 4: Pipl Deep Web Search")
    print("="*80)

    api_key = "your_pipl_api_key"

    async with PiplIntegration(api_key) as pipl:
        # Comprehensive search
        person = await pipl.comprehensive_search(
            name="John Doe",
            email="john@example.com",
            phone="+1-555-123-4567",
            location={'city': 'New York', 'state': 'NY', 'country': 'US'},
            minimum_probability=0.7
        )

        if person:
            print(pipl.export_person(person, format='text'))

            # Extract key information
            print(f"\nPrimary Email: {pipl.get_primary_email(person)}")
            print(f"Primary Phone: {pipl.get_primary_phone(person)}")
            print(f"Match Score: {person.match_score:.2f}")
            print(f"Data Sources: {len(person.sources)}")


async def example_truepeoplesearch():
    """Example 5: Free people search"""
    print("="*80)
    print("Example 5: TruePeopleSearch (Free)")
    print("="*80)

    async with TruePeopleSearch(rate_limit=2.0) as tps:
        # Search by name
        results = await tps.search_by_name(
            first_name="John",
            last_name="Doe",
            city="New York",
            state="NY"
        )

        print(f"Found {len(results)} results")

        # Get full profiles
        for result in results[:2]:
            if result.profile_url:
                full_profile = await tps.get_full_profile(result.profile_url)
                if full_profile:
                    print(tps.export_profile(full_profile, format='text'))

        # Comprehensive search (auto-fetches full profiles)
        comprehensive = await tps.comprehensive_search(
            name="John Doe",
            location="New York, NY"
        )

        print(f"Comprehensive search found {len(comprehensive)} detailed profiles")


async def example_background_check():
    """Example 6: Background check"""
    print("="*80)
    print("Example 6: Background Check")
    print("="*80)

    async with BackgroundChecker() as checker:
        report = await checker.comprehensive_check(
            name="John Doe",
            dob="1980-01-01",
            state="NY",
            county="New York"
        )

        print(checker.export_report(report, format='text'))

        # Detailed analysis
        print(f"\nRisk Score: {report.risk_score:.1f}/100")
        print(f"Completeness: {report.completeness_score:.1f}%")

        print(f"\nCriminal Records: {len(report.criminal_records)}")
        print(f"Court Cases: {len(report.court_cases)}")
        print(f"Property Records: {len(report.property_records)}")
        print(f"Business Affiliations: {len(report.business_affiliations)}")

        # High-risk items
        if report.sex_offender_registry:
            print("\n⚠️ SEX OFFENDER REGISTRY MATCH")

        felonies = [r for r in report.criminal_records if r.severity == 'felony']
        if felonies:
            print(f"\n⚠️ {len(felonies)} FELONY CONVICTION(S)")


async def example_voter_records():
    """Example 7: Voter registration search"""
    print("="*80)
    print("Example 7: Voter Records")
    print("="*80)

    async with VoterRecordsSearch() as vrs:
        # Search voter registration
        records = await vrs.search_voter(
            first_name="John",
            last_name="Doe",
            state="NY",
            county="New York"
        )

        for record in records:
            print(vrs.export_record(record, format='text'))

            # Analyze voting patterns
            analysis = vrs.analyze_voting_pattern(record)
            print(f"\nVoting Analysis:")
            print(f"  Engagement Level: {analysis['voter_engagement']}")
            print(f"  Registration Duration: {analysis['registration_duration']}")
            print(f"  Preferred Elections: {analysis['preferred_elections']}")

        # Verify registration
        verified = await vrs.verify_registration(
            name="John Doe",
            address="123 Main St",
            state="NY"
        )

        if verified:
            print("\n✓ Voter registration verified")
        else:
            print("\n✗ No voter registration found")


async def example_social_profiles():
    """Example 8: Social media aggregation"""
    print("="*80)
    print("Example 8: Social Media Profiles")
    print("="*80)

    async with SocialProfileAggregator() as spa:
        # Search by username
        network = await spa.search_username("johndoe")

        print(spa.export_network(network, format='text'))

        # Generate network graph
        graph = spa.generate_network_graph(network)
        print(f"\nNetwork Graph:")
        print(f"  Nodes: {len(graph['nodes'])}")
        print(f"  Edges: {len(graph['edges'])}")
        print(f"  Total Followers: {graph['stats']['total_followers']:,}")

        # Search by real name
        network2 = await spa.search_name("John Doe")
        print(f"\nFound {len(network2.profiles)} profiles for 'John Doe'")

        # Correlate profiles
        if len(network2.profiles) >= 2:
            correlations = await spa.correlate_profiles(network2.profiles)
            print(f"\nProfile Correlations:")
            for key, score in correlations.items():
                print(f"  {key}: {score:.2f}")


async def example_comprehensive_investigation():
    """Example 9: Full comprehensive investigation"""
    print("="*80)
    print("Example 9: Comprehensive Investigation")
    print("="*80)

    # Load configuration
    config = json.load(open('config.json'))

    target = {
        'name': 'John Doe',
        'location': 'New York, NY',
        'email': 'john.doe@example.com',
        'phone': '555-123-4567'
    }

    results = {}

    # 1. Main people search
    print("\n[1/7] Running main people search...")
    async with PeopleSearch(config) as ps:
        results['people_search'] = await ps.investigate(
            name=target['name'],
            location=target['location'],
            email=target['email'],
            phone=target['phone'],
            deep_search=True
        )
    print(f"✓ Confidence: {results['people_search'].confidence_score:.1f}/100")

    # 2. Spokeo
    if config.get('spokeo_api_key'):
        print("\n[2/7] Searching Spokeo...")
        async with SpokeoIntegration(config['spokeo_api_key']) as spokeo:
            name_parts = target['name'].split()
            profiles = await spokeo.search_person(
                first_name=name_parts[0],
                last_name=name_parts[-1]
            )
            results['spokeo'] = profiles[0] if profiles else None
        print(f"✓ Found {len(profiles)} profiles")

    # 3. Pipl
    if config.get('pipl_api_key'):
        print("\n[3/7] Searching Pipl deep web...")
        async with PiplIntegration(config['pipl_api_key']) as pipl:
            results['pipl'] = await pipl.comprehensive_search(
                name=target['name'],
                email=target['email'],
                phone=target['phone']
            )
        if results['pipl']:
            print(f"✓ Match score: {results['pipl'].match_score:.2f}")

    # 4. TruePeopleSearch
    print("\n[4/7] Searching TruePeopleSearch (free)...")
    async with TruePeopleSearch() as tps:
        tps_results = await tps.comprehensive_search(
            target['name'],
            target['location']
        )
        results['truepeoplesearch'] = tps_results[0] if tps_results else None
    print(f"✓ Found {len(tps_results)} detailed profiles")

    # 5. Background check
    print("\n[5/7] Running background check...")
    async with BackgroundChecker(config) as bc:
        state = target['location'].split(',')[-1].strip()[:2]
        results['background'] = await bc.comprehensive_check(
            name=target['name'],
            state=state
        )
    print(f"✓ Risk score: {results['background'].risk_score:.1f}/100")

    # 6. Voter records
    print("\n[6/7] Checking voter registration...")
    async with VoterRecordsSearch() as vrs:
        name_parts = target['name'].split()
        state = target['location'].split(',')[-1].strip()[:2]
        voter_records = await vrs.search_voter(
            first_name=name_parts[0],
            last_name=name_parts[-1],
            state=state
        )
        results['voter'] = voter_records[0] if voter_records else None
    print(f"✓ Found {len(voter_records)} voter records")

    # 7. Social media
    print("\n[7/7] Aggregating social profiles...")
    async with SocialProfileAggregator() as spa:
        results['social'] = await spa.search_name(target['name'])
    print(f"✓ Found on {results['social'].platforms_found} platforms")

    # Generate comprehensive report
    print("\n" + "="*80)
    print("COMPREHENSIVE INVESTIGATION REPORT")
    print("="*80)
    print(f"Subject: {target['name']}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    # Summary statistics
    print("\nSUMMARY:")
    print(f"  Overall Confidence: {results['people_search'].confidence_score:.1f}/100")
    print(f"  Risk Score: {results['background'].risk_score:.1f}/100")
    print(f"  Addresses Found: {len(results['people_search'].addresses)}")
    print(f"  Phone Numbers: {len(results['people_search'].phone_numbers)}")
    print(f"  Email Addresses: {len(results['people_search'].email_addresses)}")
    print(f"  Social Profiles: {results['social'].platforms_found}")
    print(f"  Criminal Records: {len(results['background'].criminal_records)}")

    # Save comprehensive report
    report_filename = f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump({
            'subject': target,
            'investigation_date': datetime.now().isoformat(),
            'results': {
                'people_search': results['people_search'].to_dict(),
                'background': {
                    'risk_score': results['background'].risk_score,
                    'criminal_records': len(results['background'].criminal_records),
                    'court_cases': len(results['background'].court_cases),
                    'property_records': len(results['background'].property_records)
                },
                'social': {
                    'platforms_found': results['social'].platforms_found,
                    'total_followers': results['social'].total_followers
                }
            }
        }, f, indent=2)

    print(f"\n✓ Report saved to {report_filename}")


async def example_batch_processing():
    """Example 10: Batch processing multiple subjects"""
    print("="*80)
    print("Example 10: Batch Processing")
    print("="*80)

    subjects = [
        {"name": "John Doe", "location": "New York, NY"},
        {"name": "Jane Smith", "location": "Los Angeles, CA"},
        {"name": "Bob Johnson", "location": "Chicago, IL"}
    ]

    config = json.load(open('config.json'))

    async with PeopleSearch(config) as search:
        for subject in subjects:
            print(f"\nInvestigating: {subject['name']}")

            profile = await search.investigate(
                name=subject['name'],
                location=subject['location']
            )

            print(f"  Confidence: {profile.confidence_score:.1f}/100")
            print(f"  Addresses: {len(profile.addresses)}")
            print(f"  Phones: {len(profile.phone_numbers)}")

            # Save individual report
            filename = f"{subject['name'].replace(' ', '_')}_report.json"
            with open(filename, 'w') as f:
                f.write(search.export_report(profile, format='json'))

            print(f"  ✓ Saved to {filename}")


# Main execution
async def main():
    """Run all examples"""
    import os

    print("\n" + "="*80)
    print("PEOPLE SEARCH & BACKGROUND INTELLIGENCE - EXAMPLES")
    print("="*80 + "\n")

    # Check for config file
    if not os.path.exists('config.json'):
        print("⚠️  config.json not found. Using example configuration.")
        print("Copy config.example.json to config.json and add your API keys.\n")

    examples = [
        ("Basic Search", example_basic_search),
        ("Multi-Source Search", example_multi_source_search),
        ("Spokeo Search", example_spokeo_search),
        ("Pipl Deep Web", example_pipl_search),
        ("TruePeopleSearch (Free)", example_truepeoplesearch),
        ("Background Check", example_background_check),
        ("Voter Records", example_voter_records),
        ("Social Profiles", example_social_profiles),
        ("Comprehensive Investigation", example_comprehensive_investigation),
        ("Batch Processing", example_batch_processing)
    ]

    # Run specific example or all
    import sys
    if len(sys.argv) > 1:
        example_num = int(sys.argv[1])
        if 1 <= example_num <= len(examples):
            name, func = examples[example_num - 1]
            print(f"Running Example {example_num}: {name}\n")
            await func()
        else:
            print(f"Invalid example number. Choose 1-{len(examples)}")
    else:
        # Run all examples
        for i, (name, func) in enumerate(examples, 1):
            print(f"\n{'='*80}")
            print(f"Example {i}: {name}")
            print(f"{'='*80}\n")
            try:
                await func()
            except Exception as e:
                print(f"❌ Error: {e}")
            print("\n")


if __name__ == "__main__":
    import os
    asyncio.run(main())
