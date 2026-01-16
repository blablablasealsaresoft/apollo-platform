#!/usr/bin/env python3
"""
Intelligence Fusion Engine - Example Usage
Demonstrates comprehensive intelligence profile building
"""

import logging
from datetime import datetime
from fusion_engine import IntelligenceFusion


def main():
    """Example: Building comprehensive intelligence profile"""

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("INTELLIGENCE FUSION ENGINE - EXAMPLE USAGE")
    print("=" * 70)

    # Initialize fusion engine with configuration
    fusion = IntelligenceFusion(config_path='fusion_rules.yaml')

    print("\n[1] Ingesting Intelligence from Multiple Sources...")
    print("-" * 70)

    # Source 1: OSINT Data
    osint_data = {
        'email': 'ruja.ignatova@onecoin.eu',
        'name': 'Ruja Ignatova',
        'aliases': ['Cryptoqueen', 'Dr. Ruja'],
        'location': 'Bulgaria',
        'occupation': 'CEO',
        'organization': 'OneCoin Ltd'
    }
    fusion.ingest_intelligence(osint_data, 'osint')
    print("✓ OSINT data ingested")

    # Source 2: Data Breach
    breach_data = {
        'email': 'ruja.ignatova@onecoin.eu',
        'breach': 'LinkedIn2021',
        'password_hash': 'sha1:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',
        'phone': '+359888123456',
        'name': 'Ruja Ignatova'
    }
    fusion.ingest_intelligence(breach_data, 'breach')
    print("✓ Breach data ingested")

    # Source 3: Another Breach
    breach_data2 = {
        'email': 'ruja.ignatova@onecoin.eu',
        'breach': 'Adobe2013',
        'password_hash': 'md5:e10adc3949ba59abbe56e057f20f883e',
        'username': 'cryptoqueen'
    }
    fusion.ingest_intelligence(breach_data2, 'breach')
    print("✓ Second breach data ingested")

    # Source 4: Blockchain Data
    blockchain_data = {
        'wallet': '0x742d35Cc6634C0532925a3b844e76735d82c8b91',
        'owner_email': 'ruja.ignatova@onecoin.eu',
        'blockchain': 'Ethereum',
        'transactions': 147,
        'total_volume': '1.2M USD',
        'balance': '45000 USD'
    }
    fusion.ingest_intelligence(blockchain_data, 'blockchain')
    print("✓ Blockchain data ingested")

    # Source 5: Another wallet
    blockchain_data2 = {
        'wallet': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'owner_email': 'ruja.ignatova@onecoin.eu',
        'blockchain': 'Bitcoin',
        'transactions': 89,
        'total_volume': '850K USD'
    }
    fusion.ingest_intelligence(blockchain_data2, 'blockchain')
    print("✓ Second blockchain data ingested")

    # Source 6: Social Media (Sherlock)
    sherlock_data = {
        'username': 'cryptoqueen',
        'platforms': ['Twitter', 'Instagram', 'LinkedIn', 'Facebook'],
        'email': 'ruja.ignatova@onecoin.eu'
    }
    fusion.ingest_intelligence(sherlock_data, 'sherlock')
    print("✓ Sherlock data ingested")

    # Source 7: SOCMINT
    socmint_data = {
        'platform': 'LinkedIn',
        'username': 'ruja-ignatova',
        'email': 'ruja.ignatova@onecoin.eu',
        'followers': 15000,
        'posts': 342,
        'joined_date': '2012-03-15',
        'location': 'Sofia, Bulgaria'
    }
    fusion.ingest_intelligence(socmint_data, 'socmint')
    print("✓ SOCMINT data ingested")

    print(f"\n✓ Total intelligence sources ingested: {len(fusion.raw_intelligence)}")

    # Build comprehensive profile
    print("\n[2] Building Comprehensive Intelligence Profile...")
    print("-" * 70)

    profile = fusion.build_profile(
        target='ruja.ignatova@onecoin.eu',
        sources=['osint', 'breach', 'blockchain', 'sherlock', 'socmint'],
        deep_analysis=True
    )

    print(f"✓ Profile built successfully")

    # Display results
    print("\n[3] Profile Summary")
    print("=" * 70)
    print(f"Entity ID:           {profile.entity_id}")
    print(f"Primary Identifier:  {profile.primary_identifier}")
    print(f"Entity Type:         {profile.entity_type}")
    print(f"Confidence Score:    {profile.confidence_score:.1f}/100")
    print(f"Risk Score:          {profile.risk_score:.1f}/100")

    # Categorize risk
    from risk_assessor import RiskAssessor
    assessor = RiskAssessor(fusion.config.get('risk', {}))
    risk_category = assessor.categorize_risk(profile.risk_score)
    print(f"Risk Category:       {risk_category}")

    print(f"\nData Coverage:")
    print(f"  • Sources:         {len(profile.sources)}")
    print(f"  • Attributes:      {len(profile.attributes)}")
    print(f"  • Aliases:         {len(profile.aliases)}")
    print(f"  • Relationships:   {len(profile.relationships)}")
    print(f"  • Timeline Events: {len(profile.timeline)}")

    # Display attributes
    print(f"\n[4] Attributes")
    print("-" * 70)
    for key, value in list(profile.attributes.items())[:10]:
        if isinstance(value, list):
            print(f"  • {key}: {', '.join(str(v) for v in value[:3])}")
        else:
            print(f"  • {key}: {value}")

    # Display aliases
    if profile.aliases:
        print(f"\n[5] Aliases ({len(profile.aliases)})")
        print("-" * 70)
        for alias in list(profile.aliases)[:10]:
            print(f"  • {alias}")

    # Display relationships
    if profile.relationships:
        print(f"\n[6] Relationships ({len(profile.relationships)})")
        print("-" * 70)
        for rel in profile.relationships[:5]:
            print(f"  • {rel.get('type', 'related').upper()}: {rel.get('target', 'N/A')[:50]} (Score: {rel.get('score', 0):.2f})")

    # Display timeline
    if profile.timeline:
        print(f"\n[7] Timeline ({len(profile.timeline)} events)")
        print("-" * 70)
        for event in profile.timeline[:10]:
            timestamp = event.get('timestamp', 'Unknown')[:19]
            description = event.get('description', 'N/A')
            event_type = event.get('type', 'unknown')
            print(f"  • [{timestamp}] {event_type.upper()}: {description}")

    # Display patterns
    if profile.metadata.get('patterns'):
        print(f"\n[8] Detected Patterns")
        print("-" * 70)
        for pattern in profile.metadata['patterns']:
            severity = pattern.get('severity', 'unknown').upper()
            description = pattern.get('description', 'N/A')
            print(f"  • [{severity}] {description}")

    # Graph analysis
    if profile.metadata.get('graph_analysis'):
        graph_analysis = profile.metadata['graph_analysis']
        print(f"\n[9] Network Analysis")
        print("-" * 70)

        centrality = graph_analysis.get('centrality', {})
        print(f"  Centrality Measures:")
        print(f"    • Degree:       {centrality.get('degree', 0):.3f}")
        print(f"    • Betweenness:  {centrality.get('betweenness', 0):.3f}")
        print(f"    • Closeness:    {centrality.get('closeness', 0):.3f}")
        print(f"    • Eigenvector:  {centrality.get('eigenvector', 0):.3f}")

        print(f"\n  Influence Score:  {graph_analysis.get('influence_score', 0):.1f}/100")

        communities = graph_analysis.get('communities', [])
        if communities:
            print(f"  Communities:      {len(communities)}")

    # Generate detailed reports
    print(f"\n[10] Generating Reports...")
    print("-" * 70)

    # Markdown report
    markdown_report = fusion.generate_intelligence_report(profile.entity_id, format='markdown')
    with open('intelligence_report.md', 'w', encoding='utf-8') as f:
        f.write(markdown_report)
    print("✓ Markdown report saved: intelligence_report.md")

    # JSON report
    json_report = fusion.generate_intelligence_report(profile.entity_id, format='json')
    with open('intelligence_report.json', 'w', encoding='utf-8') as f:
        f.write(json_report)
    print("✓ JSON report saved: intelligence_report.json")

    # HTML report
    html_report = fusion.generate_intelligence_report(profile.entity_id, format='html')
    with open('intelligence_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    print("✓ HTML report saved: intelligence_report.html")

    # Export graph
    try:
        fusion.export_graph(profile.entity_id, 'network_graph.gexf', format='gexf')
        print("✓ Network graph exported: network_graph.gexf")
    except Exception as e:
        print(f"! Graph export failed: {e}")

    # Confidence breakdown
    print(f"\n[11] Confidence Breakdown")
    print("-" * 70)
    from confidence_scorer import ConfidenceScorer
    scorer = ConfidenceScorer(fusion.config.get('confidence', {}))
    breakdown = scorer.get_confidence_breakdown(profile, fusion.raw_intelligence)

    for component, data in breakdown['components'].items():
        score = data['score']
        weight = data['weight']
        print(f"  • {component.replace('_', ' ').title()}: {score:.1f}/100 (weight: {weight:.0%})")

    # Risk breakdown
    print(f"\n[12] Risk Assessment Breakdown")
    print("-" * 70)
    risk_breakdown = assessor.get_risk_breakdown(profile, fusion.correlation_engine.correlate(
        [{'entity_id': profile.entity_id, 'type': profile.entity_type, 'attributes': profile.attributes, 'aliases': list(profile.aliases)}],
        fusion.raw_intelligence
    ))

    for component, data in risk_breakdown['components'].items():
        score = data['score']
        weight = data['weight']
        print(f"  • {component.replace('_', ' ').title()}: {score:.1f}/100 (weight: {weight:.0%})")

    # Threat indicators
    if risk_breakdown.get('threat_indicators'):
        print(f"\n[13] Threat Indicators")
        print("-" * 70)
        for indicator in risk_breakdown['threat_indicators']:
            severity = indicator.get('severity', 'unknown').upper()
            description = indicator.get('description', 'N/A')
            print(f"  • [{severity}] {description}")

    # Recommendations
    if risk_breakdown.get('recommendations'):
        print(f"\n[14] Recommendations")
        print("-" * 70)
        for i, recommendation in enumerate(risk_breakdown['recommendations'], 1):
            print(f"  {i}. {recommendation}")

    print("\n" + "=" * 70)
    print("INTELLIGENCE FUSION COMPLETE")
    print("=" * 70)

    print(f"\n📊 Summary:")
    print(f"  • Confidence: {profile.confidence_score:.1f}/100")
    print(f"  • Risk:       {profile.risk_score:.1f}/100 ({risk_category})")
    print(f"  • Sources:    {len(profile.sources)}")
    print(f"  • Entities:   {len(fusion.entities)}")
    print(f"\n✓ All reports generated successfully!")


if __name__ == '__main__':
    main()
