"""
Wallet Clustering System - Demonstration Script
Shows comprehensive usage of all clustering components
"""

import json
from datetime import datetime

# Import all components
from wallet_clustering import WalletClusterer
from common_input_heuristic import CommonInputHeuristic
from change_address_detector import ChangeAddressDetector
from peel_chain_analyzer import PeelChainAnalyzer
from entity_attribution import EntityAttributor, KnownEntity
from cluster_visualizer import ClusterVisualizer
from mixing_detector import MixingDetector
from exchange_identifier import ExchangeIdentifier


def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_basic_clustering():
    """Demonstrate basic wallet clustering"""
    print_section("BASIC WALLET CLUSTERING")

    # Initialize clusterer
    clusterer = WalletClusterer()

    # Analyze a wallet
    test_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Genesis block address
    print(f"Analyzing wallet: {test_address}")

    result = clusterer.analyze_wallet(test_address, depth=2)

    # Display results
    print(f"\n📊 Clustering Results:")
    print(f"  Cluster ID: {result.cluster.cluster_id}")
    print(f"  Total addresses: {len(result.cluster.addresses)}")
    print(f"  Entity type: {result.cluster.entity_type or 'Unknown'}")
    print(f"  Entity name: {result.cluster.entity_name or 'Unknown'}")
    print(f"  Total links: {len(result.links)}")
    print(f"  Risk score: {result.risk_assessment['total_risk_score']:.2f}")
    print(f"  Risk level: {result.risk_assessment['risk_level']}")
    print(f"  Mixing detected: {'Yes' if result.mixing_detected else 'No'}")

    # Show link types
    link_types = {}
    for link in result.links:
        link_types[link.link_type] = link_types.get(link.link_type, 0) + 1

    print(f"\n🔗 Link Types:")
    for link_type, count in link_types.items():
        print(f"  {link_type}: {count}")

    return result


def demo_common_input_heuristic():
    """Demonstrate Common Input Heuristic"""
    print_section("COMMON INPUT HEURISTIC (CIH)")

    cih = CommonInputHeuristic()

    test_address = "1BitcoinEaterAddressDontSendf59kuE"
    print(f"Analyzing address: {test_address}")

    result = cih.analyze_address(test_address, depth=2)

    print(f"\n📈 CIH Results:")
    print(f"  Source address: {result['source_address']}")
    print(f"  Related addresses found: {result['total_related']}")
    print(f"  Multi-input transactions: {len(result['multi_input_transactions'])}")
    print(f"  Address groups: {len(result['address_groups'])}")

    print(f"\n🎯 Top Related Addresses:")
    for i, addr_data in enumerate(result['related_addresses'][:5], 1):
        print(f"  {i}. {addr_data['address'][:20]}...")
        print(f"     Confidence: {addr_data['confidence']:.2f}")
        print(f"     Common transactions: {addr_data['evidence']['common_transactions']}")


def demo_change_detection():
    """Demonstrate change address detection"""
    print_section("CHANGE ADDRESS DETECTION")

    detector = ChangeAddressDetector()

    test_address = "1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY"
    print(f"Analyzing address: {test_address}")

    result = detector.analyze_transactions(test_address, depth=2)

    print(f"\n💰 Change Detection Results:")
    print(f"  Source address: {result['source_address']}")
    print(f"  Change addresses found: {len(result['change_addresses'])}")
    print(f"  Transactions analyzed: {result['total_transactions_analyzed']}")

    print(f"\n🔄 Detected Change Addresses:")
    for i, change in enumerate(result['change_addresses'][:5], 1):
        print(f"  {i}. {change['address'][:20]}...")
        print(f"     Confidence: {change['confidence']:.2f}")
        print(f"     Evidence: {', '.join(change['evidence']['reasons'])}")
        print(f"     Value: {change['evidence']['value']:.4f} BTC")

    # Get statistics
    stats = detector.get_statistics()
    print(f"\n📊 Detector Statistics:")
    print(f"  Total addresses seen: {stats['total_addresses_seen']}")
    print(f"  One-time addresses: {stats['one_time_addresses']}")
    print(f"  Reuse rate: {stats['reuse_rate']:.2%}")


def demo_peel_chain_analysis():
    """Demonstrate peel chain detection"""
    print_section("PEEL CHAIN ANALYSIS")

    analyzer = PeelChainAnalyzer()

    test_address = "1PeelChainExample123456789ABCDEF"
    print(f"Analyzing address: {test_address}")

    result = analyzer.analyze_address(test_address, depth=10)

    print(f"\n⛓️  Peel Chain Results:")
    print(f"  Is peel chain: {'Yes' if result['is_peel_chain'] else 'No'}")
    print(f"  Total chains detected: {result['total_chains']}")
    print(f"  Max chain length: {result['max_chain_length']}")
    print(f"  Risk score: {result['risk_score']:.2f}")

    if result['is_peel_chain']:
        print(f"\n⚠️  Risk Indicators:")
        for indicator in result['indicators']:
            print(f"  • {indicator}")

        print(f"\n🔗 Chain Details:")
        for i, chain in enumerate(result['chains'][:3], 1):
            print(f"\n  Chain {i}:")
            print(f"    Length: {chain['chain_length']} hops")
            print(f"    Total peeled: {chain['total_peeled']:.4f} BTC")
            print(f"    Total amount: {chain['total_amount']:.4f} BTC")
            print(f"    Avg peel ratio: {chain['avg_peel_ratio']:.2%}")
            print(f"    Confidence: {chain['confidence']:.2f}")


def demo_entity_attribution():
    """Demonstrate entity attribution"""
    print_section("ENTITY ATTRIBUTION")

    attributor = EntityAttributor()

    # Show database statistics
    stats = attributor.get_statistics()
    print(f"📚 Entity Database:")
    print(f"  Total entities: {stats['total_entities']}")
    print(f"  Known addresses: {stats['total_known_addresses']}")
    print(f"\n  By type:")
    for entity_type, count in stats['by_type'].items():
        print(f"    {entity_type}: {count}")
    print(f"\n  By reputation:")
    for reputation, count in stats['by_reputation'].items():
        print(f"    {reputation}: {count}")

    # Search for exchanges
    print(f"\n🔍 Searching for exchanges:")
    exchanges = attributor.search_entities("exchange")
    for exchange in exchanges[:5]:
        print(f"  • {exchange['name']} ({exchange['entity_type']})")
        print(f"    Reputation: {exchange['reputation']}")

    # Add custom entity
    print(f"\n➕ Adding custom entity:")
    custom_entity = KnownEntity(
        entity_id="darknet_market_1",
        name="Hypothetical Darknet Market",
        entity_type="darknet_market",
        addresses={"1DarkAddr123", "1DarkAddr456"},
        reputation="malicious",
        tags={"darknet", "illegal_marketplace"}
    )
    attributor.add_known_entity(custom_entity)
    print(f"  Added: {custom_entity.name}")


def demo_mixing_detection():
    """Demonstrate mixing service detection"""
    print_section("MIXING SERVICE DETECTION")

    detector = MixingDetector()

    test_addresses = [
        "1MixAddr1234567890ABC",
        "1MixAddr2234567890DEF",
        "1MixAddr3234567890GHI"
    ]

    print(f"Analyzing {len(test_addresses)} addresses for mixing activity")

    result = detector.detect_mixing(test_addresses)

    print(f"\n🌀 Mixing Detection Results:")
    print(f"  Mixing detected: {'Yes' if result['detected'] else 'No'}")

    if result['detected']:
        print(f"  Service type: {result['service_type']}")
        print(f"  Service name: {result['service_name']}")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Mixing transactions: {len(result['mixing_transactions'])}")

        print(f"\n⚠️  Indicators:")
        for indicator in result['indicators']:
            print(f"  • {indicator}")

    # Demonstrate CoinJoin detection
    print(f"\n🔄 CoinJoin Detection Example:")
    # Simulated CoinJoin transaction
    coinjoin_tx = {
        'hash': 'abc123coinjoin',
        'inputs': [f"1In{i}" for i in range(20)],  # 20 inputs
        'outputs': [
            {'address': f"1Out{i}", 'value': 0.1}  # Equal outputs
            for i in range(20)
        ],
        'total_input': 2.0,
        'fee': 0.001
    }

    cj_result = detector.detect_coinjoin(coinjoin_tx)
    print(f"  Is CoinJoin: {cj_result['is_coinjoin']}")
    print(f"  Type: {cj_result.get('coinjoin_type', 'Unknown')}")
    print(f"  Confidence: {cj_result['confidence']:.2f}")
    print(f"  Participants: {cj_result['num_participants']}")


def demo_exchange_identification():
    """Demonstrate exchange identification"""
    print_section("EXCHANGE IDENTIFICATION")

    identifier = ExchangeIdentifier()

    # Show database statistics
    stats = identifier.get_statistics()
    print(f"🏦 Exchange Database:")
    print(f"  Total exchanges: {stats['total_exchanges']}")
    print(f"  Known addresses: {stats['total_known_addresses']}")
    print(f"\n  By reputation:")
    for reputation, count in stats['by_reputation'].items():
        print(f"    {reputation}: {count}")

    # Search for specific exchange
    print(f"\n🔍 Searching for Coinbase:")
    results = identifier.search_exchanges("coinbase")
    for exchange in results:
        print(f"  {exchange['exchange_name']}")
        print(f"    ID: {exchange['exchange_id']}")
        print(f"    Reputation: {exchange['reputation']}")

    # Test exchange identification
    test_addresses = [
        "1ExchangeHotWallet123",
        "1ExchangeColdStorage456"
    ]

    print(f"\n🔎 Identifying exchanges:")
    interactions = identifier.identify_exchanges(test_addresses)

    for interaction in interactions:
        print(f"  • {interaction['address'][:20]}...")
        print(f"    Exchange: {interaction['exchange_name']}")
        print(f"    Type: {interaction['wallet_type']}")
        print(f"    Confidence: {interaction['confidence']:.2f}")


def demo_visualization():
    """Demonstrate cluster visualization"""
    print_section("CLUSTER VISUALIZATION")

    # Create sample cluster with clusterer
    clusterer = WalletClusterer()
    result = clusterer.analyze_wallet("1VisualizationTest123", depth=1)

    visualizer = ClusterVisualizer()

    print(f"Creating visualizations for cluster {result.cluster.cluster_id}")

    # Create visualization
    viz_data = visualizer.visualize_cluster(result.cluster, result.links)

    print(f"\n📊 Visualization Data:")
    print(f"  Nodes: {len(viz_data['nodes'])}")
    print(f"  Edges: {len(viz_data['edges'])}")
    print(f"  Graph density: {viz_data['graph_stats']['density']:.3f}")

    # Create risk heatmap
    heatmap = visualizer.create_risk_heatmap([result.cluster])

    print(f"\n🔥 Risk Heatmap:")
    print(f"  Risk distribution:")
    for level, count in heatmap['risk_distribution'].items():
        print(f"    {level}: {count}")

    # Export examples
    print(f"\n💾 Export Formats Available:")
    print(f"  • GraphML (for Gephi, Cytoscape)")
    print(f"  • D3.js JSON (for web visualization)")
    print(f"  • Standard JSON (for analysis)")

    # Demonstrate exports (commented out to avoid file creation)
    # visualizer.export_to_graphml(result.cluster, result.links, "cluster.graphml")
    # visualizer.export_to_d3(result.cluster, result.links, "cluster_d3.json")
    # visualizer.export_to_json(result.cluster, result.links, "cluster.json")

    print(f"  Export methods: export_to_graphml(), export_to_d3(), export_to_json()")


def demo_advanced_features():
    """Demonstrate advanced clustering features"""
    print_section("ADVANCED FEATURES")

    clusterer = WalletClusterer()

    # Create initial cluster
    result1 = clusterer.analyze_wallet("1AdvancedTest1", depth=1)
    cluster_id1 = result1.cluster.cluster_id

    print(f"🔧 Advanced Clustering Operations:")

    # Expand cluster
    print(f"\n1. Cluster Expansion:")
    print(f"  Original size: {len(result1.cluster.addresses)}")
    new_addresses = clusterer.expand_cluster(cluster_id1, depth=1)
    print(f"  New addresses added: {len(new_addresses)}")
    print(f"  New size: {len(clusterer.clusters[cluster_id1].addresses)}")

    # Get cluster summary
    print(f"\n2. Cluster Summary:")
    summary = clusterer.get_cluster_summary(cluster_id1)
    print(f"  Cluster ID: {summary['cluster_id']}")
    print(f"  Size: {summary['size']}")
    print(f"  Risk score: {summary['risk_score']:.2f}")
    print(f"  Total transactions: {summary['total_transactions']}")
    print(f"  Total volume: {summary['total_volume']:.4f} BTC")

    # Create second cluster for merging demo
    result2 = clusterer.analyze_wallet("1AdvancedTest2", depth=1)
    cluster_id2 = result2.cluster.cluster_id

    # Merge clusters
    print(f"\n3. Cluster Merging:")
    print(f"  Cluster 1 size: {len(clusterer.clusters[cluster_id1].addresses)}")
    print(f"  Cluster 2 size: {len(clusterer.clusters[cluster_id2].addresses)}")

    evidence = {
        'type': 'common_input',
        'transaction': 'tx_merge_evidence_123',
        'confidence': 0.9
    }

    merged_id = clusterer.merge_clusters(cluster_id1, cluster_id2, evidence)
    print(f"  Merged cluster ID: {merged_id}")
    print(f"  Merged size: {len(clusterer.clusters[merged_id].addresses)}")

    # Export all clusters
    print(f"\n4. Cluster Export:")
    export_file = "demo_clusters_export.json"
    clusterer.export_clusters(export_file)
    print(f"  Exported to: {export_file}")


def print_summary():
    """Print demonstration summary"""
    print_section("DEMONSTRATION SUMMARY")

    print("""
✅ Successfully demonstrated all wallet clustering components:

1. ✓ Basic Wallet Clustering - Multi-heuristic address grouping
2. ✓ Common Input Heuristic - Co-spending analysis
3. ✓ Change Address Detection - Multiple heuristics for change identification
4. ✓ Peel Chain Analysis - Money laundering pattern detection
5. ✓ Entity Attribution - Linking clusters to known entities
6. ✓ Mixing Service Detection - CoinJoin and tumbler identification
7. ✓ Exchange Identification - 50+ exchange signatures
8. ✓ Cluster Visualization - Graph creation and export
9. ✓ Advanced Features - Merging, expansion, and export

📚 Key Capabilities:
  • Multi-heuristic clustering with confidence scoring
  • Risk assessment and suspicious pattern detection
  • Entity attribution with extensive database
  • Privacy tool detection (CoinJoin, mixing, etc.)
  • Exchange and service identification
  • Graph visualization and multiple export formats
  • Production-ready architecture

🎯 Use Cases:
  • Cryptocurrency investigations
  • AML/KYC compliance
  • Blockchain forensics
  • Risk assessment
  • Entity attribution
  • Transaction flow analysis

⚠️  Note: This demonstration uses simulated blockchain data.
    For production use, integrate with real blockchain APIs.

📖 See README_WALLET_CLUSTERING.md for detailed documentation.
""")


def main():
    """Run complete demonstration"""
    print("\n" + "=" * 80)
    print("  CRYPTOCURRENCY WALLET CLUSTERING SYSTEM - DEMONSTRATION")
    print("  Advanced Blockchain Intelligence Platform")
    print("=" * 80)

    try:
        # Run all demos
        demo_basic_clustering()
        demo_common_input_heuristic()
        demo_change_detection()
        demo_peel_chain_analysis()
        demo_entity_attribution()
        demo_mixing_detection()
        demo_exchange_identification()
        demo_visualization()
        demo_advanced_features()

        # Print summary
        print_summary()

    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
