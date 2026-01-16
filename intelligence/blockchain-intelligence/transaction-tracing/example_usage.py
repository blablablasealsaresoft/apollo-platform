"""
Example Usage of Multi-Chain Transaction Tracing System

This script demonstrates all major features of the transaction tracing system.
"""

import asyncio
import logging
from datetime import datetime, timedelta
import networkx as nx

# Import all components
from transaction_tracer import TransactionTracer, BlockchainType
from bitcoin_tracer import BitcoinTracer
from ethereum_tracer import EthereumTracer
from cross_chain_tracer import CrossChainTracer
from fund_flow_analyzer import FundFlowAnalyzer, EntityType
from taint_analyzer import TaintAnalyzer, TaintMethod, TaintSource
from endpoint_identifier import EndpointIdentifier, EndpointType
from graph_generator import GraphGenerator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def example_1_basic_tracing():
    """Example 1: Basic transaction tracing"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Transaction Tracing")
    print("="*60)

    tracer = TransactionTracer({
        'bitcoin_api': 'https://blockchain.info',
        'ethereum_api': 'https://api.etherscan.io'
    })

    # Trace Bitcoin address
    result = await tracer.trace_funds(
        address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        blockchain="bitcoin",
        max_hops=5,
        min_amount=0.1,
        direction='both'
    )

    print(f"\nTrace Results:")
    print(f"  Source: {result.source_address}")
    print(f"  Blockchain: {result.blockchain.value}")
    print(f"  Total hops: {result.total_hops}")
    print(f"  Total amount: {result.total_amount:.4f} BTC")
    print(f"  Unique addresses: {result.metadata['visited_addresses']}")
    print(f"  Endpoints found: {len(result.endpoints)}")
    print(f"  Risk score: {result.risk_score:.2f}")

    # Show endpoints
    print(f"\nEndpoints:")
    for endpoint in result.endpoints[:5]:
        print(f"  - {endpoint['address'][:16]}... ({endpoint['type']})")


async def example_2_bitcoin_utxo_tracing():
    """Example 2: Bitcoin UTXO chain tracing"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Bitcoin UTXO Chain Tracing")
    print("="*60)

    tracer = BitcoinTracer(network='mainnet')

    # Trace UTXO chain
    utxo_graph = await tracer.trace_utxo_chain(
        tx_hash="a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
        output_index=0,
        max_hops=5,
        min_amount=0.01
    )

    print(f"\nUTXO Graph:")
    print(f"  Nodes: {utxo_graph.graph.number_of_nodes()}")
    print(f"  Edges: {utxo_graph.graph.number_of_edges()}")
    print(f"  Unique addresses: {len(utxo_graph.addresses)}")
    print(f"  UTXOs tracked: {len(utxo_graph.utxos)}")

    # Cluster addresses
    cluster = await tracer.cluster_addresses("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print(f"\nAddress Clustering:")
    print(f"  Clustered addresses: {len(cluster)}")
    print(f"  Sample addresses: {list(cluster)[:3]}")


async def example_3_ethereum_tracing():
    """Example 3: Ethereum transaction tracing"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Ethereum Transaction Tracing")
    print("="*60)

    tracer = EthereumTracer(api_key='YOUR_API_KEY', network='mainnet')

    # Trace transaction graph
    graph = await tracer.trace_transaction_graph(
        address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        max_hops=3,
        min_value=0.1,
        follow_contracts=True
    )

    print(f"\nTransaction Graph:")
    print(f"  Nodes: {graph.number_of_nodes()}")
    print(f"  Edges: {graph.number_of_edges()}")

    # Analyze contract interactions
    contract_address = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'  # Uniswap V2
    analysis = await tracer.analyze_contract_interactions(
        address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        contract_address=contract_address
    )

    print(f"\nContract Interactions:")
    print(f"  Contract: {analysis['contract'].name if analysis['contract'] else 'Unknown'}")
    print(f"  Total interactions: {analysis['total_interactions']}")
    print(f"  Total value: {analysis['total_value']:.4f} ETH")


async def example_4_cross_chain_tracing():
    """Example 4: Cross-chain transaction tracing"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Cross-Chain Transaction Tracing")
    print("="*60)

    tracer = CrossChainTracer()

    # Trace cross-chain flow
    flow_graph = await tracer.trace_cross_chain_flow(
        start_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        start_chain='ethereum',
        max_hops=3
    )

    print(f"\nCross-Chain Flow:")
    print(f"  Total nodes: {flow_graph.number_of_nodes()}")
    print(f"  Total edges: {flow_graph.number_of_edges()}")

    # Count cross-chain hops
    cross_chain_edges = sum(
        1 for _, _, data in flow_graph.edges(data=True)
        if data.get('is_cross_chain', False)
    )
    print(f"  Cross-chain hops: {cross_chain_edges}")

    # Find atomic swaps
    swaps = await tracer.find_atomic_swaps(
        address='bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
        chain_a='bitcoin',
        chain_b='ethereum',
        time_window=timedelta(hours=24)
    )

    print(f"\nAtomic Swaps:")
    print(f"  Found: {len(swaps)}")


async def example_5_fund_flow_analysis():
    """Example 5: Fund flow pattern analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Fund Flow Pattern Analysis")
    print("="*60)

    analyzer = FundFlowAnalyzer()

    # Create sample graph for demonstration
    graph = nx.DiGraph()
    graph.add_edge('A', 'B', amount=100.0, timestamp=datetime.now())
    graph.add_edge('B', 'C', amount=50.0, timestamp=datetime.now())
    graph.add_edge('B', 'D', amount=50.0, timestamp=datetime.now())
    graph.add_edge('C', 'E', amount=25.0, timestamp=datetime.now())
    graph.add_edge('C', 'F', amount=25.0, timestamp=datetime.now())
    graph.add_edge('D', 'G', amount=50.0, timestamp=datetime.now())

    # Analyze flow
    analysis = await analyzer.analyze_flow(
        transaction_graph=graph,
        source_address='A',
        min_amount=1.0
    )

    print(f"\nFlow Analysis:")
    print(f"  Total value flow: {analysis.total_value_flow:.2f}")
    print(f"  Number of hops: {analysis.num_hops}")
    print(f"  Unique addresses: {analysis.num_unique_addresses}")
    print(f"  Patterns detected: {len(analysis.patterns_detected)}")
    print(f"  Endpoints: {len(analysis.endpoints)}")
    print(f"  Risk score: {analysis.risk_assessment['overall_score']:.2f}")

    # Detect specific patterns
    layering = await analyzer.detect_layering(graph, min_layers=2)
    print(f"\nPattern Detection:")
    print(f"  Layering patterns: {len(layering)}")

    mixing = await analyzer.detect_mixing(graph)
    print(f"  Mixing patterns: {len(mixing)}")


async def example_6_taint_analysis():
    """Example 6: Taint analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Taint Analysis")
    print("="*60)

    analyzer = TaintAnalyzer(method=TaintMethod.HAIRCUT)

    # Create sample graph
    graph = nx.DiGraph()
    graph.add_edge('source', 'intermediate1', amount=50.0)
    graph.add_edge('source', 'intermediate2', amount=50.0)
    graph.add_edge('intermediate1', 'target', amount=30.0)
    graph.add_edge('intermediate2', 'target', amount=40.0)

    # Add taint source
    analyzer.add_taint_source(
        address='source',
        taint_type=TaintSource.HACK,
        amount=100.0,
        confidence=0.95
    )

    # Analyze taint
    taint_score = await analyzer.analyze('target', graph)

    print(f"\nTaint Analysis for 'target':")
    print(f"  Total taint: {taint_score.total_taint:.2%}")
    print(f"  Tainted amount: {taint_score.tainted_amount:.2f}")
    print(f"  Clean amount: {taint_score.clean_amount:.2f}")
    print(f"  Risk category: {analyzer.get_risk_category(taint_score)}")
    print(f"  Method: {taint_score.calculation_method.value}")
    print(f"  Confidence: {taint_score.confidence:.2%}")

    # Trace propagation
    paths = await analyzer.trace_taint_propagation('source', graph, max_hops=5)
    print(f"\nTaint Propagation:")
    print(f"  Paths found: {len(paths)}")
    for i, path in enumerate(paths[:3], 1):
        print(f"  Path {i}: {' -> '.join(path.path)}")
        print(f"    Final taint: {path.final_taint:.2%}")

    # Compare methods
    comparison = analyzer.compare_methods('target', graph)
    print(f"\nMethod Comparison:")
    for method, score in comparison.items():
        print(f"  {method.value}: {score.total_taint:.2%}")


async def example_7_endpoint_identification():
    """Example 7: Endpoint identification"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Endpoint Identification")
    print("="*60)

    identifier = EndpointIdentifier()

    # Create sample graph simulating exchange
    graph = nx.DiGraph()
    exchange_addr = "exchange_address"

    # Many deposits (inputs)
    for i in range(100):
        graph.add_edge(f"user_{i}", exchange_addr, amount=1.5)

    # Few withdrawals (outputs)
    for i in range(5):
        graph.add_edge(exchange_addr, f"withdrawal_{i}", amount=20.0)

    # Find exchanges
    exchanges = await identifier.find_exchanges(graph)

    print(f"\nExchange Detection:")
    print(f"  Exchanges found: {len(exchanges)}")
    for exchange in exchanges[:3]:
        print(f"  - {exchange.address}")
        print(f"    Confidence: {exchange.confidence:.2%}")
        print(f"    Type: {exchange.endpoint_type.value}")

    # Find terminal addresses
    terminals = await identifier.find_terminal_addresses(graph)
    print(f"\nTerminal Addresses:")
    print(f"  Found: {len(terminals)}")

    # Get summary
    all_endpoints = exchanges + terminals
    summary = identifier.get_endpoint_summary(all_endpoints)
    print(f"\nEndpoint Summary:")
    print(f"  Total endpoints: {summary['total_endpoints']}")
    print(f"  By type: {summary['by_type']}")
    print(f"  By risk: {summary['by_risk']}")


async def example_8_visualization():
    """Example 8: Graph visualization"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Graph Visualization")
    print("="*60)

    generator = GraphGenerator({
        'layout': 'hierarchical',
        'node_size_scale': 100,
        'edge_width_scale': 5
    })

    # Create sample graph
    graph = nx.DiGraph()
    graph.add_edge('A', 'B', amount=10.0, timestamp=datetime.now())
    graph.add_edge('B', 'C', amount=5.0, timestamp=datetime.now())
    graph.add_edge('B', 'D', amount=5.0, timestamp=datetime.now())
    graph.add_edge('C', 'E', amount=3.0, timestamp=datetime.now())

    # Set node types
    graph.nodes['A']['type'] = 'address'
    graph.nodes['B']['type'] = 'exchange'
    graph.nodes['C']['type'] = 'address'
    graph.nodes['D']['type'] = 'mixer'
    graph.nodes['E']['type'] = 'address'

    # Generate transaction graph
    viz_data = generator.generate_transaction_graph(
        graph=graph,
        title="Sample Transaction Flow",
        include_metadata=True
    )

    print(f"\nVisualization Data:")
    print(f"  Nodes: {viz_data['statistics']['node_count']}")
    print(f"  Edges: {viz_data['statistics']['edge_count']}")
    print(f"  Density: {viz_data['statistics']['density']:.4f}")

    # Generate Sankey diagram
    sankey = generator.generate_sankey_diagram(graph, 'A', max_depth=3)
    print(f"\nSankey Diagram:")
    print(f"  Nodes: {len(sankey['nodes'])}")
    print(f"  Links: {len(sankey['links'])}")
    print(f"  Depth: {sankey['depth']}")

    # Export to various formats
    print(f"\nExporting graphs...")
    generator.export_to_gephi(graph, 'sample_graph.gexf')
    print(f"  ✓ Gephi format: sample_graph.gexf")

    generator.export_to_cytoscape(graph, 'sample_graph_cyto.json')
    print(f"  ✓ Cytoscape format: sample_graph_cyto.json")

    generator.export_to_d3(graph, 'sample_graph_d3.json')
    print(f"  ✓ D3 format: sample_graph_d3.json")

    generator.generate_html_visualization(
        graph,
        'sample_graph.html',
        'Sample Transaction Flow'
    )
    print(f"  ✓ HTML visualization: sample_graph.html")


async def example_9_complete_investigation():
    """Example 9: Complete investigation workflow"""
    print("\n" + "="*60)
    print("EXAMPLE 9: Complete Investigation Workflow")
    print("="*60)

    # Initialize all components
    tracer = TransactionTracer()
    flow_analyzer = FundFlowAnalyzer()
    taint_analyzer = TaintAnalyzer()
    endpoint_identifier = EndpointIdentifier()
    graph_generator = GraphGenerator()

    # Create sample graph for demo
    graph = nx.DiGraph()
    graph.add_edge('source', 'hop1', amount=100.0, timestamp=datetime.now())
    graph.add_edge('hop1', 'hop2', amount=90.0, timestamp=datetime.now())
    graph.add_edge('hop2', 'exchange', amount=80.0, timestamp=datetime.now())
    graph.add_edge('hop2', 'mixer', amount=10.0, timestamp=datetime.now())

    print("\n[1/5] Analyzing fund flow...")
    flow_analysis = await flow_analyzer.analyze_flow(graph, 'source')
    print(f"  ✓ Total flow: {flow_analysis.total_value_flow:.2f}")
    print(f"  ✓ Patterns: {len(flow_analysis.patterns_detected)}")

    print("\n[2/5] Performing taint analysis...")
    taint_analyzer.add_taint_source('source', TaintSource.HACK, 100.0)
    taint_score = await taint_analyzer.analyze('exchange', graph)
    print(f"  ✓ Taint score: {taint_score.total_taint:.2%}")
    print(f"  ✓ Risk: {taint_analyzer.get_risk_category(taint_score)}")

    print("\n[3/5] Identifying endpoints...")
    endpoints = await endpoint_identifier.find_terminal_addresses(graph)
    print(f"  ✓ Endpoints found: {len(endpoints)}")

    print("\n[4/5] Generating visualizations...")
    graph_generator.generate_html_visualization(
        graph,
        'investigation_report.html',
        'Investigation Report'
    )
    print(f"  ✓ HTML report generated")

    print("\n[5/5] Generating summary...")
    summary = {
        'total_flow': flow_analysis.total_value_flow,
        'hops': flow_analysis.num_hops,
        'risk_score': flow_analysis.risk_assessment['overall_score'],
        'taint_score': taint_score.total_taint,
        'endpoints': len(endpoints)
    }

    print(f"\nInvestigation Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")


async def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("MULTI-CHAIN TRANSACTION TRACING SYSTEM - EXAMPLES")
    print("="*60)

    examples = [
        example_1_basic_tracing,
        example_2_bitcoin_utxo_tracing,
        example_3_ethereum_tracing,
        example_4_cross_chain_tracing,
        example_5_fund_flow_analysis,
        example_6_taint_analysis,
        example_7_endpoint_identification,
        example_8_visualization,
        example_9_complete_investigation,
    ]

    for example in examples:
        try:
            await example()
        except Exception as e:
            print(f"\nError in {example.__name__}: {e}")

    print("\n" + "="*60)
    print("ALL EXAMPLES COMPLETED")
    print("="*60)


if __name__ == "__main__":
    asyncio.run(main())
