# Multi-Chain Transaction Tracing System

Comprehensive blockchain transaction tracing and analysis system with support for multiple blockchains, advanced graph algorithms, and taint analysis.

## Overview

The transaction tracing system provides sophisticated tools for:
- **Multi-hop transaction tracking** across multiple blockchains
- **Cross-chain transaction tracing** via bridges and atomic swaps
- **Fund flow visualization** with interactive graphs
- **Endpoint identification** (exchanges, mixers, merchants)
- **Taint analysis** using poison and haircut algorithms
- **Pattern detection** (layering, peeling, mixing)

## Architecture

```
transaction-tracing/
├── transaction_tracer.py      # Main tracing engine
├── bitcoin_tracer.py          # Bitcoin-specific UTXO tracing
├── ethereum_tracer.py         # Ethereum account-based tracing
├── cross_chain_tracer.py      # Cross-chain transaction detection
├── fund_flow_analyzer.py      # Fund flow pattern analysis
├── taint_analyzer.py          # Taint propagation analysis
├── endpoint_identifier.py     # Endpoint detection and classification
└── graph_generator.py         # Visualization generation
```

## Core Components

### 1. Transaction Tracer (transaction_tracer.py)

Main engine for multi-chain transaction tracing.

**Key Features:**
- Multi-hop BFS/DFS traversal
- Cross-chain transaction following
- Endpoint identification
- Risk score calculation
- Graph export (GEXF, GraphML, JSON)

**Example Usage:**

```python
from transaction_tracer import TransactionTracer

# Initialize tracer
tracer = TransactionTracer({
    'bitcoin_api': 'https://blockchain.info',
    'ethereum_api': 'https://api.etherscan.io'
})

# Trace funds from address
result = await tracer.trace_funds(
    address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    blockchain="bitcoin",
    max_hops=5,
    min_amount=0.1,
    direction='both',
    follow_cross_chain=True
)

# View results
print(f"Total hops: {result.total_hops}")
print(f"Total amount: {result.total_amount}")
print(f"Endpoints found: {len(result.endpoints)}")
print(f"Risk score: {result.risk_score:.2f}")

# Find path between addresses
paths = await tracer.find_path(
    source="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    destination="1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp",
    blockchain="bitcoin",
    max_hops=10
)

print(f"Found {len(paths)} paths")

# Export graph
graph_data = tracer.export_graph(result, format='json')
```

### 2. Bitcoin Tracer (bitcoin_tracer.py)

UTXO-based transaction tracing for Bitcoin.

**Key Features:**
- UTXO graph traversal
- Input/output analysis
- Multi-hop tracking (up to 10 hops)
- Change detection
- Address clustering
- Taint calculation

**Example Usage:**

```python
from bitcoin_tracer import BitcoinTracer

tracer = BitcoinTracer(api_key='YOUR_API_KEY', network='mainnet')

# Trace UTXO chain
utxo_graph = await tracer.trace_utxo_chain(
    tx_hash="a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
    output_index=0,
    max_hops=5,
    min_amount=0.01
)

print(f"UTXO Graph:")
print(f"  Nodes: {utxo_graph.graph.number_of_nodes()}")
print(f"  Edges: {utxo_graph.graph.number_of_edges()}")
print(f"  Addresses: {len(utxo_graph.addresses)}")

# Trace backward to find sources
trace = await tracer.trace_backward(tx_hash, max_depth=5)

# Analyze transaction pattern
pattern = await tracer.analyze_transaction_pattern(tx_hash)
print(f"Patterns detected: {pattern['patterns']}")

# Cluster addresses
cluster = await tracer.cluster_addresses("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
print(f"Clustered {len(cluster)} addresses")

# Calculate taint
taint = await tracer.calculate_taint(
    source_tx="tx_hash_1",
    source_output=0,
    target_tx="tx_hash_2",
    target_input=0,
    method='haircut'
)
print(f"Taint score: {taint:.2%}")
```

### 3. Ethereum Tracer (ethereum_tracer.py)

Account-based tracing for Ethereum and EVM chains.

**Key Features:**
- Transaction graph analysis
- Internal transaction tracking
- Token transfer tracking (ERC-20, ERC-721)
- Smart contract interaction analysis
- DEX trade detection
- Bridge transaction identification

**Example Usage:**

```python
from ethereum_tracer import EthereumTracer

tracer = EthereumTracer(api_key='YOUR_API_KEY', network='mainnet')

# Trace transaction graph
graph = await tracer.trace_transaction_graph(
    address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    max_hops=3,
    min_value=0.1,
    follow_contracts=True
)

print(f"Transaction graph:")
print(f"  Nodes: {graph.number_of_nodes()}")
print(f"  Edges: {graph.number_of_edges()}")

# Analyze contract interactions
analysis = await tracer.analyze_contract_interactions(
    address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    contract_address='0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'
)

print(f"Contract interactions: {analysis['total_interactions']}")
print(f"Total value: {analysis['total_value']}")

# Trace token flow
token_graph = await tracer.trace_token_flow(
    token_address='0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    from_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    max_hops=5
)

# Detect DEX trades
trades = await tracer.detect_dex_trades(tx_hash)
print(f"DEX trades: {len(trades)}")

# Find bridge transactions
bridges = await tracer.find_bridge_transactions(address)
print(f"Bridge transactions: {len(bridges)}")
```

### 4. Cross-Chain Tracer (cross_chain_tracer.py)

Detects and traces cross-chain transactions.

**Key Features:**
- Bridge transaction detection
- Atomic swap identification
- Cross-chain fund flow tracking
- Multi-chain correlation
- Wrapped token tracking

**Example Usage:**

```python
from cross_chain_tracer import CrossChainTracer

tracer = CrossChainTracer()

# Detect bridge transaction
cross_chain_tx = await tracer.detect_bridge_transaction(
    tx_hash="0x1234...",
    source_chain="ethereum"
)

if cross_chain_tx:
    print(f"Bridge detected: {cross_chain_tx.bridge_contract}")
    print(f"Destination chain: {cross_chain_tx.destination_chain}")
    print(f"Destination tx: {cross_chain_tx.destination_tx_hash}")

# Trace cross-chain flow
flow_graph = await tracer.trace_cross_chain_flow(
    start_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    start_chain='ethereum',
    max_hops=5
)

print(f"Cross-chain nodes: {flow_graph.number_of_nodes()}")

# Find atomic swaps
swaps = await tracer.find_atomic_swaps(
    address='bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
    chain_a='bitcoin',
    chain_b='ethereum',
    time_window=timedelta(hours=24)
)

print(f"Atomic swaps found: {len(swaps)}")

# Correlate addresses across chains
correlation = await tracer.correlate_addresses_cross_chain([
    ('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb', 'ethereum'),
    ('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', 'bitcoin')
])

print(f"Connections: {len(correlation['connections'])}")

# Track wrapped tokens
wrapped_analysis = await tracer.track_wrapped_tokens(
    original_chain='bitcoin',
    wrapped_chain='ethereum',
    token='BTC'
)

print(f"Total locked: {wrapped_analysis['total_locked']}")
print(f"Total minted: {wrapped_analysis['total_minted']}")
```

### 5. Fund Flow Analyzer (fund_flow_analyzer.py)

Advanced analysis of fund movement patterns.

**Key Features:**
- Source/destination identification
- Intermediate hop analysis
- Layering detection
- Integration point identification
- Pattern recognition (peeling, mixing, circular)
- Temporal analysis

**Example Usage:**

```python
from fund_flow_analyzer import FundFlowAnalyzer

analyzer = FundFlowAnalyzer()

# Analyze fund flow
analysis = await analyzer.analyze_flow(
    transaction_graph=graph,
    source_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    min_amount=0.1
)

print(f"Flow Analysis:")
print(f"  Total value: {analysis.total_value_flow}")
print(f"  Hops: {analysis.num_hops}")
print(f"  Patterns detected: {len(analysis.patterns_detected)}")
print(f"  Endpoints: {len(analysis.endpoints)}")
print(f"  Risk score: {analysis.risk_assessment['overall_score']:.2f}")

# Identify sources
sources = await analyzer.identify_source(graph, target_address)
for source in sources[:5]:
    print(f"  {source['address']}: {source['confidence']:.2%} confidence")

# Identify destinations
destinations = await analyzer.identify_destination(graph, source_address)
for dest in destinations[:5]:
    print(f"  {dest['address']}: {dest['total_flow']} ({dest['entity_type']})")

# Detect layering
layering = await analyzer.detect_layering(graph, min_layers=3)
print(f"Layering patterns: {len(layering)}")

# Detect peeling chains
peeling = await analyzer.detect_peeling_chain(graph, min_peels=3)
print(f"Peeling chains: {len(peeling)}")

# Detect mixing
mixing = await analyzer.detect_mixing(graph)
print(f"Mixing patterns: {len(mixing)}")

# Detect circular flows
circular = await analyzer.detect_circular_flow(graph)
print(f"Circular flows: {len(circular)}")
```

### 6. Taint Analyzer (taint_analyzer.py)

Advanced taint tracking and propagation analysis.

**Key Features:**
- Poison algorithm (binary taint)
- Haircut algorithm (proportional taint)
- FIFO/LIFO tracking
- Multi-source taint tracking
- Taint propagation analysis
- Risk categorization

**Example Usage:**

```python
from taint_analyzer import TaintAnalyzer, TaintSource, TaintMethod

# Create analyzer
analyzer = TaintAnalyzer(method=TaintMethod.HAIRCUT)

# Add taint sources
analyzer.add_taint_source(
    address="0x123...",
    taint_type=TaintSource.HACK,
    amount=100.0,
    confidence=0.95
)

analyzer.add_taint_source(
    address="0x456...",
    taint_type=TaintSource.RANSOMWARE,
    amount=50.0,
    confidence=0.90
)

# Analyze taint for address
taint_score = await analyzer.analyze(
    address="0x789...",
    transaction_graph=graph,
    method=TaintMethod.HAIRCUT
)

print(f"Taint Analysis:")
print(f"  Total taint: {taint_score.total_taint:.2%}")
print(f"  Tainted amount: {taint_score.tainted_amount:.2f}")
print(f"  Clean amount: {taint_score.clean_amount:.2f}")
print(f"  Risk category: {analyzer.get_risk_category(taint_score)}")
print(f"  Taint sources: {taint_score.taint_sources}")

# Trace taint propagation
paths = await analyzer.trace_taint_propagation(
    source_address="0x123...",
    graph=graph,
    max_hops=10,
    min_taint=0.01
)

print(f"\nTaint propagation paths: {len(paths)}")
for path in paths[:5]:
    print(f"  {' -> '.join(path.path)}")
    print(f"    Final taint: {path.final_taint:.2%}")
    print(f"    Dilution: {path.taint_dilution:.2%}")

# Compare methods
comparison = analyzer.compare_methods(address, graph)
print(f"\nMethod comparison:")
for method, score in comparison.items():
    print(f"  {method.value}: {score.total_taint:.2%}")
```

### 7. Endpoint Identifier (endpoint_identifier.py)

Identifies and classifies transaction endpoints.

**Key Features:**
- Exchange deposit detection
- Merchant payment identification
- P2P transaction detection
- Terminal address identification
- Pattern-based classification
- Risk assessment

**Example Usage:**

```python
from endpoint_identifier import EndpointIdentifier

identifier = EndpointIdentifier()

# Identify single endpoint
endpoint = await identifier.identify(
    address='0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE',
    blockchain='ethereum',
    transaction_data={
        'transaction_count': 10000,
        'in_degree': 5000,
        'out_degree': 2000,
        'unique_senders': 3000
    }
)

if endpoint:
    print(f"Endpoint identified:")
    print(f"  Type: {endpoint.endpoint_type.value}")
    print(f"  Name: {endpoint.name or 'Unknown'}")
    print(f"  Confidence: {endpoint.confidence:.2%}")
    print(f"  Risk level: {endpoint.risk_level}")

# Batch identify
addresses = [
    ('0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE', 'ethereum'),
    ('0x71660c4005BA85c37ccec55d0C4493E66Fe775d3', 'ethereum'),
]

endpoints = await identifier.batch_identify(addresses, graph=transaction_graph)
print(f"Identified {len(endpoints)} endpoints")

# Find all exchanges
exchanges = await identifier.find_exchanges(graph)
print(f"Exchanges found: {len(exchanges)}")

# Find terminal addresses
terminals = await identifier.find_terminal_addresses(graph)
print(f"Terminal addresses: {len(terminals)}")

# Get summary
summary = identifier.get_endpoint_summary(endpoints)
print(f"\nEndpoint summary:")
print(f"  Total: {summary['total_endpoints']}")
print(f"  By type: {summary['by_type']}")
print(f"  By risk: {summary['by_risk']}")
```

### 8. Graph Generator (graph_generator.py)

Generates visualizations of transaction flows.

**Key Features:**
- Transaction graph generation
- Sankey diagrams
- Interactive flow charts
- Export to Gephi/Cytoscape
- HTML visualizations
- Timeline charts

**Example Usage:**

```python
from graph_generator import GraphGenerator

generator = GraphGenerator({
    'node_size_scale': 100,
    'edge_width_scale': 5,
    'layout': 'hierarchical'
})

# Generate transaction graph
viz_data = generator.generate_transaction_graph(
    graph=transaction_graph,
    title="Bitcoin Transaction Flow",
    include_metadata=True
)

print(f"Graph generated:")
print(f"  Nodes: {viz_data['statistics']['node_count']}")
print(f"  Edges: {viz_data['statistics']['edge_count']}")

# Generate Sankey diagram
sankey = generator.generate_sankey_diagram(
    graph=transaction_graph,
    source_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    max_depth=3
)

print(f"Sankey: {len(sankey['nodes'])} nodes, {len(sankey['links'])} links")

# Generate timeline
timeline = generator.generate_flow_timeline(
    graph=transaction_graph,
    time_intervals=10
)

print(f"Timeline: {timeline['total_transactions']} transactions")

# Export to various formats
generator.export_to_gephi(transaction_graph, 'output.gexf')
generator.export_to_cytoscape(transaction_graph, 'output_cyto.json')
generator.export_to_d3(transaction_graph, 'output_d3.json')

# Generate interactive HTML
generator.generate_html_visualization(
    graph=transaction_graph,
    output_path='transaction_flow.html',
    title='Interactive Transaction Flow'
)

print("Visualizations generated!")
```

## Advanced Use Cases

### Complete Investigation Workflow

```python
import asyncio
from transaction_tracer import TransactionTracer
from fund_flow_analyzer import FundFlowAnalyzer
from taint_analyzer import TaintAnalyzer, TaintSource
from endpoint_identifier import EndpointIdentifier
from graph_generator import GraphGenerator

async def investigate_address(address: str, blockchain: str):
    """Complete investigation workflow"""

    # Initialize components
    tracer = TransactionTracer()
    flow_analyzer = FundFlowAnalyzer()
    taint_analyzer = TaintAnalyzer()
    endpoint_identifier = EndpointIdentifier()
    graph_generator = GraphGenerator()

    # Step 1: Trace transactions
    print(f"[1/5] Tracing transactions from {address}...")
    trace_result = await tracer.trace_funds(
        address=address,
        blockchain=blockchain,
        max_hops=5,
        min_amount=0.1
    )

    print(f"  Found {trace_result.total_hops} hops")
    print(f"  Total flow: {trace_result.total_amount}")

    # Step 2: Analyze fund flow
    print(f"[2/5] Analyzing fund flow patterns...")
    flow_analysis = await flow_analyzer.analyze_flow(
        transaction_graph=trace_result.transaction_graph,
        source_address=address
    )

    print(f"  Patterns detected: {len(flow_analysis.patterns_detected)}")
    print(f"  Endpoints: {len(flow_analysis.endpoints)}")

    # Step 3: Taint analysis
    print(f"[3/5] Performing taint analysis...")
    # Add known tainted sources
    for endpoint in flow_analysis.endpoints:
        if endpoint.get('type') == 'mixer':
            taint_analyzer.add_taint_source(
                endpoint['address'],
                TaintSource.MIXER,
                endpoint['amount']
            )

    taint_score = await taint_analyzer.analyze(
        address=address,
        transaction_graph=trace_result.transaction_graph
    )

    print(f"  Taint score: {taint_score.total_taint:.2%}")
    print(f"  Risk category: {taint_analyzer.get_risk_category(taint_score)}")

    # Step 4: Identify endpoints
    print(f"[4/5] Identifying endpoints...")
    endpoints = await endpoint_identifier.find_terminal_addresses(
        trace_result.transaction_graph
    )

    summary = endpoint_identifier.get_endpoint_summary(endpoints)
    print(f"  Terminal addresses: {summary['total_endpoints']}")
    print(f"  By type: {summary['by_type']}")

    # Step 5: Generate visualizations
    print(f"[5/5] Generating visualizations...")
    graph_generator.generate_html_visualization(
        graph=trace_result.transaction_graph,
        output_path=f'investigation_{address[:8]}.html',
        title=f'Investigation: {address}'
    )

    graph_generator.export_to_gephi(
        trace_result.transaction_graph,
        f'investigation_{address[:8]}.gexf'
    )

    # Generate report
    report = {
        'address': address,
        'blockchain': blockchain,
        'trace_summary': {
            'hops': trace_result.total_hops,
            'total_flow': trace_result.total_amount,
            'unique_addresses': trace_result.metadata['visited_addresses']
        },
        'flow_analysis': {
            'patterns': [p['pattern_type'] for p in flow_analysis.patterns_detected],
            'risk_score': flow_analysis.risk_assessment['overall_score']
        },
        'taint_analysis': {
            'taint_score': taint_score.total_taint,
            'sources': list(taint_score.taint_sources.keys()),
            'risk_category': taint_analyzer.get_risk_category(taint_score)
        },
        'endpoints': summary
    }

    print("\n=== Investigation Report ===")
    print(json.dumps(report, indent=2, default=str))

    return report

# Run investigation
asyncio.run(investigate_address(
    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "ethereum"
))
```

## Configuration

### API Keys

```python
config = {
    # Bitcoin
    'bitcoin_api': 'https://blockchain.info/api',
    'bitcoin_api_key': 'YOUR_KEY',

    # Ethereum
    'ethereum_api': 'https://api.etherscan.io/api',
    'ethereum_api_key': 'YOUR_KEY',

    # Other chains
    'polygon_api_key': 'YOUR_KEY',
    'bsc_api_key': 'YOUR_KEY',
    'avalanche_api_key': 'YOUR_KEY',
}
```

### Tracing Parameters

```python
tracing_params = {
    'max_hops': 10,              # Maximum hops to trace
    'min_amount': 0.1,           # Minimum transaction amount
    'direction': 'both',         # 'forward', 'backward', or 'both'
    'follow_cross_chain': True,  # Follow cross-chain transactions
    'include_taint': True,       # Include taint analysis
    'cache_enabled': True,       # Enable caching
}
```

## Performance Considerations

### Caching

All tracers implement caching to improve performance:

```python
# Clear caches when needed
tracer.tx_cache.clear()
taint_analyzer.clear_cache()
```

### Rate Limiting

Implement rate limiting for API calls:

```python
import asyncio

async def rate_limited_call(func, *args, delay=0.1):
    result = await func(*args)
    await asyncio.sleep(delay)
    return result
```

### Parallel Processing

Process multiple addresses in parallel:

```python
async def trace_multiple(addresses):
    tasks = [tracer.trace_funds(addr, 'bitcoin') for addr in addresses]
    results = await asyncio.gather(*tasks)
    return results
```

## Best Practices

1. **Always set reasonable limits** on max_hops and min_amount
2. **Use caching** for repeated queries
3. **Implement rate limiting** to avoid API throttling
4. **Validate addresses** before tracing
5. **Handle errors gracefully** with try/except blocks
6. **Monitor memory usage** for large graphs
7. **Export large graphs** rather than keeping in memory

## Troubleshooting

### Common Issues

**Issue:** Trace returns empty results
- Check API keys are valid
- Verify address format is correct
- Ensure minimum amount threshold isn't too high

**Issue:** Memory errors with large traces
- Reduce max_hops parameter
- Increase min_amount threshold
- Process in batches

**Issue:** Slow performance
- Enable caching
- Reduce max_hops
- Use parallel processing

## License

Proprietary - Apollo Intelligence System

## Support

For issues and questions, contact the development team.

---

**Last Updated:** 2026-01-14
**Version:** 1.0.0
**Agent:** Agent 18 - Multi-Chain Transaction Tracing
