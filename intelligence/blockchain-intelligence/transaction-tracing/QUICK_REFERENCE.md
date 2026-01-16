# Transaction Tracing - Quick Reference Guide

## Installation

```python
# Import the main components
from transaction_tracing import (
    TransactionTracer,
    BitcoinTracer,
    EthereumTracer,
    CrossChainTracer,
    FundFlowAnalyzer,
    TaintAnalyzer,
    EndpointIdentifier,
    GraphGenerator
)
```

## Quick Start Examples

### 1. Trace Bitcoin Transaction (5 lines)

```python
tracer = TransactionTracer()
result = await tracer.trace_funds("1A1zP1eP...", "bitcoin", max_hops=5)
print(f"Found {result.total_hops} hops, {len(result.endpoints)} endpoints")
print(f"Risk score: {result.risk_score:.2f}")
```

### 2. Trace Ethereum Address (5 lines)

```python
tracer = EthereumTracer(api_key='YOUR_KEY')
graph = await tracer.trace_transaction_graph("0x742d35...", max_hops=3)
print(f"Nodes: {graph.number_of_nodes()}, Edges: {graph.number_of_edges()}")
```

### 3. Analyze Taint (6 lines)

```python
analyzer = TaintAnalyzer()
analyzer.add_taint_source("source_addr", TaintSource.HACK, 100.0)
taint = await analyzer.analyze("target_addr", graph)
print(f"Taint: {taint.total_taint:.2%}")
print(f"Risk: {analyzer.get_risk_category(taint)}")
```

### 4. Find Endpoints (4 lines)

```python
identifier = EndpointIdentifier()
endpoints = await identifier.find_terminal_addresses(graph)
summary = identifier.get_endpoint_summary(endpoints)
print(f"Endpoints by type: {summary['by_type']}")
```

### 5. Generate Visualization (3 lines)

```python
generator = GraphGenerator()
generator.generate_html_visualization(graph, 'output.html', 'My Graph')
print("Visualization generated!")
```

## Common Patterns

### Complete Investigation

```python
async def investigate(address, blockchain):
    # 1. Trace
    tracer = TransactionTracer()
    result = await tracer.trace_funds(address, blockchain, max_hops=5)

    # 2. Analyze
    analyzer = FundFlowAnalyzer()
    flow = await analyzer.analyze_flow(result.transaction_graph, address)

    # 3. Taint
    taint_analyzer = TaintAnalyzer()
    taint = await taint_analyzer.analyze(address, result.transaction_graph)

    # 4. Visualize
    generator = GraphGenerator()
    generator.generate_html_visualization(
        result.transaction_graph,
        f'{address}_report.html'
    )

    return {
        'hops': result.total_hops,
        'flow': flow.total_value_flow,
        'taint': taint.total_taint,
        'risk': result.risk_score
    }
```

### Find Path Between Addresses

```python
tracer = TransactionTracer()
paths = await tracer.find_path(
    source="source_address",
    destination="dest_address",
    blockchain="bitcoin",
    max_hops=10
)

for i, path in enumerate(paths, 1):
    print(f"Path {i}: {len(path)} hops")
```

### Detect Mixers

```python
analyzer = FundFlowAnalyzer()
mixing = await analyzer.detect_mixing(graph)

for mixer in mixing:
    print(f"Mixer: {mixer['mixer_address']}")
    print(f"  Inputs: {mixer['num_inputs']}")
    print(f"  Outputs: {mixer['num_outputs']}")
```

### Cross-Chain Trace

```python
tracer = CrossChainTracer()
flow = await tracer.trace_cross_chain_flow(
    start_address='0x742d35...',
    start_chain='ethereum',
    max_hops=5
)

cross_chain_hops = sum(
    1 for _, _, d in flow.edges(data=True)
    if d.get('is_cross_chain')
)
print(f"Cross-chain hops: {cross_chain_hops}")
```

## Configuration Cheat Sheet

### API Setup

```python
config = {
    'bitcoin_api': 'https://blockchain.info/api',
    'bitcoin_api_key': 'YOUR_KEY',
    'ethereum_api': 'https://api.etherscan.io/api',
    'ethereum_api_key': 'YOUR_KEY',
}
tracer = TransactionTracer(config)
```

### Tracing Options

```python
result = await tracer.trace_funds(
    address="...",
    blockchain="bitcoin",
    max_hops=5,              # Maximum hops to trace
    min_amount=0.1,          # Minimum tx amount
    direction='both',        # 'forward', 'backward', or 'both'
    follow_cross_chain=True, # Follow bridges
    include_taint=True       # Include taint analysis
)
```

### Taint Methods

```python
# Poison (binary)
taint = await analyzer.analyze(addr, graph, TaintMethod.POISON)

# Haircut (proportional)
taint = await analyzer.analyze(addr, graph, TaintMethod.HAIRCUT)

# FIFO
taint = await analyzer.analyze(addr, graph, TaintMethod.FIFO)

# LIFO
taint = await analyzer.analyze(addr, graph, TaintMethod.LIFO)
```

### Export Formats

```python
generator = GraphGenerator()

# Gephi
generator.export_to_gephi(graph, 'output.gexf')

# Cytoscape
generator.export_to_cytoscape(graph, 'output.json')

# D3.js
generator.export_to_d3(graph, 'output.json')

# HTML Interactive
generator.generate_html_visualization(graph, 'output.html')
```

## Pattern Detection Quick Reference

```python
analyzer = FundFlowAnalyzer()

# Layering (multiple hops to obscure)
layering = await analyzer.detect_layering(graph, min_layers=3)

# Peeling (sequential small sends)
peeling = await analyzer.detect_peeling_chain(graph, min_peels=3)

# Mixing (many-to-many)
mixing = await analyzer.detect_mixing(graph)

# Circular (round-tripping)
circular = await analyzer.detect_circular_flow(graph)
```

## Endpoint Types

```python
EndpointType.EXCHANGE        # Cryptocurrency exchange
EndpointType.MIXER          # Mixing service
EndpointType.MERCHANT       # Merchant payment
EndpointType.GAMBLING       # Gambling site
EndpointType.DARKNET        # Darknet market
EndpointType.P2P            # Peer-to-peer
EndpointType.DEFI_PROTOCOL  # DeFi protocol
EndpointType.BRIDGE         # Cross-chain bridge
EndpointType.TERMINAL       # Dead-end address
```

## Taint Sources

```python
TaintSource.THEFT       # Stolen funds
TaintSource.RANSOMWARE  # Ransomware payment
TaintSource.DARKNET     # Darknet market
TaintSource.SANCTIONED  # Sanctioned entity
TaintSource.MIXER       # Mixer output
TaintSource.SCAM        # Scam/fraud
TaintSource.HACK        # Hacked funds
TaintSource.TERRORIST   # Terrorist financing
```

## Performance Tips

### Use Caching

```python
# Caches are automatic, clear when needed
tracer.tx_cache.clear()
taint_analyzer.clear_cache()
```

### Limit Scope

```python
# Reduce max_hops for faster results
result = await tracer.trace_funds(address, "bitcoin", max_hops=3)

# Increase min_amount to filter small transactions
result = await tracer.trace_funds(address, "bitcoin", min_amount=1.0)
```

### Parallel Processing

```python
# Trace multiple addresses in parallel
addresses = ['addr1', 'addr2', 'addr3']
tasks = [tracer.trace_funds(addr, 'bitcoin') for addr in addresses]
results = await asyncio.gather(*tasks)
```

## Error Handling

```python
try:
    result = await tracer.trace_funds(address, blockchain)
except ValueError as e:
    print(f"Invalid input: {e}")
except ConnectionError as e:
    print(f"API error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Statistics

```python
# Get component statistics
tracer_stats = tracer.get_statistics()
print(f"Total traces: {tracer_stats['total_traces']}")

flow_stats = flow_analyzer.get_statistics()
print(f"Analyses: {flow_stats['analyses_performed']}")

taint_stats = taint_analyzer.get_statistics()
print(f"Addresses analyzed: {taint_stats['addresses_analyzed']}")

endpoint_stats = endpoint_identifier.get_statistics()
print(f"Endpoints found: {endpoint_stats['identifications']}")
```

## Common Use Cases

### 1. Investigate Suspicious Address

```python
result = await tracer.trace_funds(suspicious_addr, "bitcoin", max_hops=5)
if result.risk_score > 0.7:
    print("HIGH RISK")
```

### 2. Track Stolen Funds

```python
analyzer = TaintAnalyzer()
analyzer.add_taint_source(theft_addr, TaintSource.THEFT, 1000.0)
paths = await analyzer.trace_taint_propagation(theft_addr, graph)
```

### 3. Find Exchange Deposits

```python
identifier = EndpointIdentifier()
exchanges = await identifier.find_exchanges(graph)
for exchange in exchanges:
    if exchange.confidence > 0.8:
        print(f"Likely exchange: {exchange.address}")
```

### 4. Generate Report

```python
generator = GraphGenerator()
generator.generate_html_visualization(
    graph,
    'investigation_report.html',
    'Investigation: Suspicious Activity'
)
```

## Integration Example

```python
class TransactionInvestigator:
    def __init__(self):
        self.tracer = TransactionTracer()
        self.flow_analyzer = FundFlowAnalyzer()
        self.taint_analyzer = TaintAnalyzer()
        self.identifier = EndpointIdentifier()
        self.generator = GraphGenerator()

    async def investigate(self, address, blockchain):
        # Trace
        trace = await self.tracer.trace_funds(address, blockchain)

        # Analyze
        flow = await self.flow_analyzer.analyze_flow(
            trace.transaction_graph,
            address
        )

        # Taint
        taint = await self.taint_analyzer.analyze(
            address,
            trace.transaction_graph
        )

        # Report
        self.generator.generate_html_visualization(
            trace.transaction_graph,
            f'report_{address[:8]}.html',
            f'Investigation: {address}'
        )

        return {
            'risk_score': trace.risk_score,
            'taint_score': taint.total_taint,
            'patterns': len(flow.patterns_detected),
            'endpoints': len(flow.endpoints)
        }

# Usage
investigator = TransactionInvestigator()
report = await investigator.investigate("0x742d35...", "ethereum")
```

---

**Quick Help:** For detailed documentation, see `README_TRANSACTION_TRACING.md`
**Examples:** Run `python example_usage.py` for comprehensive examples
**Version:** 1.0.0
