# Cryptocurrency Wallet Clustering and Attribution System

Advanced blockchain intelligence system for clustering cryptocurrency addresses and attributing them to real-world entities. This system implements state-of-the-art heuristics used by blockchain analysis companies like Chainalysis, Elliptic, and CipherTrace.

## Features

### 1. **Wallet Clustering Engine** (`wallet_clustering.py`)
Complete clustering system that combines multiple heuristics to identify related addresses:
- **Multi-heuristic approach**: Combines CIH, change detection, and peel chain analysis
- **Cluster merging**: Automatically merges clusters when new evidence links them
- **Risk scoring**: Comprehensive risk assessment based on transaction patterns
- **Graph building**: Creates NetworkX graphs for visualization and analysis
- **Export capabilities**: Export clusters to JSON for further analysis

### 2. **Common Input Heuristic** (`common_input_heuristic.py`)
Implements the fundamental CIH principle that addresses used as inputs in the same transaction are controlled by the same entity:
- **Multi-input analysis**: Identifies addresses that appear together in transactions
- **Address grouping**: Uses union-find algorithm to build connected groups
- **CoinJoin detection**: Excludes likely CoinJoin transactions to avoid false clustering
- **Confidence scoring**: Assigns confidence scores based on evidence strength
- **Cluster expansion**: Iteratively expands clusters by following links

### 3. **Change Address Detection** (`change_address_detector.py`)
Sophisticated change address identification using multiple heuristics:
- **One-time address heuristic**: New addresses are likely change
- **Round number heuristic**: Payments are usually round numbers, change is not
- **Script type matching**: Change addresses typically use same script type
- **Optimal change heuristic**: Smallest output is often change
- **Position analysis**: Some wallets consistently place change at specific positions
- **Client fingerprinting**: Identifies wallet software patterns

### 4. **Peel Chain Analysis** (`peel_chain_analyzer.py`)
Detects peel chain patterns commonly used in money laundering:
- **Sequential pattern detection**: Identifies chains of transactions
- **Peel ratio analysis**: Each transaction "peels off" a small amount
- **Layering detection**: Identifies complex layering schemes
- **Time-based analysis**: Analyzes timing patterns between hops
- **Confidence calculation**: Scores chains based on consistency
- **Money laundering indicators**: Flags suspicious patterns

### 5. **Entity Attribution** (`entity_attribution.py`)
Attributes wallet clusters to known entities:
- **50+ known entities**: Pre-loaded database of exchanges, mining pools, etc.
- **Direct address matching**: Matches against known wallet addresses
- **Behavioral signatures**: Matches transaction patterns to entity profiles
- **Pattern recognition**: Identifies exchanges, merchants, mining pools
- **Reputation tracking**: Maintains reputation scores for entities
- **Extensible database**: Easy to add new entities

### 6. **Cluster Visualization** (`cluster_visualizer.py`)
Creates visual representations of wallet clusters:
- **NetworkX integration**: Builds graph structures for analysis
- **Multiple export formats**: GraphML, D3.js, JSON
- **Transaction flow diagrams**: Visualizes money movement
- **Hierarchical views**: Shows cluster hierarchies
- **Risk heatmaps**: Visualizes risk across multiple clusters
- **Interactive graphs**: Generates data for web-based visualization

### 7. **Mixing Service Detection** (`mixing_detector.py`)
Detects use of cryptocurrency mixing/tumbling services:
- **CoinJoin detection**: Identifies Wasabi Wallet, Samourai Whirlpool, JoinMarket
- **Centralized mixer detection**: Identifies ChipMixer, Bitcoin Fog, etc.
- **Equal-output analysis**: Detects characteristic CoinJoin patterns
- **Participant counting**: Analyzes number of CoinJoin participants
- **Service fingerprinting**: Identifies specific mixing service implementations
- **Privacy tool detection**: Lightning Network, atomic swaps, privacy coins

### 8. **Exchange Identification** (`exchange_identifier.py`)
Identifies cryptocurrency exchange wallets:
- **50+ exchange signatures**: Binance, Coinbase, Kraken, and more
- **Hot wallet detection**: High-volume, bidirectional transaction patterns
- **Cold storage identification**: Large balances, infrequent transactions
- **Deposit address clustering**: Identifies deposit address pools
- **Consolidation pattern detection**: Recognizes exchange fund management
- **Reputation tracking**: Maintains exchange reputation scores

## Installation

```bash
# Install required dependencies
pip install networkx
pip install matplotlib  # Optional, for visualization
pip install numpy
```

## Quick Start

### Basic Wallet Clustering

```python
from wallet_clustering import WalletClusterer

# Initialize clusterer
clusterer = WalletClusterer()

# Analyze a wallet
result = clusterer.analyze_wallet("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", depth=2)

# Access results
print(f"Cluster size: {len(result.cluster.addresses)}")
print(f"Entity: {result.cluster.entity_name or 'Unknown'}")
print(f"Risk score: {result.risk_assessment['total_risk_score']:.2f}")
print(f"Mixing detected: {result.mixing_detected}")

# Export cluster
clusterer.export_clusters("clusters_output.json")
```

### Common Input Heuristic Analysis

```python
from common_input_heuristic import CommonInputHeuristic

cih = CommonInputHeuristic()

# Analyze address for related addresses
result = cih.analyze_address("1AddressHere...", depth=3)

print(f"Found {result['total_related']} related addresses")
for addr in result['related_addresses']:
    print(f"  {addr['address']}: confidence {addr['confidence']:.2f}")
```

### Change Address Detection

```python
from change_address_detector import ChangeAddressDetector

detector = ChangeAddressDetector()

# Analyze transactions
result = detector.analyze_transactions("1AddressHere...", depth=2)

print(f"Change addresses found: {len(result['change_addresses'])}")
for change in result['change_addresses']:
    print(f"  {change['address']}: {change['confidence']:.2f}")
    print(f"    Reasons: {', '.join(change['evidence']['reasons'])}")
```

### Peel Chain Detection

```python
from peel_chain_analyzer import PeelChainAnalyzer

analyzer = PeelChainAnalyzer()

# Detect peel chains
result = analyzer.analyze_address("1AddressHere...", depth=10)

if result['is_peel_chain']:
    print(f"⚠️ Peel chain detected!")
    print(f"Chains: {result['total_chains']}")
    print(f"Max length: {result['max_chain_length']}")
    print(f"Risk score: {result['risk_score']:.2f}")

    for chain in result['chains']:
        print(f"\nChain: {chain['chain_length']} hops")
        print(f"  Total peeled: {chain['total_peeled']:.4f} BTC")
```

### Entity Attribution

```python
from entity_attribution import EntityAttributor, KnownEntity

attributor = EntityAttributor()

# Add custom entity
entity = KnownEntity(
    entity_id="my_exchange",
    name="My Exchange",
    entity_type="exchange",
    addresses={"1Addr1...", "1Addr2..."},
    reputation="high"
)
attributor.add_known_entity(entity)

# Attribute cluster
attribution = attributor.attribute_cluster(cluster)

if attribution['entity_identified']:
    print(f"Entity: {attribution['entity_name']}")
    print(f"Type: {attribution['entity_type']}")
    print(f"Confidence: {attribution['confidence']:.2f}")
```

### Mixing Service Detection

```python
from mixing_detector import MixingDetector

detector = MixingDetector()

# Detect mixing
result = detector.detect_mixing(["1Addr1...", "1Addr2..."])

if result['detected']:
    print(f"⚠️ Mixing service detected!")
    print(f"Service: {result['service_name']}")
    print(f"Type: {result['service_type']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Indicators: {', '.join(result['indicators'])}")
```

### Exchange Identification

```python
from exchange_identifier import ExchangeIdentifier

identifier = ExchangeIdentifier()

# Identify exchanges
interactions = identifier.identify_exchanges(["1Addr1...", "1Addr2..."])

for interaction in interactions:
    print(f"Exchange: {interaction['exchange_name']}")
    print(f"Wallet type: {interaction['wallet_type']}")
    print(f"Confidence: {interaction['confidence']:.2f}")
```

### Cluster Visualization

```python
from cluster_visualizer import ClusterVisualizer

visualizer = ClusterVisualizer()

# Create visualization
viz_data = visualizer.visualize_cluster(cluster, links)

# Export to various formats
visualizer.export_to_graphml(cluster, links, "cluster.graphml")
visualizer.export_to_d3(cluster, links, "cluster_d3.json")
visualizer.export_to_json(cluster, links, "cluster_viz.json")

# Create risk heatmap
heatmap = visualizer.create_risk_heatmap([cluster1, cluster2, cluster3])
```

## Advanced Usage

### Custom Clustering Configuration

```python
config = {
    'cih': {
        'min_inputs': 2,
        'max_inputs': 100,
        'exclude_coinjoin': True
    },
    'change': {
        'min_confidence': 0.6,
        'round_number_heuristic': True,
        'one_time_heuristic': True
    },
    'peel': {
        'min_chain_length': 3,
        'max_peel_ratio': 0.3,
        'min_peel_ratio': 0.01
    },
    'min_confidence': 0.7,
    'aggressive': False
}

clusterer = WalletClusterer(config=config)
```

### Merge Clusters

```python
# Merge two clusters when new evidence links them
evidence = {
    'type': 'common_input',
    'transaction': 'txhash123...',
    'confidence': 0.9
}

merged_id = clusterer.merge_clusters(cluster_id1, cluster_id2, evidence)
```

### Expand Cluster

```python
# Expand existing cluster
new_addresses = clusterer.expand_cluster(cluster_id, depth=2)
print(f"Added {len(new_addresses)} new addresses to cluster")
```

### Layering Detection

```python
# Detect money laundering layering activity
addresses = ["1Addr1...", "1Addr2...", "1Addr3..."]
layering = analyzer.detect_layering_activity(addresses)

if layering['is_layering_detected']:
    print(f"⚠️ Layering activity detected!")
    print(f"Complexity score: {layering['complexity_score']:.2f}")
    print(f"Risk level: {layering['risk_level']}")
```

## Architecture

### Clustering Process Flow

```
1. Initial Analysis
   ├── Common Input Heuristic (CIH)
   ├── Change Address Detection
   └── Peel Chain Analysis

2. Cluster Building
   ├── Address Grouping
   ├── Link Creation
   └── Confidence Scoring

3. Entity Attribution
   ├── Direct Address Matching
   ├── Behavioral Pattern Matching
   └── Transaction Pattern Analysis

4. Risk Assessment
   ├── Mixing Detection
   ├── Exchange Interaction Analysis
   ├── Peel Chain Scoring
   └── Overall Risk Calculation

5. Visualization & Export
   ├── Graph Building
   ├── Layout Calculation
   └── Export to Formats
```

### Data Structures

**AddressCluster**: Represents a cluster of related addresses
- `cluster_id`: Unique identifier
- `addresses`: Set of addresses in cluster
- `entity_type`: Type of entity (exchange, merchant, etc.)
- `risk_score`: 0-1 risk score
- `tags`: Set of descriptive tags
- `metadata`: Additional data

**ClusterLink**: Represents a link between addresses
- `source`: Source address
- `target`: Target address
- `link_type`: Type of link (common_input, change, etc.)
- `confidence`: Link confidence score
- `evidence`: Supporting evidence

**PeelChain**: Represents a peel chain
- `chain_id`: Unique identifier
- `links`: List of chain links
- `chain_length`: Number of hops
- `total_peeled`: Amount peeled off
- `confidence`: Chain confidence

## Heuristics Explained

### Common Input Heuristic (CIH)
**Principle**: All inputs to a transaction are controlled by the same entity.

**Example**:
```
Transaction:
  Inputs: [1Addr1, 1Addr2, 1Addr3]
  Outputs: [1AddrA, 1AddrB]

Conclusion: Addr1, Addr2, and Addr3 are controlled by same entity
```

**Exceptions**: CoinJoin transactions violate this heuristic

### Change Address Detection
**Heuristics**:
1. **One-time address**: Change addresses are typically new, one-time use
2. **Round number**: Payments are round (0.1 BTC), change is not (0.1337 BTC)
3. **Script type**: Change uses same script type as inputs
4. **Smallest output**: Change is often the smallest output
5. **Position**: Some wallets always put change first or last

### Peel Chain Pattern
**Characteristics**:
```
Transaction 1: 10.0 BTC → 0.5 BTC (peel) + 9.5 BTC (change)
Transaction 2: 9.5 BTC → 0.5 BTC (peel) + 9.0 BTC (change)
Transaction 3: 9.0 BTC → 0.5 BTC (peel) + 8.5 BTC (change)
...
```

**Use cases**: Money laundering, fund distribution

## Risk Scoring

Risk scores are calculated based on multiple factors:

- **Mixing service use**: +0.3 (high risk)
- **Peel chain activity**: +0.25 per chain (layering)
- **Exchange interaction**: -0.1 (legitimate exchanges reduce risk)
- **Cluster complexity**: +0.15 (large clusters)
- **Suspicious patterns**: +0.5 (darknet, ransomware tags)

**Risk Levels**:
- **0.0 - 0.2**: LOW
- **0.2 - 0.4**: MEDIUM
- **0.4 - 0.6**: HIGH
- **0.6 - 1.0**: CRITICAL

## Known Limitations

1. **CoinJoin False Positives**: CIH can incorrectly cluster CoinJoin participants
2. **Address Reuse**: Assumes addresses aren't reused across entities
3. **Script Polymorphism**: Different script types from same entity confuse heuristics
4. **Privacy Tools**: Advanced privacy techniques can defeat clustering
5. **Simulated Data**: Current implementation uses simulated blockchain data

## Production Deployment

For production use, integrate with real blockchain APIs:

### Blockchain Data Sources
```python
# Example: Bitcoin Core RPC
import requests

def get_transaction(tx_hash):
    response = requests.post('http://localhost:8332', json={
        'jsonrpc': '1.0',
        'method': 'getrawtransaction',
        'params': [tx_hash, True]
    })
    return response.json()['result']

# Example: Block explorer API
def get_address_transactions(address):
    response = requests.get(
        f'https://blockstream.info/api/address/{address}/txs'
    )
    return response.json()
```

### Replace Simulation Methods
Update these methods in each module to use real data:
- `_get_transactions()`
- `_simulate_blockchain_query()`
- `_find_multi_input_transactions()`

## Performance Considerations

- **Large clusters**: Limit cluster size with `max_cluster_size` config
- **Deep analysis**: Higher depth values increase runtime exponentially
- **Graph operations**: NetworkX operations are O(n²) for dense graphs
- **Caching**: Implementation includes transaction caching
- **Parallel processing**: Analyze multiple addresses in parallel

## Security Considerations

- **Data privacy**: Blockchain data is public but analysis reveals sensitive info
- **Rate limiting**: Implement rate limiting for API calls
- **False positives**: Always verify findings before taking action
- **Legal compliance**: Ensure compliance with local regulations

## References

### Academic Papers
1. "An Analysis of Anonymity in the Bitcoin System" (Reid & Harrigan, 2011)
2. "Evaluating User Privacy in Bitcoin" (Androulaki et al., 2013)
3. "Deanonymisation of Clients in Bitcoin P2P Network" (Biryukov et al., 2014)
4. "CoinJoin: Bitcoin Privacy for the Real World" (Maxwell, 2013)

### Industry Resources
- Chainalysis: Transaction clustering methodology
- Elliptic: Entity attribution techniques
- CipherTrace: AML compliance tools

## License

Proprietary - Apollo Threat Intelligence Platform

## Support

For issues, questions, or contributions, contact the Apollo development team.

---

**Built for advanced blockchain intelligence and cryptocurrency investigations.**
