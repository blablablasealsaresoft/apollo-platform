# Wallet Clustering - Quick Start Guide

## Installation

```bash
pip install networkx
```

## 5-Minute Quick Start

### 1. Basic Wallet Analysis

```python
from wallet_clustering import WalletClusterer

# Initialize
clusterer = WalletClusterer()

# Analyze wallet
result = clusterer.analyze_wallet("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

# View results
print(f"Cluster size: {len(result.cluster.addresses)}")
print(f"Risk score: {result.risk_assessment['total_risk_score']:.2f}")
print(f"Entity: {result.cluster.entity_name or 'Unknown'}")
```

### 2. Detect Mixing Services

```python
from mixing_detector import MixingDetector

detector = MixingDetector()
result = detector.detect_mixing(["1Address1", "1Address2"])

if result['detected']:
    print(f"⚠️ Mixing detected: {result['service_name']}")
```

### 3. Identify Exchanges

```python
from exchange_identifier import ExchangeIdentifier

identifier = ExchangeIdentifier()
interactions = identifier.identify_exchanges(["1ExchangeAddr"])

for interaction in interactions:
    print(f"Exchange: {interaction['exchange_name']}")
```

### 4. Find Related Addresses (CIH)

```python
from common_input_heuristic import CommonInputHeuristic

cih = CommonInputHeuristic()
result = cih.analyze_address("1YourAddress", depth=2)

for addr in result['related_addresses'][:5]:
    print(f"{addr['address']}: {addr['confidence']:.2f}")
```

### 5. Detect Peel Chains

```python
from peel_chain_analyzer import PeelChainAnalyzer

analyzer = PeelChainAnalyzer()
result = analyzer.analyze_address("1Address", depth=10)

if result['is_peel_chain']:
    print(f"⚠️ Peel chain detected!")
    print(f"Chains: {result['total_chains']}")
    print(f"Risk: {result['risk_score']:.2f}")
```

## Common Use Cases

### Investigate Suspicious Wallet

```python
from wallet_clustering import WalletClusterer

clusterer = WalletClusterer()
result = clusterer.analyze_wallet("1SuspiciousAddr", depth=3, include_mixing=True)

# Check risk
if result.risk_assessment['risk_level'] in ['HIGH', 'CRITICAL']:
    print("⚠️ High-risk wallet detected!")
    print(f"Reasons: {result.risk_assessment['explanation']}")

# Check mixing
if result.mixing_detected:
    print("⚠️ Uses mixing services")

# Check peel chains
if result.peel_chains:
    print(f"⚠️ {len(result.peel_chains)} peel chains detected")
```

### Attribute to Entity

```python
from wallet_clustering import WalletClusterer
from entity_attribution import EntityAttributor

# Cluster addresses
clusterer = WalletClusterer()
result = clusterer.analyze_wallet("1Address")

# Attribute
attributor = EntityAttributor()
attribution = attributor.attribute_cluster(result.cluster)

if attribution['entity_identified']:
    print(f"Entity: {attribution['entity_name']}")
    print(f"Type: {attribution['entity_type']}")
    print(f"Confidence: {attribution['confidence']:.2f}")
```

### Track Money Flow

```python
from peel_chain_analyzer import PeelChainAnalyzer
from cluster_visualizer import ClusterVisualizer

# Detect peel chains
analyzer = PeelChainAnalyzer()
result = analyzer.analyze_address("1Source")

# Visualize
visualizer = ClusterVisualizer()
# Create transaction flow
if result['chains']:
    chain = result['chains'][0]
    print(f"Money flow: {chain['start_address']}")
    for addr in chain['addresses']:
        print(f"  → {addr}")
```

### Export for Analysis

```python
from wallet_clustering import WalletClusterer
from cluster_visualizer import ClusterVisualizer

clusterer = WalletClusterer()
result = clusterer.analyze_wallet("1Address")

# Export cluster data
clusterer.export_clusters("analysis_clusters.json")

# Export visualization
visualizer = ClusterVisualizer()
visualizer.export_to_d3(result.cluster, result.links, "visualization.json")
visualizer.export_to_graphml(result.cluster, result.links, "graph.graphml")
```

## Configuration Examples

### High-Precision Configuration

```python
config = {
    'min_confidence': 0.8,  # Higher confidence threshold
    'cih': {
        'min_inputs': 3,  # At least 3 inputs for CIH
        'exclude_coinjoin': True
    },
    'change': {
        'min_confidence': 0.75
    }
}

clusterer = WalletClusterer(config=config)
```

### Aggressive Clustering

```python
config = {
    'min_confidence': 0.5,  # Lower threshold
    'aggressive': True,
    'max_cluster_size': 50000
}

clusterer = WalletClusterer(config=config)
```

## Output Examples

### Clustering Result
```json
{
  "cluster_id": "abc123def456",
  "addresses": 47,
  "entity_type": "exchange",
  "entity_name": "Binance",
  "risk_score": 0.15,
  "risk_level": "LOW",
  "mixing_detected": false,
  "peel_chains": 0
}
```

### Risk Assessment
```json
{
  "total_risk_score": 0.65,
  "risk_level": "HIGH",
  "risk_factors": {
    "mixing_service_use": 0.3,
    "peel_chain_activity": 0.25,
    "suspicious_patterns": 0.1
  },
  "explanation": "Uses mixing/tumbling services; Exhibits peel chain patterns"
}
```

## Command Line Usage

### Run Demo
```bash
cd wallet-clustering
python demo.py
```

### Run Tests
```bash
python test_clustering.py
```

## Next Steps

1. **Read Full Documentation**: See `README_WALLET_CLUSTERING.md`
2. **Integrate Blockchain API**: Replace simulated data with real blockchain APIs
3. **Customize Entity Database**: Add your own known entities
4. **Visualize Results**: Use exported data with Gephi or D3.js
5. **Scale Up**: Implement caching and parallel processing for large-scale analysis

## Common Patterns

### Pattern 1: Complete Investigation
```python
# 1. Cluster addresses
clusterer = WalletClusterer()
result = clusterer.analyze_wallet("1Target", depth=3)

# 2. Check risk
risk = result.risk_assessment
print(f"Risk: {risk['risk_level']} ({risk['total_risk_score']:.2f})")

# 3. Identify entity
if result.cluster.entity_name:
    print(f"Entity: {result.cluster.entity_name}")

# 4. Check for mixing
if result.mixing_detected:
    print("⚠️ Uses privacy tools")

# 5. Export results
clusterer.export_clusters("investigation.json")
```

### Pattern 2: Batch Analysis
```python
addresses = ["1Addr1", "1Addr2", "1Addr3"]

for addr in addresses:
    result = clusterer.analyze_wallet(addr, depth=2)
    print(f"{addr}: Risk {result.risk_assessment['risk_level']}")
```

### Pattern 3: Real-time Monitoring
```python
def monitor_address(address):
    result = clusterer.analyze_wallet(address)

    if result.risk_assessment['risk_level'] == 'CRITICAL':
        alert(f"Critical risk wallet: {address}")

    if result.mixing_detected:
        alert(f"Mixing service detected: {address}")

    return result

# Monitor continuously
for new_address in stream:
    monitor_address(new_address)
```

## Troubleshooting

**Q: No related addresses found**
- Increase analysis depth
- Lower confidence threshold
- Check if address has transactions

**Q: Too many false positives**
- Increase `min_confidence`
- Enable CoinJoin exclusion
- Use stricter heuristics

**Q: Performance issues**
- Reduce analysis depth
- Set `max_cluster_size` limit
- Implement caching

**Q: NetworkX import error**
- Install: `pip install networkx`
- Or disable visualization features

## Resources

- **Full Documentation**: `README_WALLET_CLUSTERING.md`
- **Demo Script**: `demo.py`
- **Test Suite**: `test_clustering.py`
- **API Reference**: See docstrings in each module

---

**Ready to analyze blockchain data!**
