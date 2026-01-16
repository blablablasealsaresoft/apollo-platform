# Blockchain Intelligence System

Comprehensive blockchain forensics and intelligence platform supporting Bitcoin, Ethereum, and 50+ blockchain networks.

## Features

### Multi-Chain Support
- **Bitcoin**: Complete wallet analysis, UTXO tracking, transaction tracing
- **Ethereum**: Smart contract analysis, ERC-20 tokens, DeFi protocol tracking
- **50+ Chains**: BSC, Polygon, Avalanche, Fantom, Arbitrum, Optimism, and more

### Core Capabilities

#### 1. Wallet Analysis (`bitcoin_tracker.py`, `ethereum_tracker.py`)
- Balance tracking across multiple APIs
- Transaction history analysis
- Risk scoring and pattern detection
- Support for multiple data sources with automatic fallback

#### 2. Multi-Chain Tracking (`multi_chain_tracker.py`)
- Unified interface for 50+ blockchain networks
- Cross-chain activity monitoring
- Token balance tracking across chains
- Support for EVM-compatible chains and beyond

#### 3. Wallet Clustering (`wallet_clustering.py`)
- Common input ownership heuristic
- Change address detection
- Peel chain analysis
- Entity attribution
- Confidence scoring

#### 4. Transaction Tracing (`transaction_tracer.py`)
- Multi-hop fund flow analysis
- Forward and backward tracing
- Mixing service detection
- Exchange identification
- Graph visualization (DOT, JSON, Cytoscape formats)

#### 5. Exchange Monitoring (`exchange_monitor.py`)
- Track 50+ cryptocurrency exchanges
- Deposit/withdrawal detection
- Exchange hopping analysis
- Wallet clustering by exchange

#### 6. API Orchestration (`blockchain_apis.py`)
- 50+ blockchain API integrations
- Rate limiting per API
- Automatic fallback mechanisms
- Response caching (60-second TTL)
- Retry logic with exponential backoff

#### 7. OneCoin Investigation (`onecoin_tracker.py`)
- OneCoin-specific fraud tracking
- Known wallet identification
- Victim payment analysis
- Criminal network mapping
- Comprehensive investigation reports

## Installation

```bash
# Install required dependencies
pip install requests

# Optional: For advanced visualization
pip install networkx matplotlib
```

## Quick Start

### Basic Usage

```python
from blockchain_intelligence import create_intelligence_suite

# Create the full intelligence suite
suite = create_intelligence_suite(
    ethereum_api_key='YOUR_ETHERSCAN_API_KEY'
)

# Analyze a Bitcoin wallet
analysis = suite['bitcoin'].analyze_wallet('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
print(f"Balance: {analysis['balance']} BTC")
print(f"Risk Score: {analysis['risk_score']}/10")
```

### Bitcoin Analysis

```python
from bitcoin_tracker import BitcoinTracker

tracker = BitcoinTracker()

# Get wallet information
wallet = tracker.analyze_wallet('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
print(f"Total received: {wallet['total_received']} BTC")
print(f"Total sent: {wallet['total_sent']} BTC")
print(f"Transaction count: {wallet['tx_count']}")

# Trace fund flow
flow = tracker.trace_funds('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', max_hops=5)
print(f"Traced {len(flow['nodes'])} addresses")

# Get UTXOs
utxos = tracker.get_utxos('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
print(f"Unspent outputs: {len(utxos)}")
```

### Ethereum Analysis

```python
from ethereum_tracker import EthereumTracker

tracker = EthereumTracker(etherscan_api_key='YOUR_API_KEY')

# Analyze Ethereum wallet
wallet = tracker.analyze_wallet('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')
print(f"ETH Balance: {wallet['eth_balance']}")
print(f"Token Count: {wallet['token_count']}")
print(f"Portfolio Value: ${wallet['portfolio_value_usd']:.2f}")

# Get token balances
tokens = tracker.get_token_balances('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')
for token in tokens:
    print(f"{token['token_symbol']}: {token['balance']}")

# Analyze DeFi activity
defi = tracker.analyze_defi_activity('0x742d35Cc6634C0532925a3b844Bc454e4438f44e')
print(f"DeFi Protocols Used: {defi['unique_protocols']}")

# Analyze smart contract
contract = tracker.analyze_smart_contract('0x6B175474E89094C44Da98b954EedeAC495271d0F')
print(f"Contract: {contract['name']}")
print(f"Verified: {contract['verified']}")
```

### Multi-Chain Analysis

```python
from multi_chain_tracker import MultiChainTracker

tracker = MultiChainTracker()

# Get supported chains
chains = tracker.get_supported_chains()
print(f"Supported chains: {len(chains)}")

# Analyze wallet across multiple chains
analysis = tracker.analyze_multi_chain_wallet(
    '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    chains=['bsc', 'polygon', 'avalanche', 'fantom', 'arbitrum']
)

for balance in analysis['chain_balances']:
    print(f"{balance['chain_name']}: {balance['balance']} {balance['token']}")

# Trace cross-chain activity
activity = tracker.trace_cross_chain_activity(
    '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    chains=['ethereum', 'bsc', 'polygon']
)
print(f"Total transactions: {activity['total_transactions']}")
```

### Wallet Clustering

```python
from wallet_clustering import WalletClusterer
from bitcoin_tracker import BitcoinTracker

btc_tracker = BitcoinTracker()
clusterer = WalletClusterer(bitcoin_tracker=btc_tracker)

# Cluster Bitcoin addresses
cluster = clusterer.cluster_bitcoin_addresses(
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    depth=3
)

print(f"Cluster size: {cluster['size']} addresses")
print(f"Entity type: {cluster['entity_type']}")
print(f"Heuristics used: {cluster['heuristics_used']}")

# Analyze cluster behavior
behavior = clusterer.analyze_cluster_behavior(cluster)
print(f"Risk score: {behavior['risk_score']}/10")
print(f"Risk indicators: {behavior['risk_indicators']}")

# Export as graph
graph = clusterer.export_cluster_graph(cluster)
# Use with visualization tools like Cytoscape or D3.js
```

### Transaction Tracing

```python
from transaction_tracer import TransactionTracer
from bitcoin_tracker import BitcoinTracker

btc_tracker = BitcoinTracker()
tracer = TransactionTracer(bitcoin_tracker=btc_tracker)

# Trace funds forward (where did the money go?)
trace = tracer.trace_bitcoin_funds(
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    direction='forward',
    max_hops=5,
    min_amount=0.01
)

print(f"Unique addresses: {trace['unique_addresses']}")
print(f"Total amount traced: {trace['total_amount_traced']} BTC")
print(f"Mixing services detected: {trace['mixing_services_detected']}")
print(f"Exchanges detected: {trace['exchanges_detected']}")

# Analyze patterns
analysis = trace['analysis']
print(f"Risk score: {analysis['risk_score']}/10")
print(f"Patterns: {analysis['patterns_detected']}")

# Generate visualization
dot_graph = tracer.visualize_flow(trace, output_format='dot')
# Save to file for Graphviz

# Generate report
report = tracer.generate_report(trace)
print(report)
```

### Exchange Monitoring

```python
from exchange_monitor import ExchangeMonitor
from bitcoin_tracker import BitcoinTracker

btc_tracker = BitcoinTracker()
monitor = ExchangeMonitor(bitcoin_tracker=btc_tracker)

# Get all monitored exchanges
exchanges = monitor.get_all_exchanges()
print(f"Monitoring {len(exchanges)} exchanges")

# Track exchange activity for an address
activity = monitor.track_exchange_activity(
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    blockchain='bitcoin'
)

print(f"Exchanges used: {activity['exchanges_used']}")
print(f"Total deposited: {activity['total_deposited']} BTC")
print(f"Total withdrawn: {activity['total_withdrawn']} BTC")

# Detect exchange hopping
hopping = monitor.detect_exchange_hopping('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
if hopping['is_exchange_hopping']:
    print(f"⚠ Exchange hopping detected! ({hopping['hop_count']} hops)")
    print(f"Risk score: {hopping['risk_score']}/10")

# Monitor specific exchange
report = monitor.generate_exchange_report('binance', hours=24)
print(report)
```

### OneCoin Investigation

```python
from onecoin_tracker import OneCoinTracker
from bitcoin_tracker import BitcoinTracker

btc_tracker = BitcoinTracker()
onecoin = OneCoinTracker(bitcoin_tracker=btc_tracker)

# Get known OneCoin operators
operators = onecoin.get_known_operators()
for op in operators:
    print(f"{op['name']} - {op['role']} ({op['status']})")

# Track OneCoin funds
tracking = onecoin.track_onecoin_funds(
    'onecoin_wallet_address',
    blockchain='bitcoin'
)

print(f"Total tracked: {tracking['total_amount_tracked']} BTC")
print(f"Unique recipients: {tracking['unique_recipients']}")

# Identify victim payments
victims = onecoin.identify_victim_payments('onecoin_wallet_address')
print(f"Identified {len(victims)} potential victims")

for victim in victims[:10]:
    print(f"  {victim['address']}: {victim['total_received']} BTC ({victim['payment_count']} payments)")

# Generate investigation report
report = onecoin.generate_investigation_report({
    'case_id': 'ONECOIN-001',
    'wallets_tracked': 50,
    'victims': victims
})
print(report)
```

### API Orchestration

```python
from blockchain_apis import BlockchainAPIOrchestrator

orchestrator = BlockchainAPIOrchestrator()

# Get API status
status = orchestrator.get_api_status()
print(f"Total APIs configured: {status['total_apis']}")
print(f"By type: {status['by_type']}")

# Get Bitcoin address with automatic fallback
result = orchestrator.get_bitcoin_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
print(f"Data source: {result.get('_source_api')}")

# Get token price
price = orchestrator.get_token_price('bitcoin')
print(f"BTC Price: ${price.get('bitcoin', {}).get('usd')}")

# Manual API call with caching
result = orchestrator.call_api(
    'blockstream',
    '/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    use_cache=True
)

# Clear cache
orchestrator.clear_cache()
```

## Supported Blockchain Networks

### Layer 1 Networks (30+)
- Bitcoin, Ethereum, Binance Smart Chain, Polygon, Avalanche
- Fantom, Cronos, Moonbeam, Moonriver, Gnosis Chain
- Celo, Harmony, Aurora, Klaytn, Metis
- IoTeX, ThunderCore, Energi, Smart Bitcoin Cash
- Algorand, NEAR, Flow, Hedera, Aptos, Sui

### Layer 2 Networks (20+)
- Arbitrum, Optimism, Base, Linea, Scroll
- zkSync Era, Polygon zkEVM, Mantle, Blast
- Boba Network, StarkNet, Loopring

### Additional Networks
- Testnets: Goerli, Sepolia, Mumbai
- And many more...

## API Sources

### Bitcoin APIs
- Blockchain.info
- Blockchair
- BlockCypher
- Blockstream
- Mempool.space

### Ethereum APIs
- Etherscan
- Ethplorer
- Blockchair
- Alchemy
- Infura

### Multi-Chain APIs
- Covalent
- Moralis
- QuickNode
- Ankr
- Pocket Network

### Market Data APIs
- CoinGecko
- CoinMarketCap
- CryptoCompare

## API Rate Limits

The system automatically handles rate limiting for all APIs:

- Blockchain.info: 5 req/sec
- Blockchair: 3 req/sec
- BlockCypher: 5 req/sec
- Blockstream: 10 req/sec
- Etherscan: 5 req/sec
- Ethplorer: 1 req/sec (free tier)

## Advanced Features

### Graph Visualization

Export transaction flows as graphs:

```python
# DOT format (Graphviz)
dot = tracer.visualize_flow(trace, output_format='dot')
with open('flow.dot', 'w') as f:
    f.write(dot)

# Cytoscape format
cyto = tracer.visualize_flow(trace, output_format='cytoscape')
# Import into Cytoscape for advanced visualization
```

### Clustering Analysis

```python
# Find common patterns across clusters
patterns = clusterer.find_common_patterns([cluster1, cluster2, cluster3])
print(f"Common addresses: {patterns['common_addresses']}")
print(f"Shared heuristics: {patterns['shared_heuristics']}")
```

### Cross-Chain Investigation

```python
# Track activity across multiple chains
from multi_chain_tracker import MultiChainTracker

tracker = MultiChainTracker()
activity = tracker.trace_cross_chain_activity(
    address='0x...',
    chains=['ethereum', 'bsc', 'polygon', 'avalanche']
)

for chain, data in activity['chains'].items():
    print(f"{chain}: {data['tx_count']} transactions")
```

## Risk Scoring

The system assigns risk scores (0-10) based on:

- Transaction patterns (mixing, peeling, etc.)
- Exchange interactions
- Wallet clustering characteristics
- Known entity associations
- Volume and frequency analysis

## Security Considerations

1. **API Keys**: Store API keys securely (environment variables)
2. **Rate Limiting**: Respect API rate limits to avoid bans
3. **Data Privacy**: Handle wallet data responsibly
4. **Legal Compliance**: Ensure compliance with local regulations

## Performance Optimization

1. **Caching**: 60-second TTL for API responses
2. **Rate Limiting**: Automatic throttling per API
3. **Fallback**: Multiple APIs for redundancy
4. **Batch Processing**: Process wallets in batches

## Limitations

1. OneCoin never had a real blockchain (Bitcoin/Ethereum used for tracking fiat flows)
2. Some exchange wallets may not be in the database
3. API rate limits may slow large-scale analysis
4. Some chains require specific API keys

## Contributing

To add support for new blockchains:

1. Add chain configuration to `multi_chain_tracker.py`
2. Update API endpoints in `blockchain_apis.py`
3. Add rate limiting configuration
4. Test with sample addresses

## Use Cases

1. **Law Enforcement**: Track criminal funds, identify suspects
2. **Compliance**: AML/KYC screening for exchanges
3. **Investigation**: Fraud detection and analysis
4. **Research**: Network analysis and pattern recognition
5. **Recovery**: Asset tracing for victims

## License

This software is for legitimate investigative purposes only.

## Disclaimer

This tool is designed for legitimate blockchain intelligence and investigative purposes. Users are responsible for compliance with all applicable laws and regulations.

## Support

For issues, questions, or contributions, please refer to the project documentation.

---

**Built for comprehensive blockchain intelligence and forensic analysis.**
