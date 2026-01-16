# Intelligence Fusion Engine

## Overview

The **Intelligence Fusion Engine** is an advanced system for correlating multi-source intelligence, resolving entities, assessing risk, and generating comprehensive intelligence profiles. It combines data from various sources (OSINT, SOCMINT, breach data, blockchain analysis) to create unified entity profiles with confidence scoring and risk assessment.

## Features

### Core Capabilities

- **Multi-Source Intelligence Correlation**: Automatically links and correlates data from multiple intelligence sources
- **Entity Resolution**: Fuzzy matching and deduplication across email, phone, name, wallet addresses
- **Relationship Mapping**: Discovers and scores relationships between entities
- **Confidence Scoring**: Multi-factor confidence calculation based on source reliability, freshness, and corroboration
- **Risk Assessment**: Advanced threat level calculation with behavioral pattern detection
- **Timeline Generation**: Chronological event reconstruction with gap identification and pattern extraction
- **Graph Analysis**: Network analysis with centrality calculations, community detection, and link prediction

## Architecture

```
fusion-engine/
├── fusion_engine.py           # Core fusion orchestration
├── entity_resolver.py         # Entity resolution and deduplication
├── correlation_algorithm.py   # Multi-source correlation
├── confidence_scorer.py       # Confidence scoring system
├── risk_assessor.py          # Risk assessment engine
├── timeline_builder.py       # Timeline generation
├── graph_analyzer.py         # Network graph analysis
├── fusion_rules.yaml         # Configuration and rules
└── README_FUSION_ENGINE.md   # This file
```

## Installation

### Dependencies

```bash
pip install pyyaml
pip install phonenumbers
pip install email-validator
pip install neo4j  # Optional, for graph database integration
```

### Configuration

Edit `fusion_rules.yaml` to customize:
- Entity matching thresholds
- Correlation weights
- Confidence scoring parameters
- Risk assessment rules
- Alert triggers

## Usage

### Basic Usage

```python
from fusion_engine import IntelligenceFusion

# Initialize fusion engine
fusion = IntelligenceFusion(config_path='fusion_rules.yaml')

# Ingest intelligence from various sources
fusion.ingest_intelligence({
    'email': 'target@example.com',
    'name': 'John Doe',
    'location': 'Bulgaria'
}, source_type='osint')

fusion.ingest_intelligence({
    'email': 'target@example.com',
    'breach': 'LinkedIn2021',
    'password_hash': 'sha1:abc123...'
}, source_type='breach')

fusion.ingest_intelligence({
    'wallet': '0x742d35Cc6634C0532925a3b8...',
    'owner_email': 'target@example.com',
    'transactions': 147
}, source_type='blockchain')

# Build comprehensive profile
profile = fusion.build_profile(
    target='target@example.com',
    sources=['osint', 'breach', 'blockchain'],
    deep_analysis=True
)

# Access results
print(f"Confidence Score: {profile.confidence_score}/100")
print(f"Risk Score: {profile.risk_score}/100")
print(f"Relationships: {len(profile.relationships)}")
print(f"Timeline Events: {len(profile.timeline)}")
```

### Advanced Features

#### Generate Intelligence Report

```python
# JSON report
report = fusion.generate_intelligence_report(
    profile.entity_id,
    format='json'
)

# Markdown report
report = fusion.generate_intelligence_report(
    profile.entity_id,
    format='markdown'
)

# HTML report
report = fusion.generate_intelligence_report(
    profile.entity_id,
    format='html'
)
```

#### Export Relationship Graph

```python
# Export as GEXF (for Gephi)
fusion.export_graph(
    profile.entity_id,
    output_path='network.gexf',
    format='gexf'
)

# Export as GraphML
fusion.export_graph(
    profile.entity_id,
    output_path='network.graphml',
    format='graphml'
)
```

#### Get Related Entities

```python
# Find entities connected to target (2 hops)
related = fusion.get_related_entities(
    profile.entity_id,
    max_depth=2
)

for entity in related:
    print(f"{entity.primary_identifier} - Risk: {entity.risk_score}")
```

## Components

### 1. Entity Resolution (`entity_resolver.py`)

Resolves and merges entities across multiple sources using fuzzy matching.

**Features:**
- Email normalization and exact matching
- Phone number normalization (E.164 format)
- Fuzzy name matching (configurable threshold)
- Cryptocurrency wallet detection
- Conflict resolution with confidence weighting

**Example:**
```python
from entity_resolver import EntityResolver

resolver = EntityResolver({'fuzzy_threshold': 0.85})
resolved = resolver.resolve_entities(intelligence_sources, target)
```

### 2. Correlation Algorithm (`correlation_algorithm.py`)

Links entities across sources using weighted scoring and graph-based analysis.

**Features:**
- Multi-source entity correlation
- Temporal proximity correlation
- Attribute overlap detection
- Network clustering
- Shortest path finding

**Example:**
```python
from correlation_algorithm import CorrelationEngine

correlator = CorrelationEngine({'min_correlation_score': 0.6})
correlations = correlator.correlate(entities, intelligence_sources)
```

### 3. Confidence Scorer (`confidence_scorer.py`)

Calculates confidence scores based on multiple factors.

**Scoring Components:**
- **Source Reliability** (30%): Based on source type weights
- **Data Freshness** (20%): Exponential decay over time
- **Corroboration** (25%): Multi-source validation
- **Completeness** (15%): Profile attribute coverage
- **Conflict Penalty** (10%): Deductions for conflicting data

**Example:**
```python
from confidence_scorer import ConfidenceScorer

scorer = ConfidenceScorer(config)
confidence = scorer.calculate_confidence(profile, sources)
breakdown = scorer.get_confidence_breakdown(profile, sources)
```

### 4. Risk Assessor (`risk_assessor.py`)

Advanced threat level calculation with behavioral analysis.

**Risk Factors:**
- **Breach Exposure** (20%): Number and severity of breaches
- **Behavioral Patterns** (25%): Aliases, wallet count, anonymization
- **Network Risk** (20%): Connectivity and relationships
- **Geographic Risk** (10%): High-risk countries, tax havens
- **Temporal Patterns** (15%): Activity bursts, dormancy
- **Known Indicators** (10%): Threat keywords, high-risk domains

**Example:**
```python
from risk_assessor import RiskAssessor

assessor = RiskAssessor(config)
risk_score = assessor.assess_risk(profile, correlations)
category = assessor.categorize_risk(risk_score)  # CRITICAL/HIGH/MEDIUM/LOW
breakdown = assessor.get_risk_breakdown(profile, correlations)
```

### 5. Timeline Builder (`timeline_builder.py`)

Constructs chronological timelines with pattern detection.

**Features:**
- Event extraction from all source types
- Chronological ordering
- Event deduplication
- Gap identification
- Pattern detection (bursts, cycles, escalation)

**Example:**
```python
from timeline_builder import TimelineBuilder

builder = TimelineBuilder(config)
timeline = builder.build_timeline(profile, sources)
builder.export_timeline(timeline, 'timeline.html', format='html')
```

### 6. Graph Analyzer (`graph_analyzer.py`)

Network analysis with graph theory algorithms.

**Features:**
- Centrality calculations (degree, betweenness, closeness, eigenvector)
- Community detection (label propagation)
- Link prediction (common neighbors)
- Shortest path finding
- Influence scoring

**Example:**
```python
from graph_analyzer import GraphAnalyzer

analyzer = GraphAnalyzer(config)
analysis = analyzer.analyze_network(profile, correlations)

print(f"Degree Centrality: {analysis['centrality']['degree']}")
print(f"Communities: {len(analysis['communities'])}")
print(f"Influence Score: {analysis['influence_score']}")
```

## Configuration Reference

### Entity Resolution

```yaml
entity_resolution:
  fuzzy_threshold: 0.85          # Name matching threshold (0.0-1.0)
  email_exact_match: true        # Require exact email matches
  phone_normalize: true          # Normalize phone numbers
  merge_confidence_threshold: 0.75
```

### Correlation

```yaml
correlation:
  min_correlation_score: 0.6     # Minimum score to establish relationship
  time_window_days: 365          # Temporal correlation window
  max_graph_depth: 3             # Maximum traversal depth

  weights:
    exact_match: 1.0
    fuzzy_match: 0.8
    temporal_proximity: 0.6
    attribute_overlap: 0.7
```

### Confidence Scoring

```yaml
confidence:
  source_weights:
    blockchain: 0.95
    breach: 0.85
    sherlock: 0.80
    socmint: 0.75
    osint: 0.70

  freshness_decay_days: 180      # Exponential decay period
  corroboration_bonus: 0.15      # Bonus for multi-source
  conflict_penalty: 0.20         # Penalty for conflicts
```

### Risk Assessment

```yaml
risk:
  high_threshold: 75             # High risk threshold (0-100)
  medium_threshold: 50
  low_threshold: 25

  risk_weights:
    breach_exposure: 0.20
    behavioral_patterns: 0.25
    network_risk: 0.20
    geographic_risk: 0.10
```

## Output Formats

### Entity Profile Structure

```python
{
  "entity_id": "entity_abc123",
  "primary_identifier": "target@example.com",
  "entity_type": "email",
  "confidence_score": 87.5,
  "risk_score": 72.3,
  "attributes": {
    "email": "target@example.com",
    "name": "John Doe",
    "location": "Bulgaria",
    "wallets": ["0x742d35Cc..."]
  },
  "aliases": ["johnd", "jdoe"],
  "relationships": [
    {
      "source_entity": "entity_abc123",
      "target_entity": "entity_def456",
      "type": "owns",
      "score": 0.92
    }
  ],
  "timeline": [
    {
      "timestamp": "2023-05-15T10:30:00",
      "type": "breach",
      "description": "Credentials exposed in LinkedIn2021"
    }
  ]
}
```

## Performance Considerations

- **Batch Processing**: Process multiple targets in parallel
- **Caching**: Enable caching for repeated queries
- **Graph Database**: Use Neo4j for large-scale graph analysis
- **Incremental Updates**: Only re-analyze changed data

## Security & Privacy

- **Data Sanitization**: Automatically redact sensitive data in exports
- **Access Control**: Implement role-based access to fusion engine
- **Audit Logging**: All queries and profile generation logged
- **Data Retention**: Configurable retention policies

## Integration Examples

### With OSINT Tools

```python
# Integrate with Sherlock
from sherlock import search_username
from fusion_engine import IntelligenceFusion

fusion = IntelligenceFusion()

# Run Sherlock
results = search_username('target_username')

# Ingest into fusion engine
fusion.ingest_intelligence({
    'username': 'target_username',
    'platforms': results.found_platforms
}, source_type='sherlock')
```

### With Blockchain Analysis

```python
# Integrate with blockchain scanner
wallet_data = blockchain_api.get_wallet_info('0x742d35Cc...')

fusion.ingest_intelligence({
    'wallet': wallet_data['address'],
    'balance': wallet_data['balance'],
    'transactions': wallet_data['tx_count']
}, source_type='blockchain')
```

### With Breach Databases

```python
# Query breach database
breaches = breach_db.query_email('target@example.com')

for breach in breaches:
    fusion.ingest_intelligence({
        'email': breach['email'],
        'breach': breach['name'],
        'password_hash': breach['password']
    }, source_type='breach')
```

## API Reference

### IntelligenceFusion

- `ingest_intelligence(data, source_type, reliability=None)` - Ingest intelligence
- `build_profile(target, sources=None, deep_analysis=True)` - Build entity profile
- `get_related_entities(entity_id, max_depth=2)` - Find related entities
- `generate_intelligence_report(entity_id, format='json')` - Generate report
- `export_graph(entity_id, output_path, format='gexf')` - Export graph

### EntityResolver

- `resolve_entities(intelligence_sources, target)` - Resolve and merge entities

### CorrelationEngine

- `correlate(entities, intelligence_sources)` - Perform correlation
- `find_shortest_path(entity1_id, entity2_id, relationships)` - Find path
- `calculate_network_centrality(entities, relationships)` - Calculate centrality

### ConfidenceScorer

- `calculate_confidence(profile, sources)` - Calculate confidence score
- `calculate_attribute_confidence(attr_name, attr_value, sources)` - Per-attribute score
- `get_confidence_breakdown(profile, sources)` - Detailed breakdown

### RiskAssessor

- `assess_risk(profile, correlations)` - Calculate risk score
- `categorize_risk(risk_score)` - Get risk category
- `get_risk_breakdown(profile, correlations)` - Detailed breakdown

### TimelineBuilder

- `build_timeline(profile, sources)` - Build timeline
- `export_timeline(events, output_path, format='json')` - Export timeline

### GraphAnalyzer

- `analyze_network(profile, correlations)` - Network analysis
- `find_connections(entity, max_depth=2)` - Find connections
- `export_graph(profile, output_path, format='gexf')` - Export graph

## Troubleshooting

### Low Confidence Scores

- Verify source data quality
- Check for sufficient multi-source corroboration
- Ensure data is recent (check freshness_decay_days)

### Poor Correlation Results

- Adjust `min_correlation_score` threshold
- Verify entity resolution is working correctly
- Check attribute normalization

### High False Positive Rate

- Increase correlation thresholds
- Tighten fuzzy matching threshold
- Review and update fusion_rules.yaml

## Roadmap

- [ ] Machine learning-based entity resolution
- [ ] Real-time streaming intelligence ingestion
- [ ] Advanced graph neural networks for link prediction
- [ ] Integration with STIX/TAXII threat intelligence feeds
- [ ] Automated alert generation and notification
- [ ] Web-based dashboard for profile visualization

## License

Proprietary - APOLLO Intelligence Platform

## Support

For issues, questions, or contributions, contact the APOLLO Intelligence Team.

---

**Built with advanced ML algorithms for production-ready intelligence fusion.**
