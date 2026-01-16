# Intelligence Fusion Engine - Quick Start Guide

## 5-Minute Quick Start

### Installation

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\fusion-engine
pip install -r requirements.txt
```

### Basic Example

```python
from fusion_engine import IntelligenceFusion

# Initialize
fusion = IntelligenceFusion()

# Ingest data from multiple sources
fusion.ingest_intelligence({
    'email': 'target@example.com',
    'name': 'John Doe',
    'location': 'Bulgaria'
}, source_type='osint')

fusion.ingest_intelligence({
    'email': 'target@example.com',
    'breach': 'LinkedIn2021',
    'password_hash': 'sha1:abc123'
}, source_type='breach')

fusion.ingest_intelligence({
    'wallet': '0x742d35Cc6634C0532925a3b8...',
    'owner_email': 'target@example.com',
    'transactions': 147
}, source_type='blockchain')

# Build comprehensive profile
profile = fusion.build_profile(
    target='target@example.com',
    deep_analysis=True
)

# View results
print(f"Confidence: {profile.confidence_score}/100")
print(f"Risk: {profile.risk_score}/100")
print(f"Relationships: {len(profile.relationships)}")

# Generate report
report = fusion.generate_intelligence_report(
    profile.entity_id,
    format='markdown'
)
print(report)
```

## Run Example

```bash
python example_usage.py
```

This will:
1. Ingest intelligence from 7 different sources
2. Build a comprehensive profile with entity resolution
3. Calculate confidence and risk scores
4. Generate timeline with pattern detection
5. Perform network analysis
6. Export reports in JSON, Markdown, and HTML formats

## Run Tests

```bash
python test_fusion_engine.py
```

## Key Features Demo

### Entity Resolution

```python
# Automatically merges entities across sources
fusion.ingest_intelligence({'email': 'Test@Example.COM'}, 'osint')
fusion.ingest_intelligence({'email': 'test@example.com'}, 'breach')
# Both resolve to same entity
```

### Confidence Scoring

```python
from confidence_scorer import ConfidenceScorer

scorer = ConfidenceScorer(config)
breakdown = scorer.get_confidence_breakdown(profile, sources)

# Components:
# - Source Reliability (30%)
# - Data Freshness (20%)
# - Corroboration (25%)
# - Completeness (15%)
# - Conflict Penalty (10%)
```

### Risk Assessment

```python
from risk_assessor import RiskAssessor

assessor = RiskAssessor(config)
breakdown = assessor.get_risk_breakdown(profile, correlations)

# Risk Factors:
# - Breach Exposure (20%)
# - Behavioral Patterns (25%)
# - Network Risk (20%)
# - Geographic Risk (10%)
# - Temporal Patterns (15%)
# - Known Indicators (10%)
```

### Timeline Generation

```python
from timeline_builder import TimelineBuilder

builder = TimelineBuilder(config)
timeline = builder.build_timeline(profile, sources)

# Export to HTML
builder.export_timeline(timeline, 'timeline.html', format='html')
```

### Graph Analysis

```python
from graph_analyzer import GraphAnalyzer

analyzer = GraphAnalyzer(config)
analysis = analyzer.analyze_network(profile, correlations)

print(f"Degree Centrality: {analysis['centrality']['degree']}")
print(f"Influence Score: {analysis['influence_score']}")
print(f"Communities: {len(analysis['communities'])}")
```

## Configuration

Edit `fusion_rules.yaml` to customize:

```yaml
# Entity matching threshold
entity_resolution:
  fuzzy_threshold: 0.85

# Correlation threshold
correlation:
  min_correlation_score: 0.6

# Risk thresholds
risk:
  high_threshold: 75
  medium_threshold: 50
```

## Output Formats

### JSON Report
```python
report = fusion.generate_intelligence_report(entity_id, format='json')
```

### Markdown Report
```python
report = fusion.generate_intelligence_report(entity_id, format='markdown')
```

### HTML Report
```python
report = fusion.generate_intelligence_report(entity_id, format='html')
```

### Graph Export
```python
# GEXF (for Gephi)
fusion.export_graph(entity_id, 'graph.gexf', format='gexf')

# GraphML
fusion.export_graph(entity_id, 'graph.graphml', format='graphml')

# JSON
fusion.export_graph(entity_id, 'graph.json', format='json')
```

## Common Use Cases

### 1. Multi-Source Person Investigation

```python
# Ingest from all available sources
sources = ['osint', 'breach', 'socmint', 'sherlock', 'blockchain']

for source_type in sources:
    data = get_data_from_source(target, source_type)
    fusion.ingest_intelligence(data, source_type)

# Build comprehensive profile
profile = fusion.build_profile(target, sources=sources)
```

### 2. Cryptocurrency Investigation

```python
# Focus on blockchain sources
fusion.ingest_intelligence({
    'wallet': '0x742d35Cc...',
    'blockchain': 'Ethereum',
    'transactions': 147
}, 'blockchain')

profile = fusion.build_profile('0x742d35Cc...')
```

### 3. Network Analysis

```python
# Build profile with deep network analysis
profile = fusion.build_profile(target, deep_analysis=True)

# Get related entities
related = fusion.get_related_entities(profile.entity_id, max_depth=3)

for entity in related:
    print(f"{entity.primary_identifier}: Risk {entity.risk_score}")
```

### 4. Breach Exposure Assessment

```python
# Focus on breach data
breaches = query_breach_databases(email)

for breach in breaches:
    fusion.ingest_intelligence(breach, 'breach')

profile = fusion.build_profile(email)

# Check risk
if profile.risk_score >= 75:
    print("HIGH RISK: Significant breach exposure detected")
```

## Performance Tips

1. **Batch Processing**: Process multiple targets in parallel
2. **Caching**: Enable caching in config for repeated queries
3. **Source Selection**: Only use relevant sources for faster processing
4. **Shallow Analysis**: Set `deep_analysis=False` for quick profiles

## Troubleshooting

### Import Errors
```bash
# Install dependencies
pip install -r requirements.txt
```

### Low Confidence Scores
- Check data quality and freshness
- Ensure multi-source corroboration
- Verify source reliability weights in config

### High Memory Usage
- Process targets in batches
- Clear cache periodically: `fusion.clear_cache()`
- Reduce `max_graph_depth` in config

## Next Steps

1. Read the full documentation: `README_FUSION_ENGINE.md`
2. Explore example code: `example_usage.py`
3. Run test suite: `test_fusion_engine.py`
4. Customize configuration: `fusion_rules.yaml`

## Support

For questions or issues:
- Check README_FUSION_ENGINE.md for detailed documentation
- Review example_usage.py for working examples
- Run test suite to verify installation

---

**Ready to start fusing intelligence!**
