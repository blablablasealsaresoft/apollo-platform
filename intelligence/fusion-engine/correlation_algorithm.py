"""
Correlation Algorithm
Multi-source data correlation with graph-based relationship discovery
"""

import hashlib
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import itertools


class CorrelationEngine:
    """
    Advanced Correlation Engine
    Links entities across sources using weighted scoring and graph analysis
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Correlation Engine

        Args:
            config: Configuration dictionary
        """
        self.min_correlation_score = config.get('min_correlation_score', 0.6)
        self.time_window_days = config.get('time_window_days', 365)
        self.max_graph_depth = config.get('max_graph_depth', 3)

        # Correlation weight factors
        self.weights = {
            'exact_match': 1.0,
            'fuzzy_match': 0.8,
            'temporal_proximity': 0.6,
            'attribute_overlap': 0.7,
            'shared_source': 0.5,
            'network_proximity': 0.75
        }

    def correlate(self, entities: List[Dict[str, Any]],
                 intelligence_sources: List[Any]) -> Dict[str, Any]:
        """
        Perform comprehensive correlation across entities and sources

        Args:
            entities: List of resolved entities
            intelligence_sources: List of IntelligenceSource objects

        Returns:
            Correlation results with relationships and scores
        """
        correlations = {
            'relationships': [],
            'correlations': [],
            'clusters': [],
            'shared_attributes': {}
        }

        # 1. Direct entity correlations
        entity_relationships = self._correlate_entities(entities)
        correlations['relationships'].extend(entity_relationships)

        # 2. Temporal correlations
        temporal_correlations = self._correlate_temporal(intelligence_sources)
        correlations['correlations'].extend(temporal_correlations)

        # 3. Attribute-based correlations
        attribute_correlations = self._correlate_attributes(entities)
        correlations['shared_attributes'] = attribute_correlations

        # 4. Network clustering
        clusters = self._cluster_entities(entities, entity_relationships)
        correlations['clusters'] = clusters

        # 5. Cross-source validation
        cross_source = self._cross_source_correlation(entities, intelligence_sources)
        correlations['cross_source_validation'] = cross_source

        return correlations

    def _correlate_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find relationships between entities"""
        relationships = []

        # Compare all entity pairs
        for e1, e2 in itertools.combinations(entities, 2):
            score = self._calculate_entity_correlation(e1, e2)

            if score >= self.min_correlation_score:
                relationship = {
                    'source_entity': e1['entity_id'],
                    'target_entity': e2['entity_id'],
                    'type': self._determine_relationship_type(e1, e2),
                    'score': score,
                    'evidence': self._collect_evidence(e1, e2)
                }
                relationships.append(relationship)

        return relationships

    def _calculate_entity_correlation(self, entity1: Dict[str, Any],
                                     entity2: Dict[str, Any]) -> float:
        """Calculate correlation score between two entities"""
        score = 0.0
        factors = []

        attrs1 = entity1.get('attributes', {})
        attrs2 = entity2.get('attributes', {})

        # 1. Shared email domain
        if 'email' in attrs1 and 'email' in attrs2:
            domain1 = attrs1['email'].split('@')[1] if '@' in attrs1['email'] else ''
            domain2 = attrs2['email'].split('@')[1] if '@' in attrs2['email'] else ''
            if domain1 and domain1 == domain2:
                score += self.weights['exact_match'] * 0.6
                factors.append('shared_email_domain')

        # 2. Shared phone prefix (area code)
        if 'phone' in attrs1 and 'phone' in attrs2:
            if attrs1['phone'][:4] == attrs2['phone'][:4]:  # Country + area code
                score += self.weights['fuzzy_match'] * 0.5
                factors.append('shared_phone_prefix')

        # 3. Location overlap
        loc1 = attrs1.get('location', '')
        loc2 = attrs2.get('location', '')
        if loc1 and loc2:
            if loc1.lower() == loc2.lower():
                score += self.weights['exact_match'] * 0.7
                factors.append('same_location')
            elif loc1.lower() in loc2.lower() or loc2.lower() in loc1.lower():
                score += self.weights['fuzzy_match'] * 0.5
                factors.append('location_overlap')

        # 4. Name similarity
        name1 = attrs1.get('name', '')
        name2 = attrs2.get('name', '')
        if name1 and name2:
            name_similarity = self._calculate_string_similarity(name1, name2)
            if name_similarity > 0.8:
                score += self.weights['fuzzy_match'] * name_similarity
                factors.append('name_similarity')

        # 5. Shared aliases
        aliases1 = set(entity1.get('aliases', []))
        aliases2 = set(entity2.get('aliases', []))
        shared_aliases = aliases1.intersection(aliases2)
        if shared_aliases:
            score += self.weights['exact_match'] * min(len(shared_aliases) * 0.3, 1.0)
            factors.append('shared_aliases')

        # 6. Attribute overlap
        shared_keys = set(attrs1.keys()).intersection(set(attrs2.keys()))
        if shared_keys:
            overlap_score = sum(
                1.0 for key in shared_keys
                if attrs1[key] == attrs2[key]
            ) / len(shared_keys)
            score += self.weights['attribute_overlap'] * overlap_score * 0.5

        # 7. Source overlap
        source1 = entity1.get('source_id', '')
        source2 = entity2.get('source_id', '')
        if source1 and source2 and source1 == source2:
            score += self.weights['shared_source'] * 0.3

        # Normalize score to 0-1 range
        max_possible_score = 4.0  # Approximate max from all factors
        normalized_score = min(score / max_possible_score, 1.0)

        return normalized_score

    def _correlate_temporal(self, sources: List[Any]) -> List[Dict[str, Any]]:
        """Find temporal correlations across intelligence sources"""
        correlations = []

        # Group sources by time windows
        time_window = timedelta(days=self.time_window_days)

        for s1, s2 in itertools.combinations(sources, 2):
            time_diff = abs((s1.timestamp - s2.timestamp).total_seconds())

            # If sources are within time window
            if time_diff <= time_window.total_seconds():
                proximity_score = 1.0 - (time_diff / time_window.total_seconds())

                correlation = {
                    'source1': s1.source_id,
                    'source2': s2.source_id,
                    'type': 'temporal',
                    'time_diff_hours': time_diff / 3600,
                    'score': proximity_score * self.weights['temporal_proximity']
                }
                correlations.append(correlation)

        return correlations

    def _correlate_attributes(self, entities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Find shared attributes across entities"""
        attribute_index = defaultdict(set)

        # Index entities by attribute values
        for entity in entities:
            entity_id = entity['entity_id']
            attrs = entity.get('attributes', {})

            for key, value in attrs.items():
                if value and key not in ['name']:  # Skip ambiguous attributes
                    if isinstance(value, list):
                        for v in value:
                            attribute_index[f"{key}:{v}"].add(entity_id)
                    else:
                        attribute_index[f"{key}:{value}"].add(entity_id)

        # Find shared attributes (2+ entities)
        shared = {
            attr: list(entity_ids)
            for attr, entity_ids in attribute_index.items()
            if len(entity_ids) >= 2
        }

        return shared

    def _cluster_entities(self, entities: List[Dict[str, Any]],
                         relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cluster entities using graph-based community detection"""
        # Build adjacency graph
        graph = defaultdict(set)

        for rel in relationships:
            if rel['score'] >= self.min_correlation_score:
                source = rel['source_entity']
                target = rel['target_entity']
                graph[source].add(target)
                graph[target].add(source)

        # Simple connected components clustering
        visited = set()
        clusters = []

        def dfs(node, cluster):
            visited.add(node)
            cluster.add(node)
            for neighbor in graph[node]:
                if neighbor not in visited:
                    dfs(neighbor, cluster)

        for entity in entities:
            entity_id = entity['entity_id']
            if entity_id not in visited:
                cluster = set()
                dfs(entity_id, cluster)
                if len(cluster) >= 2:  # Only clusters with 2+ entities
                    clusters.append({
                        'cluster_id': hashlib.md5(str(sorted(cluster)).encode()).hexdigest()[:8],
                        'entities': list(cluster),
                        'size': len(cluster)
                    })

        return clusters

    def _cross_source_correlation(self, entities: List[Dict[str, Any]],
                                  sources: List[Any]) -> Dict[str, Any]:
        """Validate correlations across multiple sources"""
        validation = {
            'multi_source_entities': [],
            'single_source_entities': [],
            'corroboration_score': 0.0
        }

        for entity in entities:
            source_id = entity.get('source_id', '')
            source_count = len(source_id.split('+'))  # Merged entities have "+" separator

            if source_count >= 2:
                validation['multi_source_entities'].append({
                    'entity_id': entity['entity_id'],
                    'source_count': source_count,
                    'identifier': entity['primary_identifier']
                })
            else:
                validation['single_source_entities'].append(entity['entity_id'])

        # Calculate overall corroboration score
        total_entities = len(entities)
        if total_entities > 0:
            multi_source_count = len(validation['multi_source_entities'])
            validation['corroboration_score'] = multi_source_count / total_entities

        return validation

    def _determine_relationship_type(self, entity1: Dict[str, Any],
                                    entity2: Dict[str, Any]) -> str:
        """Determine the type of relationship between entities"""
        attrs1 = entity1.get('attributes', {})
        attrs2 = entity2.get('attributes', {})

        # Same person with multiple identifiers
        if entity1['type'] == entity2['type'] == 'person':
            return 'alias'

        # Email to wallet (ownership)
        if (entity1['type'] == 'email' and entity2['type'] == 'wallet') or \
           (entity2['type'] == 'email' and entity1['type'] == 'wallet'):
            return 'owns'

        # Same location (associates)
        if attrs1.get('location') and attrs1.get('location') == attrs2.get('location'):
            return 'associates'

        # Same organization
        if attrs1.get('organization') and attrs1.get('organization') == attrs2.get('organization'):
            return 'colleague'

        return 'related'

    def _collect_evidence(self, entity1: Dict[str, Any],
                         entity2: Dict[str, Any]) -> List[str]:
        """Collect evidence supporting the correlation"""
        evidence = []

        attrs1 = entity1.get('attributes', {})
        attrs2 = entity2.get('attributes', {})

        # Check for shared attributes
        for key in set(attrs1.keys()).intersection(set(attrs2.keys())):
            if attrs1[key] == attrs2[key]:
                evidence.append(f"Shared {key}: {attrs1[key]}")

        # Check for alias overlap
        aliases1 = set(entity1.get('aliases', []))
        aliases2 = set(entity2.get('aliases', []))
        shared_aliases = aliases1.intersection(aliases2)
        if shared_aliases:
            evidence.append(f"Shared aliases: {', '.join(shared_aliases)}")

        return evidence

    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance"""
        from difflib import SequenceMatcher
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

    def find_shortest_path(self, entity1_id: str, entity2_id: str,
                          relationships: List[Dict[str, Any]]) -> List[str]:
        """Find shortest path between two entities in relationship graph"""
        # Build adjacency graph
        graph = defaultdict(list)
        for rel in relationships:
            graph[rel['source_entity']].append(rel['target_entity'])
            graph[rel['target_entity']].append(rel['source_entity'])

        # BFS to find shortest path
        from collections import deque

        queue = deque([(entity1_id, [entity1_id])])
        visited = {entity1_id}

        while queue:
            current, path = queue.popleft()

            if current == entity2_id:
                return path

            for neighbor in graph[current]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return []  # No path found

    def calculate_network_centrality(self, entities: List[Dict[str, Any]],
                                    relationships: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate centrality scores for entities in the network"""
        centrality = {}

        # Degree centrality (number of connections)
        connection_count = defaultdict(int)
        for rel in relationships:
            connection_count[rel['source_entity']] += 1
            connection_count[rel['target_entity']] += 1

        # Normalize
        max_connections = max(connection_count.values()) if connection_count else 1

        for entity in entities:
            entity_id = entity['entity_id']
            centrality[entity_id] = connection_count[entity_id] / max_connections

        return centrality
