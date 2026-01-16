#!/usr/bin/env python3
"""
Intelligence Fusion Engine - Comprehensive Test Suite
Tests all components of the fusion engine
"""

import unittest
from datetime import datetime, timedelta
from fusion_engine import IntelligenceFusion, IntelligenceSource, EntityProfile
from entity_resolver import EntityResolver
from correlation_algorithm import CorrelationEngine
from confidence_scorer import ConfidenceScorer
from risk_assessor import RiskAssessor
from timeline_builder import TimelineBuilder
from graph_analyzer import GraphAnalyzer


class TestEntityResolver(unittest.TestCase):
    """Test Entity Resolution functionality"""

    def setUp(self):
        self.resolver = EntityResolver({
            'fuzzy_threshold': 0.85,
            'email_exact_match': True,
            'phone_normalize': True
        })

    def test_email_normalization(self):
        """Test email entity creation and normalization"""
        source_id = "test_source_1"
        data = {
            'email': 'Test.User@Example.COM',
            'name': 'Test User'
        }

        entity = self.resolver._create_entity_from_email(data, source_id)

        self.assertIsNotNone(entity)
        self.assertEqual(entity.attributes['email'], 'test.user@example.com')
        self.assertEqual(entity.type, 'email')

    def test_phone_normalization(self):
        """Test phone number normalization"""
        phone = '+1 (555) 123-4567'
        normalized = self.resolver._normalize_phone(phone)

        self.assertTrue(normalized.startswith('+'))

    def test_fuzzy_name_matching(self):
        """Test fuzzy name matching"""
        name1 = "John Smith"
        name2 = "Jon Smith"

        matches = self.resolver._names_match(name1, name2)
        self.assertTrue(matches)

    def test_entity_deduplication(self):
        """Test entity deduplication"""
        entities = [
            {
                'entity_id': '1',
                'type': 'email',
                'attributes': {'email': 'test@example.com'},
                'aliases': [],
                'source_id': 's1',
                'confidence': 0.9
            },
            {
                'entity_id': '2',
                'type': 'email',
                'attributes': {'email': 'test@example.com'},
                'aliases': [],
                'source_id': 's2',
                'confidence': 0.85
            }
        ]

        # Convert to ResolvedEntity objects
        from entity_resolver import ResolvedEntity
        resolved_entities = [
            ResolvedEntity(**e) for e in entities
        ]

        deduplicated = self.resolver._deduplicate_emails(resolved_entities)

        self.assertEqual(len(deduplicated), 1)
        self.assertGreater(deduplicated[0].confidence, 0.9)


class TestCorrelationEngine(unittest.TestCase):
    """Test Correlation Engine functionality"""

    def setUp(self):
        self.correlator = CorrelationEngine({
            'min_correlation_score': 0.6,
            'time_window_days': 365,
            'max_graph_depth': 3
        })

    def test_entity_correlation(self):
        """Test correlation between entities"""
        entity1 = {
            'entity_id': 'e1',
            'type': 'email',
            'attributes': {
                'email': 'user@example.com',
                'location': 'New York'
            },
            'aliases': ['user1']
        }

        entity2 = {
            'entity_id': 'e2',
            'type': 'phone',
            'attributes': {
                'phone': '+1555123456',
                'location': 'New York'
            },
            'aliases': ['user1']
        }

        score = self.correlator._calculate_entity_correlation(entity1, entity2)

        self.assertGreater(score, 0.5)  # Should correlate on location and alias

    def test_temporal_correlation(self):
        """Test temporal correlation"""
        now = datetime.now()

        sources = [
            type('Source', (), {
                'source_id': 's1',
                'timestamp': now,
                'source_type': 'osint',
                'data': {}
            })(),
            type('Source', (), {
                'source_id': 's2',
                'timestamp': now + timedelta(days=10),
                'source_type': 'breach',
                'data': {}
            })()
        ]

        correlations = self.correlator._correlate_temporal(sources)

        self.assertGreater(len(correlations), 0)

    def test_shortest_path(self):
        """Test shortest path finding"""
        relationships = [
            {'source_entity': 'A', 'target_entity': 'B', 'score': 0.9},
            {'source_entity': 'B', 'target_entity': 'C', 'score': 0.8},
            {'source_entity': 'A', 'target_entity': 'D', 'score': 0.7},
            {'source_entity': 'D', 'target_entity': 'C', 'score': 0.6}
        ]

        path = self.correlator.find_shortest_path('A', 'C', relationships)

        self.assertIsNotNone(path)
        self.assertEqual(path[0], 'A')
        self.assertEqual(path[-1], 'C')


class TestConfidenceScorer(unittest.TestCase):
    """Test Confidence Scoring functionality"""

    def setUp(self):
        self.scorer = ConfidenceScorer({
            'source_weights': {
                'blockchain': 0.95,
                'breach': 0.85,
                'osint': 0.70
            },
            'freshness_decay_days': 180,
            'corroboration_bonus': 0.15,
            'conflict_penalty': 0.20
        })

    def test_source_reliability(self):
        """Test source reliability calculation"""
        sources = [
            type('Source', (), {
                'source_type': 'blockchain',
                'reliability': 0.95,
                'timestamp': datetime.now(),
                'data': {}
            })(),
            type('Source', (), {
                'source_type': 'osint',
                'reliability': 0.70,
                'timestamp': datetime.now(),
                'data': {}
            })()
        ]

        reliability = self.scorer._calculate_source_reliability(sources)

        self.assertGreater(reliability, 0.7)
        self.assertLess(reliability, 1.0)

    def test_freshness_calculation(self):
        """Test data freshness scoring"""
        recent = datetime.now()
        old = datetime.now() - timedelta(days=365)

        sources = [
            type('Source', (), {
                'source_type': 'osint',
                'timestamp': recent,
                'data': {}
            })(),
            type('Source', (), {
                'source_type': 'breach',
                'timestamp': old,
                'data': {}
            })()
        ]

        freshness = self.scorer._calculate_freshness(sources)

        self.assertGreater(freshness, 0.0)
        self.assertLessEqual(freshness, 1.0)

    def test_attribute_confidence(self):
        """Test per-attribute confidence scoring"""
        sources = [
            type('Source', (), {
                'source_type': 'blockchain',
                'timestamp': datetime.now(),
                'data': {'email': 'test@example.com'}
            })(),
            type('Source', (), {
                'source_type': 'breach',
                'timestamp': datetime.now(),
                'data': {'email': 'test@example.com'}
            })()
        ]

        confidence = self.scorer.calculate_attribute_confidence(
            'email',
            'test@example.com',
            sources
        )

        self.assertGreater(confidence, 50)  # Multi-source should boost confidence


class TestRiskAssessor(unittest.TestCase):
    """Test Risk Assessment functionality"""

    def setUp(self):
        self.assessor = RiskAssessor({
            'high_threshold': 75,
            'medium_threshold': 50,
            'low_threshold': 25
        })

    def test_breach_risk_calculation(self):
        """Test breach exposure risk"""
        profile = type('Profile', (), {
            'sources': ['breach_1', 'breach_2', 'breach_3'],
            'attributes': {'password_hash': 'abc123'},
            'metadata': {'patterns': []}
        })()

        risk = self.assessor._calculate_breach_risk(profile)

        self.assertGreater(risk, 0.5)  # Multiple breaches = high risk

    def test_behavioral_risk(self):
        """Test behavioral pattern risk"""
        profile = type('Profile', (), {
            'sources': ['osint'],
            'attributes': {},
            'metadata': {
                'patterns': [
                    {
                        'type': 'multiple_aliases',
                        'severity': 'high',
                        'count': 5
                    },
                    {
                        'type': 'repeated_breaches',
                        'severity': 'high',
                        'count': 4
                    }
                ]
            }
        })()

        risk = self.assessor._calculate_behavioral_risk(profile)

        self.assertGreater(risk, 0.3)

    def test_risk_categorization(self):
        """Test risk score categorization"""
        self.assertEqual(self.assessor.categorize_risk(95), 'CRITICAL')
        self.assertEqual(self.assessor.categorize_risk(80), 'HIGH')
        self.assertEqual(self.assessor.categorize_risk(60), 'MEDIUM')
        self.assertEqual(self.assessor.categorize_risk(30), 'LOW')
        self.assertEqual(self.assessor.categorize_risk(10), 'MINIMAL')


class TestTimelineBuilder(unittest.TestCase):
    """Test Timeline Builder functionality"""

    def setUp(self):
        self.builder = TimelineBuilder({
            'max_gap_days': 30,
            'min_events': 2
        })

    def test_event_extraction(self):
        """Test event extraction from sources"""
        source = type('Source', (), {
            'source_id': 's1',
            'source_type': 'breach',
            'timestamp': datetime.now(),
            'data': {
                'breach': 'LinkedIn2021',
                'email': 'test@example.com',
                'password': 'hash123'
            }
        })()

        profile = type('Profile', (), {
            'entity_id': 'e1'
        })()

        events = self.builder._extract_events(source, profile)

        self.assertGreater(len(events), 0)
        self.assertEqual(events[0]['type'], 'breach')

    def test_event_sorting(self):
        """Test chronological event sorting"""
        now = datetime.now()

        events = [
            {'timestamp': (now + timedelta(days=2)).isoformat(), 'description': 'Event 2'},
            {'timestamp': now.isoformat(), 'description': 'Event 0'},
            {'timestamp': (now + timedelta(days=1)).isoformat(), 'description': 'Event 1'}
        ]

        sorted_events = self.builder._sort_events(events)

        self.assertEqual(sorted_events[0]['description'], 'Event 0')
        self.assertEqual(sorted_events[1]['description'], 'Event 1')
        self.assertEqual(sorted_events[2]['description'], 'Event 2')

    def test_gap_identification(self):
        """Test timeline gap identification"""
        now = datetime.now()

        events = [
            {'timestamp': now.isoformat(), 'description': 'Event 1'},
            {'timestamp': (now + timedelta(days=60)).isoformat(), 'description': 'Event 2'}
        ]

        enhanced = self.builder._identify_gaps(events)

        # Should have original events + gap marker
        gap_events = [e for e in enhanced if e.get('type') == 'gap']
        self.assertGreater(len(gap_events), 0)


class TestGraphAnalyzer(unittest.TestCase):
    """Test Graph Analysis functionality"""

    def setUp(self):
        self.analyzer = GraphAnalyzer({
            'neo4j_enabled': False
        })

    def test_centrality_calculations(self):
        """Test centrality measure calculations"""
        # Build simple graph
        self.analyzer.nodes = {
            'A': {'id': 'A', 'type': 'person'},
            'B': {'id': 'B', 'type': 'person'},
            'C': {'id': 'C', 'type': 'person'}
        }

        self.analyzer.graph = {
            'A': [{'target': 'B', 'weight': 1.0}, {'target': 'C', 'weight': 1.0}],
            'B': [{'target': 'A', 'weight': 1.0}, {'target': 'C', 'weight': 1.0}],
            'C': [{'target': 'A', 'weight': 1.0}, {'target': 'B', 'weight': 1.0}]
        }

        centrality = self.analyzer._calculate_centrality('A')

        self.assertIn('degree', centrality)
        self.assertIn('betweenness', centrality)
        self.assertIn('closeness', centrality)
        self.assertGreater(centrality['degree'], 0)

    def test_community_detection(self):
        """Test community detection"""
        # Build graph with two clusters
        self.analyzer.nodes = {
            'A': {'id': 'A'},
            'B': {'id': 'B'},
            'C': {'id': 'C'},
            'D': {'id': 'D'}
        }

        self.analyzer.graph = {
            'A': [{'target': 'B', 'weight': 1.0}],
            'B': [{'target': 'A', 'weight': 1.0}],
            'C': [{'target': 'D', 'weight': 1.0}],
            'D': [{'target': 'C', 'weight': 1.0}]
        }

        communities = self.analyzer._detect_communities()

        self.assertGreaterEqual(len(communities), 1)

    def test_influence_calculation(self):
        """Test influence score calculation"""
        self.analyzer.nodes = {
            'A': {'id': 'A'},
            'B': {'id': 'B'}
        }

        self.analyzer.graph = {
            'A': [{'target': 'B', 'weight': 1.0}],
            'B': [{'target': 'A', 'weight': 1.0}]
        }

        influence = self.analyzer._calculate_influence('A')

        self.assertGreaterEqual(influence, 0.0)
        self.assertLessEqual(influence, 100.0)


class TestIntelligenceFusion(unittest.TestCase):
    """Test complete Intelligence Fusion workflow"""

    def setUp(self):
        self.fusion = IntelligenceFusion()

    def test_intelligence_ingestion(self):
        """Test intelligence ingestion"""
        source_id = self.fusion.ingest_intelligence({
            'email': 'test@example.com',
            'name': 'Test User'
        }, 'osint')

        self.assertIsNotNone(source_id)
        self.assertEqual(len(self.fusion.raw_intelligence), 1)

    def test_profile_building(self):
        """Test complete profile building"""
        # Ingest multiple sources
        self.fusion.ingest_intelligence({
            'email': 'test@example.com',
            'name': 'Test User',
            'location': 'Test City'
        }, 'osint')

        self.fusion.ingest_intelligence({
            'email': 'test@example.com',
            'breach': 'TestBreach',
            'password_hash': 'abc123'
        }, 'breach')

        # Build profile
        profile = self.fusion.build_profile(
            target='test@example.com',
            deep_analysis=False
        )

        self.assertIsNotNone(profile)
        self.assertEqual(profile.entity_type, 'email')
        self.assertGreater(profile.confidence_score, 0)
        self.assertGreater(profile.risk_score, 0)

    def test_report_generation(self):
        """Test report generation"""
        # Ingest and build profile
        self.fusion.ingest_intelligence({
            'email': 'test@example.com',
            'name': 'Test User'
        }, 'osint')

        profile = self.fusion.build_profile('test@example.com')

        # Generate reports
        json_report = self.fusion.generate_intelligence_report(
            profile.entity_id,
            format='json'
        )

        markdown_report = self.fusion.generate_intelligence_report(
            profile.entity_id,
            format='markdown'
        )

        self.assertIsNotNone(json_report)
        self.assertIsNotNone(markdown_report)
        self.assertIn('Test User', markdown_report)


def run_tests():
    """Run all tests"""
    print("=" * 70)
    print("INTELLIGENCE FUSION ENGINE - TEST SUITE")
    print("=" * 70)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestEntityResolver))
    suite.addTests(loader.loadTestsFromTestCase(TestCorrelationEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestConfidenceScorer))
    suite.addTests(loader.loadTestsFromTestCase(TestRiskAssessor))
    suite.addTests(loader.loadTestsFromTestCase(TestTimelineBuilder))
    suite.addTests(loader.loadTestsFromTestCase(TestGraphAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelligenceFusion))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run:    {result.testsRun}")
    print(f"Successes:    {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:     {len(result.failures)}")
    print(f"Errors:       {len(result.errors)}")

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
