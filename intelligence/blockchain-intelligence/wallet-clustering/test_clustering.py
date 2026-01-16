"""
Wallet Clustering System - Test Suite
Comprehensive tests for all clustering components
"""

import unittest
from datetime import datetime

from wallet_clustering import WalletClusterer, AddressCluster, ClusterLink
from common_input_heuristic import CommonInputHeuristic
from change_address_detector import ChangeAddressDetector
from peel_chain_analyzer import PeelChainAnalyzer
from entity_attribution import EntityAttributor, KnownEntity
from cluster_visualizer import ClusterVisualizer
from mixing_detector import MixingDetector
from exchange_identifier import ExchangeIdentifier


class TestWalletClusterer(unittest.TestCase):
    """Test main wallet clustering engine"""

    def setUp(self):
        self.clusterer = WalletClusterer()

    def test_cluster_creation(self):
        """Test basic cluster creation"""
        result = self.clusterer.analyze_wallet("1TestAddr123", depth=1)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.cluster)
        self.assertGreater(len(result.cluster.addresses), 0)
        self.assertIsNotNone(result.cluster.cluster_id)

    def test_cluster_merging(self):
        """Test cluster merging"""
        result1 = self.clusterer.analyze_wallet("1Addr1", depth=1)
        result2 = self.clusterer.analyze_wallet("1Addr2", depth=1)

        cluster_id1 = result1.cluster.cluster_id
        cluster_id2 = result2.cluster.cluster_id

        evidence = {'type': 'test', 'confidence': 0.9}
        merged_id = self.clusterer.merge_clusters(cluster_id1, cluster_id2, evidence)

        self.assertIn(merged_id, self.clusterer.clusters)
        self.assertNotIn(cluster_id2, self.clusterer.clusters)

    def test_cluster_expansion(self):
        """Test cluster expansion"""
        result = self.clusterer.analyze_wallet("1TestExpand", depth=1)
        cluster_id = result.cluster.cluster_id

        original_size = len(result.cluster.addresses)
        new_addresses = self.clusterer.expand_cluster(cluster_id, depth=1)

        self.assertIsInstance(new_addresses, set)
        # After expansion, cluster should have at least original addresses
        self.assertGreaterEqual(
            len(self.clusterer.clusters[cluster_id].addresses),
            original_size
        )

    def test_risk_scoring(self):
        """Test risk score calculation"""
        result = self.clusterer.analyze_wallet("1RiskTest", depth=1)

        self.assertIn('total_risk_score', result.risk_assessment)
        self.assertIn('risk_level', result.risk_assessment)
        self.assertGreaterEqual(result.risk_assessment['total_risk_score'], 0.0)
        self.assertLessEqual(result.risk_assessment['total_risk_score'], 1.0)


class TestCommonInputHeuristic(unittest.TestCase):
    """Test Common Input Heuristic"""

    def setUp(self):
        self.cih = CommonInputHeuristic()

    def test_address_analysis(self):
        """Test CIH address analysis"""
        result = self.cih.analyze_address("1TestCIH", depth=2)

        self.assertIn('source_address', result)
        self.assertIn('related_addresses', result)
        self.assertIn('total_related', result)
        self.assertEqual(result['source_address'], "1TestCIH")

    def test_cluster_expansion(self):
        """Test CIH cluster expansion"""
        initial_addresses = {"1Addr1", "1Addr2"}
        expanded = self.cih.expand_cluster(initial_addresses, iterations=1)

        self.assertIsInstance(expanded, set)
        # Should at least contain original addresses
        self.assertTrue(initial_addresses.issubset(expanded))

    def test_confidence_calculation(self):
        """Test cluster confidence calculation"""
        addresses = {"1Addr1", "1Addr2", "1Addr3"}
        confidence = self.cih.calculate_cluster_confidence(addresses)

        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)


class TestChangeAddressDetector(unittest.TestCase):
    """Test change address detection"""

    def setUp(self):
        self.detector = ChangeAddressDetector()

    def test_transaction_analysis(self):
        """Test transaction analysis for change"""
        result = self.detector.analyze_transactions("1ChangeTest", depth=2)

        self.assertIn('source_address', result)
        self.assertIn('change_addresses', result)
        self.assertIn('total_transactions_analyzed', result)

    def test_round_number_detection(self):
        """Test round number heuristic"""
        self.assertTrue(self.detector._is_round_number(0.01))
        self.assertTrue(self.detector._is_round_number(1.0))
        self.assertFalse(self.detector._is_round_number(0.01337))

    def test_script_type_detection(self):
        """Test script type detection"""
        self.assertEqual(self.detector._get_address_script_type("1Addr"), "P2PKH")
        self.assertEqual(self.detector._get_address_script_type("3Addr"), "P2SH")
        self.assertEqual(self.detector._get_address_script_type("bc1q"), "P2WPKH")

    def test_statistics(self):
        """Test detector statistics"""
        # Analyze some addresses
        self.detector.analyze_transactions("1Stats", depth=1)

        stats = self.detector.get_statistics()
        self.assertIn('total_addresses_seen', stats)
        self.assertIn('one_time_addresses', stats)
        self.assertIn('reuse_rate', stats)


class TestPeelChainAnalyzer(unittest.TestCase):
    """Test peel chain detection"""

    def setUp(self):
        self.analyzer = PeelChainAnalyzer()

    def test_peel_chain_detection(self):
        """Test peel chain detection"""
        result = self.analyzer.analyze_address("1PeelTest", depth=5)

        self.assertIn('is_peel_chain', result)
        self.assertIn('chains', result)
        self.assertIn('risk_score', result)
        self.assertIn('indicators', result)

    def test_layering_detection(self):
        """Test layering activity detection"""
        addresses = ["1Layer1", "1Layer2", "1Layer3"]
        result = self.analyzer.detect_layering_activity(addresses)

        self.assertIn('is_layering_detected', result)
        self.assertIn('total_peel_chains', result)
        self.assertIn('risk_level', result)


class TestEntityAttributor(unittest.TestCase):
    """Test entity attribution"""

    def setUp(self):
        self.attributor = EntityAttributor()

    def test_entity_database(self):
        """Test entity database initialization"""
        stats = self.attributor.get_statistics()

        self.assertGreater(stats['total_entities'], 0)
        self.assertIn('by_type', stats)
        self.assertIn('by_reputation', stats)

    def test_add_entity(self):
        """Test adding custom entity"""
        entity = KnownEntity(
            entity_id="test_entity",
            name="Test Entity",
            entity_type="test",
            addresses={"1Test1", "1Test2"}
        )

        initial_count = len(self.attributor.known_entities)
        self.attributor.add_known_entity(entity)

        self.assertEqual(len(self.attributor.known_entities), initial_count + 1)
        self.assertIn("test_entity", self.attributor.known_entities)

    def test_search_entities(self):
        """Test entity search"""
        results = self.attributor.search_entities("exchange")

        self.assertIsInstance(results, list)
        # Should find exchanges in default database
        self.assertGreater(len(results), 0)

    def test_get_entity_info(self):
        """Test getting entity information"""
        # Binance should be in default database
        info = self.attributor.get_entity_info("binance")

        if info:  # If entity exists
            self.assertIn('exchange_name', info)
            self.assertIn('reputation', info)


class TestClusterVisualizer(unittest.TestCase):
    """Test cluster visualization"""

    def setUp(self):
        self.visualizer = ClusterVisualizer()
        # Create a simple cluster for testing
        self.cluster = AddressCluster(
            cluster_id="test_cluster",
            addresses={"1Addr1", "1Addr2", "1Addr3"},
            risk_score=0.5
        )
        self.links = [
            ClusterLink(
                source="1Addr1",
                target="1Addr2",
                link_type="common_input",
                confidence=0.8
            )
        ]

    def test_visualization_creation(self):
        """Test visualization data creation"""
        viz_data = self.visualizer.visualize_cluster(self.cluster, self.links)

        self.assertIn('cluster_id', viz_data)
        self.assertIn('nodes', viz_data)
        self.assertIn('edges', viz_data)
        self.assertIn('metadata', viz_data)

    def test_risk_heatmap(self):
        """Test risk heatmap creation"""
        clusters = [self.cluster]
        heatmap = self.visualizer.create_risk_heatmap(clusters)

        self.assertIn('clusters', heatmap)
        self.assertIn('risk_distribution', heatmap)


class TestMixingDetector(unittest.TestCase):
    """Test mixing service detection"""

    def setUp(self):
        self.detector = MixingDetector()

    def test_mixing_detection(self):
        """Test basic mixing detection"""
        addresses = ["1Mix1", "1Mix2"]
        result = self.detector.detect_mixing(addresses)

        self.assertIn('detected', result)
        self.assertIn('confidence', result)
        self.assertIn('indicators', result)

    def test_coinjoin_detection(self):
        """Test CoinJoin detection"""
        # Create CoinJoin-like transaction
        coinjoin_tx = {
            'hash': 'test_coinjoin',
            'inputs': [f"1In{i}" for i in range(10)],
            'outputs': [
                {'address': f"1Out{i}", 'value': 0.1}
                for i in range(10)
            ],
            'total_input': 1.0,
            'fee': 0.001
        }

        result = self.detector.detect_coinjoin(coinjoin_tx)

        self.assertIn('is_coinjoin', result)
        self.assertIn('confidence', result)

    def test_equal_output_detection(self):
        """Test equal output detection"""
        values = [0.1, 0.1, 0.1, 0.2, 0.3]
        equal_outputs = self.detector._find_equal_outputs(values)

        self.assertIn(0.1, equal_outputs)  # Should find 0.1 as equal


class TestExchangeIdentifier(unittest.TestCase):
    """Test exchange identification"""

    def setUp(self):
        self.identifier = ExchangeIdentifier()

    def test_exchange_database(self):
        """Test exchange database initialization"""
        stats = self.identifier.get_statistics()

        self.assertGreater(stats['total_exchanges'], 0)
        self.assertIn('by_reputation', stats)

    def test_search_exchanges(self):
        """Test exchange search"""
        results = self.identifier.search_exchanges("binance")

        self.assertIsInstance(results, list)
        # Should find Binance
        self.assertGreater(len(results), 0)

    def test_hot_wallet_detection(self):
        """Test hot wallet detection"""
        result = self.identifier.detect_hot_wallet("1HotWallet")

        self.assertIn('is_hot_wallet', result)
        self.assertIn('confidence', result)

    def test_cold_storage_detection(self):
        """Test cold storage detection"""
        result = self.identifier.detect_cold_storage("1ColdStorage")

        self.assertIn('is_cold_storage', result)
        self.assertIn('confidence', result)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestWalletClusterer))
    suite.addTests(loader.loadTestsFromTestCase(TestCommonInputHeuristic))
    suite.addTests(loader.loadTestsFromTestCase(TestChangeAddressDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestPeelChainAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestEntityAttributor))
    suite.addTests(loader.loadTestsFromTestCase(TestClusterVisualizer))
    suite.addTests(loader.loadTestsFromTestCase(TestMixingDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestExchangeIdentifier))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 80)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
