"""
Predictive Analytics - Network Growth Prediction
Apollo Platform v0.1.0

Predict how criminal networks will evolve over time.
Models network growth, member recruitment, and structural changes.
"""

import networkx as nx
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class NetworkGrowthPredictor:
    """
    Predict how criminal network will evolve.

    Models:
    - Preferential attachment (rich get richer)
    - Community-based growth (clustering)
    - Hierarchical growth (organizational structure)
    """

    def __init__(self):
        """Initialize network growth predictor."""
        self.growth_models = {
            'preferential_attachment': self._preferential_attachment_model,
            'community_based': self._community_based_growth,
            'hierarchical': self._hierarchical_growth
        }

        self.historical_networks = []

        logger.info("Initialized NetworkGrowthPredictor")

    def train(
        self,
        historical_networks: List[nx.Graph],
        timestamps: List[datetime]
    ) -> Dict:
        """
        Train on historical network snapshots.

        Args:
            historical_networks: List of network graphs over time
            timestamps: Timestamps for each snapshot

        Returns:
            Training metrics
        """
        logger.info(f"Training on {len(historical_networks)} historical snapshots")

        self.historical_networks = historical_networks
        self.timestamps = timestamps

        # Analyze growth patterns
        growth_stats = self._analyze_growth_patterns()

        logger.info(f"Growth analysis: {growth_stats}")

        return growth_stats

    def _analyze_growth_patterns(self) -> Dict:
        """Analyze historical growth patterns."""
        if len(self.historical_networks) < 2:
            return {}

        # Calculate growth rates
        growth_rates = []
        for i in range(1, len(self.historical_networks)):
            prev_size = self.historical_networks[i-1].number_of_nodes()
            curr_size = self.historical_networks[i].number_of_nodes()

            if prev_size > 0:
                growth_rate = (curr_size - prev_size) / prev_size
                growth_rates.append(growth_rate)

        return {
            'mean_growth_rate': np.mean(growth_rates) if growth_rates else 0,
            'std_growth_rate': np.std(growth_rates) if growth_rates else 0,
            'max_size': max(G.number_of_nodes() for G in self.historical_networks),
            'avg_degree': np.mean([
                np.mean([d for n, d in G.degree()])
                for G in self.historical_networks
            ])
        }

    def predict_network_evolution(
        self,
        current_network: nx.Graph,
        time_periods: int = 12,
        growth_model: str = 'preferential_attachment'
    ) -> Dict:
        """
        Predict network changes over time.

        Args:
            current_network: Current network state
            time_periods: Number of time periods to predict
            growth_model: Growth model to use

        Returns:
            Evolution predictions
        """
        logger.info(
            f"Predicting network evolution for {time_periods} periods "
            f"using {growth_model} model"
        )

        G = current_network.copy()
        predictions = []

        for period in range(time_periods):
            # Predict new members
            new_members = self._predict_new_members(G, period)

            # Predict new connections
            new_connections = self._predict_new_connections(G, new_members, growth_model)

            # Predict departures
            departures = self._predict_departures(G)

            # Update network
            G = self._update_network(G, new_members, new_connections, departures)

            # Analyze current state
            key_players = self._identify_key_players(G)
            vulnerabilities = self._identify_vulnerabilities(G)
            communities = self._detect_communities(G)

            predictions.append({
                'period': period + 1,
                'network_size': G.number_of_nodes(),
                'edge_count': G.number_of_edges(),
                'new_members': new_members,
                'new_connections': new_connections,
                'departures': departures,
                'key_players': key_players,
                'vulnerabilities': vulnerabilities,
                'communities': communities,
                'density': nx.density(G),
                'avg_clustering': nx.average_clustering(G) if G.number_of_nodes() > 0 else 0
            })

        # Identify critical intervention points
        intervention_points = self._identify_intervention_points(predictions)

        # Assess network resilience
        resilience = self._assess_network_resilience(G)

        return {
            'evolution_timeline': predictions,
            'final_network_size': G.number_of_nodes(),
            'growth_trajectory': [p['network_size'] for p in predictions],
            'critical_nodes': self._predict_critical_nodes(predictions),
            'intervention_opportunities': intervention_points,
            'network_resilience': resilience,
            'predicted_structure': self._characterize_structure(G)
        }

    def _predict_new_members(
        self,
        G: nx.Graph,
        period: int
    ) -> List[str]:
        """Predict new member recruitment."""
        # Base growth rate from historical data
        if hasattr(self, 'historical_networks') and len(self.historical_networks) > 1:
            growth_stats = self._analyze_growth_patterns()
            growth_rate = growth_stats.get('mean_growth_rate', 0.05)
        else:
            growth_rate = 0.05

        # Calculate expected new members
        current_size = G.number_of_nodes()
        expected_new = int(current_size * growth_rate)

        # Add randomness
        new_count = max(0, int(np.random.poisson(expected_new)))

        # Generate member IDs
        new_members = [f"NEW_MEMBER_{period}_{i}" for i in range(new_count)]

        return new_members

    def _predict_new_connections(
        self,
        G: nx.Graph,
        new_members: List[str],
        growth_model: str
    ) -> List[Tuple[str, str]]:
        """Predict how new members connect."""
        model_func = self.growth_models.get(
            growth_model,
            self._preferential_attachment_model
        )

        return model_func(G, new_members)

    def _preferential_attachment_model(
        self,
        G: nx.Graph,
        new_members: List[str]
    ) -> List[Tuple[str, str]]:
        """Preferential attachment: connect to high-degree nodes."""
        connections = []
        existing_nodes = list(G.nodes())

        if len(existing_nodes) == 0:
            return connections

        # Calculate connection probabilities based on degree
        degrees = dict(G.degree())
        total_degree = sum(degrees.values()) + len(existing_nodes)  # +1 for each node

        for new_member in new_members:
            # Each new member makes 2-4 connections
            num_connections = np.random.randint(2, 5)

            # Select nodes preferentially
            probs = [
                (degrees.get(node, 0) + 1) / total_degree
                for node in existing_nodes
            ]
            probs = np.array(probs) / sum(probs)

            targets = np.random.choice(
                existing_nodes,
                size=min(num_connections, len(existing_nodes)),
                replace=False,
                p=probs
            )

            for target in targets:
                connections.append((new_member, target))

        return connections

    def _community_based_growth(
        self,
        G: nx.Graph,
        new_members: List[str]
    ) -> List[Tuple[str, str]]:
        """Community-based growth: join existing communities."""
        from networkx.algorithms import community

        connections = []

        # Detect communities
        try:
            communities = community.greedy_modularity_communities(G)
        except:
            return self._preferential_attachment_model(G, new_members)

        for new_member in new_members:
            # Join a community
            if len(communities) > 0:
                target_community = communities[np.random.randint(len(communities))]
                community_members = list(target_community)

                # Connect to 2-3 members
                num_connections = min(np.random.randint(2, 4), len(community_members))
                targets = np.random.choice(community_members, num_connections, replace=False)

                for target in targets:
                    connections.append((new_member, target))

        return connections

    def _hierarchical_growth(
        self,
        G: nx.Graph,
        new_members: List[str]
    ) -> List[Tuple[str, str]]:
        """Hierarchical growth: connect to leadership."""
        connections = []

        # Identify leaders (high betweenness centrality)
        if G.number_of_nodes() > 0:
            centrality = nx.betweenness_centrality(G)
            leaders = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
            leader_nodes = [node for node, _ in leaders]

            for new_member in new_members:
                # Connect to 1-2 leaders
                num_leaders = min(np.random.randint(1, 3), len(leader_nodes))
                targets = np.random.choice(leader_nodes, num_leaders, replace=False)

                for target in targets:
                    connections.append((new_member, target))

        return connections

    def _predict_departures(self, G: nx.Graph) -> List[str]:
        """Predict member departures (arrests, exits)."""
        # Low departure rate (2-5%)
        departure_rate = np.random.uniform(0.02, 0.05)
        num_departures = int(G.number_of_nodes() * departure_rate)

        # Peripheral members more likely to leave
        if G.number_of_nodes() > 0:
            degrees = dict(G.degree())
            nodes = list(G.nodes())

            # Inverse probability (low degree = higher chance to leave)
            probs = [1.0 / (degrees.get(node, 1) + 1) for node in nodes]
            probs = np.array(probs) / sum(probs)

            departures = np.random.choice(
                nodes,
                size=min(num_departures, len(nodes)),
                replace=False,
                p=probs
            )

            return list(departures)

        return []

    def _update_network(
        self,
        G: nx.Graph,
        new_members: List[str],
        new_connections: List[Tuple[str, str]],
        departures: List[str]
    ) -> nx.Graph:
        """Update network with changes."""
        G_new = G.copy()

        # Add new members
        G_new.add_nodes_from(new_members)

        # Add new connections
        G_new.add_edges_from(new_connections)

        # Remove departures
        G_new.remove_nodes_from(departures)

        return G_new

    def _identify_key_players(self, G: nx.Graph) -> List[Dict]:
        """Identify key players in network."""
        if G.number_of_nodes() == 0:
            return []

        # Calculate centrality metrics
        degree_cent = nx.degree_centrality(G)
        between_cent = nx.betweenness_centrality(G)
        close_cent = nx.closeness_centrality(G)

        # Combine metrics
        key_players = []
        for node in G.nodes():
            importance = (
                degree_cent.get(node, 0) * 0.4 +
                between_cent.get(node, 0) * 0.4 +
                close_cent.get(node, 0) * 0.2
            )

            key_players.append({
                'node': node,
                'importance': importance,
                'degree': G.degree(node),
                'role': self._infer_role(G, node)
            })

        # Return top 10
        key_players.sort(key=lambda x: x['importance'], reverse=True)
        return key_players[:10]

    def _infer_role(self, G: nx.Graph, node: str) -> str:
        """Infer node role in network."""
        degree = G.degree(node)
        betweenness = nx.betweenness_centrality(G).get(node, 0)

        if betweenness > 0.1 and degree > 5:
            return "LEADER"
        elif betweenness > 0.05:
            return "BROKER"
        elif degree > 3:
            return "ACTIVE_MEMBER"
        else:
            return "PERIPHERAL"

    def _identify_vulnerabilities(self, G: nx.Graph) -> List[Dict]:
        """Identify network vulnerabilities."""
        vulnerabilities = []

        if G.number_of_nodes() == 0:
            return vulnerabilities

        # Bridge nodes (whose removal disconnects network)
        bridges = list(nx.bridges(G))
        if bridges:
            vulnerabilities.append({
                'type': 'BRIDGE_NODES',
                'count': len(bridges),
                'severity': 'HIGH',
                'description': f'{len(bridges)} bridge connections found'
            })

        # Cut vertices (whose removal increases components)
        cut_vertices = list(nx.articulation_points(G))
        if cut_vertices:
            vulnerabilities.append({
                'type': 'CUT_VERTICES',
                'nodes': cut_vertices[:5],
                'count': len(cut_vertices),
                'severity': 'CRITICAL',
                'description': f'{len(cut_vertices)} critical nodes found'
            })

        return vulnerabilities

    def _detect_communities(self, G: nx.Graph) -> int:
        """Detect number of communities."""
        try:
            from networkx.algorithms import community
            communities = community.greedy_modularity_communities(G)
            return len(communities)
        except:
            return 0

    def _identify_intervention_points(self, predictions: List[Dict]) -> List[Dict]:
        """Identify optimal intervention points."""
        interventions = []

        for i, pred in enumerate(predictions):
            # Vulnerability-based intervention
            if len(pred['vulnerabilities']) > 0:
                interventions.append({
                    'period': pred['period'],
                    'type': 'VULNERABILITY_EXPLOITATION',
                    'reason': f"{len(pred['vulnerabilities'])} vulnerabilities detected",
                    'effectiveness': 'HIGH'
                })

            # Size-based intervention (before too large)
            if pred['network_size'] > 50 and predictions[i-1]['network_size'] < 50:
                interventions.append({
                    'period': pred['period'],
                    'type': 'SIZE_THRESHOLD',
                    'reason': 'Network reaching critical size',
                    'effectiveness': 'MEDIUM'
                })

        return interventions

    def _assess_network_resilience(self, G: nx.Graph) -> Dict:
        """Assess network resilience to disruption."""
        if G.number_of_nodes() == 0:
            return {'resilience_score': 0, 'rating': 'N/A'}

        # Metrics
        density = nx.density(G)
        avg_clustering = nx.average_clustering(G)

        # Resilience score
        resilience_score = (density + avg_clustering) / 2

        if resilience_score > 0.7:
            rating = "VERY_HIGH"
        elif resilience_score > 0.5:
            rating = "HIGH"
        elif resilience_score > 0.3:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            'resilience_score': float(resilience_score),
            'rating': rating,
            'density': float(density),
            'clustering': float(avg_clustering)
        }

    def _predict_critical_nodes(self, predictions: List[Dict]) -> List[str]:
        """Predict which nodes will become critical."""
        # Nodes that appear consistently as key players
        node_appearances = {}

        for pred in predictions:
            for player in pred['key_players']:
                node = player['node']
                node_appearances[node] = node_appearances.get(node, 0) + 1

        # Sort by appearance frequency
        critical = sorted(
            node_appearances.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [node for node, _ in critical[:10]]

    def _characterize_structure(self, G: nx.Graph) -> str:
        """Characterize network structure."""
        if G.number_of_nodes() == 0:
            return "EMPTY"

        density = nx.density(G)
        avg_clustering = nx.average_clustering(G)

        if density > 0.5:
            return "DENSE_NETWORK"
        elif avg_clustering > 0.5:
            return "CLUSTERED_COMMUNITIES"
        else:
            return "SPARSE_HIERARCHICAL"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create sample network
    G = nx.barabasi_albert_graph(50, 3)

    # Predict evolution
    predictor = NetworkGrowthPredictor()
    prediction = predictor.predict_network_evolution(G, time_periods=12)

    print(f"Network evolution: {len(prediction['evolution_timeline'])} periods")
    print(f"Final size: {prediction['final_network_size']}")
    print(f"Interventions: {prediction['intervention_opportunities']}")
