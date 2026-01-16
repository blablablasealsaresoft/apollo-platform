"""
Cross-Breach Correlation Engine
Correlate data across multiple breach databases
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass
import hashlib
from datetime import datetime
import networkx as nx


@dataclass
class CredentialCluster:
    """Cluster of related credentials"""
    emails: Set[str]
    usernames: Set[str]
    passwords: Set[str]
    ip_addresses: Set[str]
    names: Set[str]
    databases: Set[str]
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'emails': list(self.emails),
            'usernames': list(self.usernames),
            'passwords': list(self.passwords),
            'ip_addresses': list(self.ip_addresses),
            'names': list(self.names),
            'databases': list(self.databases),
            'confidence': self.confidence
        }


class BreachCorrelator:
    """
    Cross-breach correlation engine
    Identifies patterns and relationships across breach databases
    """

    def __init__(self):
        """Initialize breach correlator"""
        self.logger = logging.getLogger(__name__)

    def correlate_records(self, records: List[Any]) -> Dict[str, Any]:
        """
        Correlate breach records to find patterns

        Args:
            records: List of BreachRecord objects

        Returns:
            Correlation results
        """
        self.logger.info(f"Correlating {len(records)} breach records")

        if not records:
            return {}

        # Build correlation graph
        correlation_graph = self._build_correlation_graph(records)

        # Find patterns
        password_reuse = self._find_password_reuse(records)
        related_accounts = self._find_related_accounts(records)
        credential_clusters = self._find_credential_clusters(correlation_graph)
        temporal_patterns = self._analyze_temporal_patterns(records)
        common_passwords = self._find_common_passwords(records)
        username_patterns = self._analyze_username_patterns(records)

        # Generate attack surface
        attack_surface = self._generate_attack_surface(records)

        return {
            'total_records': len(records),
            'password_reuse': password_reuse,
            'related_accounts': related_accounts,
            'credential_clusters': [c.to_dict() for c in credential_clusters],
            'temporal_patterns': temporal_patterns,
            'common_passwords': common_passwords,
            'username_patterns': username_patterns,
            'attack_surface': attack_surface,
            'correlation_strength': self._calculate_correlation_strength(records)
        }

    def _build_correlation_graph(self, records: List[Any]) -> nx.Graph:
        """
        Build graph of correlated entities

        Args:
            records: Breach records

        Returns:
            NetworkX graph
        """
        G = nx.Graph()

        for record in records:
            # Add nodes for each entity
            if record.email:
                G.add_node(f"email:{record.email}", type='email', value=record.email)

            if record.username:
                G.add_node(f"username:{record.username}", type='username', value=record.username)

            if record.password:
                G.add_node(f"password:{record.password}", type='password', value=record.password)

            if record.ip_address:
                G.add_node(f"ip:{record.ip_address}", type='ip', value=record.ip_address)

            # Add edges between related entities
            if record.email and record.username:
                G.add_edge(f"email:{record.email}", f"username:{record.username}",
                          weight=1.0, database=record.database)

            if record.email and record.password:
                G.add_edge(f"email:{record.email}", f"password:{record.password}",
                          weight=1.0, database=record.database)

            if record.username and record.password:
                G.add_edge(f"username:{record.username}", f"password:{record.password}",
                          weight=1.0, database=record.database)

        self.logger.info(f"Built correlation graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")

        return G

    def _find_password_reuse(self, records: List[Any]) -> Dict[str, Any]:
        """
        Find password reuse patterns

        Args:
            records: Breach records

        Returns:
            Password reuse analysis
        """
        password_to_accounts = defaultdict(set)

        for record in records:
            if record.password:
                if record.email:
                    password_to_accounts[record.password].add(f"email:{record.email}")
                if record.username:
                    password_to_accounts[record.password].add(f"username:{record.username}")

        # Find passwords used across multiple accounts
        reused_passwords = {
            pwd: list(accounts)
            for pwd, accounts in password_to_accounts.items()
            if len(accounts) > 1
        }

        # Calculate reuse statistics
        total_passwords = len(password_to_accounts)
        reused_count = len(reused_passwords)
        reuse_percentage = (reused_count / total_passwords * 100) if total_passwords > 0 else 0

        # Find most reused passwords
        most_reused = sorted(
            reused_passwords.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:10]

        return {
            'total_unique_passwords': total_passwords,
            'reused_passwords': reused_count,
            'reuse_percentage': reuse_percentage,
            'most_reused': [
                {'password': pwd, 'account_count': len(accounts), 'accounts': accounts[:5]}
                for pwd, accounts in most_reused
            ],
            'high_risk': reused_count > 0
        }

    def _find_related_accounts(self, records: List[Any]) -> Dict[str, Any]:
        """
        Find related accounts based on shared attributes

        Args:
            records: Breach records

        Returns:
            Related accounts analysis
        """
        # Group by email
        email_accounts = defaultdict(lambda: {
            'usernames': set(),
            'passwords': set(),
            'ip_addresses': set(),
            'databases': set()
        })

        for record in records:
            if record.email:
                if record.username:
                    email_accounts[record.email]['usernames'].add(record.username)
                if record.password:
                    email_accounts[record.email]['passwords'].add(record.password)
                if record.ip_address:
                    email_accounts[record.email]['ip_addresses'].add(record.ip_address)
                email_accounts[record.email]['databases'].add(record.database)

        # Group by username
        username_accounts = defaultdict(lambda: {
            'emails': set(),
            'passwords': set(),
            'ip_addresses': set(),
            'databases': set()
        })

        for record in records:
            if record.username:
                if record.email:
                    username_accounts[record.username]['emails'].add(record.email)
                if record.password:
                    username_accounts[record.username]['passwords'].add(record.password)
                if record.ip_address:
                    username_accounts[record.username]['ip_addresses'].add(record.ip_address)
                username_accounts[record.username]['databases'].add(record.database)

        # Find accounts with multiple usernames (potential aliases)
        aliases = {
            email: list(data['usernames'])
            for email, data in email_accounts.items()
            if len(data['usernames']) > 1
        }

        # Find accounts with multiple emails (potential related accounts)
        related = {
            username: list(data['emails'])
            for username, data in username_accounts.items()
            if len(data['emails']) > 1
        }

        return {
            'total_unique_emails': len(email_accounts),
            'total_unique_usernames': len(username_accounts),
            'email_aliases': aliases,
            'related_accounts': related,
            'multi_database_accounts': [
                {
                    'email': email,
                    'database_count': len(data['databases']),
                    'databases': list(data['databases'])
                }
                for email, data in email_accounts.items()
                if len(data['databases']) > 1
            ]
        }

    def _find_credential_clusters(self, graph: nx.Graph) -> List[CredentialCluster]:
        """
        Find clusters of related credentials

        Args:
            graph: Correlation graph

        Returns:
            List of credential clusters
        """
        clusters = []

        # Find connected components
        for component in nx.connected_components(graph):
            if len(component) < 2:
                continue

            # Extract entities from component
            emails = set()
            usernames = set()
            passwords = set()
            ip_addresses = set()
            names = set()
            databases = set()

            for node in component:
                node_data = graph.nodes[node]
                node_type = node_data.get('type')
                node_value = node_data.get('value')

                if node_type == 'email':
                    emails.add(node_value)
                elif node_type == 'username':
                    usernames.add(node_value)
                elif node_type == 'password':
                    passwords.add(node_value)
                elif node_type == 'ip':
                    ip_addresses.add(node_value)

            # Get databases from edges
            for u, v in graph.subgraph(component).edges():
                edge_data = graph[u][v]
                if 'database' in edge_data:
                    databases.add(edge_data['database'])

            # Calculate confidence based on cluster size and connections
            confidence = min(1.0, len(component) / 10.0)

            cluster = CredentialCluster(
                emails=emails,
                usernames=usernames,
                passwords=passwords,
                ip_addresses=ip_addresses,
                names=names,
                databases=databases,
                confidence=confidence
            )

            clusters.append(cluster)

        # Sort by cluster size
        clusters.sort(key=lambda c: len(c.emails) + len(c.usernames) + len(c.passwords), reverse=True)

        self.logger.info(f"Found {len(clusters)} credential clusters")

        return clusters

    def _analyze_temporal_patterns(self, records: List[Any]) -> Dict[str, Any]:
        """
        Analyze temporal patterns in breaches

        Args:
            records: Breach records

        Returns:
            Temporal analysis
        """
        breach_dates = []
        database_timeline = defaultdict(list)

        for record in records:
            if record.breach_date:
                breach_dates.append(record.breach_date)
                database_timeline[record.database].append(record.breach_date)

        if not breach_dates:
            return {
                'earliest_breach': None,
                'latest_breach': None,
                'breach_timeline': [],
                'active_period_days': 0
            }

        earliest = min(breach_dates)
        latest = max(breach_dates)
        active_period = (latest - earliest).days

        # Create timeline
        timeline = []
        for database, dates in database_timeline.items():
            timeline.append({
                'database': database,
                'earliest': min(dates),
                'latest': max(dates),
                'breach_count': len(dates)
            })

        timeline.sort(key=lambda x: x['earliest'])

        return {
            'earliest_breach': earliest,
            'latest_breach': latest,
            'active_period_days': active_period,
            'breach_timeline': timeline,
            'total_breaches': len(set(r.database for r in records))
        }

    def _find_common_passwords(self, records: List[Any]) -> Dict[str, Any]:
        """
        Find most common passwords

        Args:
            records: Breach records

        Returns:
            Common password analysis
        """
        password_counter = Counter()
        password_databases = defaultdict(set)

        for record in records:
            if record.password:
                password_counter[record.password] += 1
                password_databases[record.password].add(record.database)

        # Get top passwords
        top_passwords = [
            {
                'password': pwd,
                'count': count,
                'database_count': len(password_databases[pwd]),
                'databases': list(password_databases[pwd])[:5]
            }
            for pwd, count in password_counter.most_common(10)
        ]

        # Analyze password strength
        weak_passwords = [
            pwd for pwd in password_counter.keys()
            if len(pwd) < 8 or pwd.lower() in ['password', '123456', 'qwerty', 'admin']
        ]

        return {
            'total_unique_passwords': len(password_counter),
            'top_passwords': top_passwords,
            'weak_password_count': len(weak_passwords),
            'weak_password_percentage': (len(weak_passwords) / len(password_counter) * 100)
                if password_counter else 0
        }

    def _analyze_username_patterns(self, records: List[Any]) -> Dict[str, Any]:
        """
        Analyze username patterns

        Args:
            records: Breach records

        Returns:
            Username pattern analysis
        """
        usernames = [r.username for r in records if r.username]

        if not usernames:
            return {}

        # Analyze patterns
        patterns = {
            'email_as_username': sum(1 for u in usernames if '@' in u),
            'numeric_usernames': sum(1 for u in usernames if u.isdigit()),
            'alphanumeric': sum(1 for u in usernames if u.isalnum()),
            'special_chars': sum(1 for u in usernames if not u.isalnum())
        }

        # Find common username prefixes/suffixes
        prefixes = Counter()
        suffixes = Counter()

        for username in usernames:
            if len(username) > 3:
                prefixes[username[:3]] += 1
                suffixes[username[-3:]] += 1

        return {
            'total_usernames': len(usernames),
            'unique_usernames': len(set(usernames)),
            'patterns': patterns,
            'common_prefixes': [
                {'prefix': p, 'count': c}
                for p, c in prefixes.most_common(5)
            ],
            'common_suffixes': [
                {'suffix': s, 'count': c}
                for s, c in suffixes.most_common(5)
            ]
        }

    def _generate_attack_surface(self, records: List[Any]) -> Dict[str, Any]:
        """
        Generate attack surface map

        Args:
            records: Breach records

        Returns:
            Attack surface analysis
        """
        attack_surface = {
            'entry_points': set(),
            'credential_pairs': [],
            'vulnerable_services': set(),
            'recon_data': {}
        }

        # Collect entry points
        for record in records:
            if record.email:
                attack_surface['entry_points'].add(f"email:{record.email}")
            if record.username:
                attack_surface['entry_points'].add(f"username:{record.username}")

            # Collect credential pairs
            if record.email and record.password:
                attack_surface['credential_pairs'].append({
                    'email': record.email,
                    'password': record.password,
                    'database': record.database
                })

            # Identify vulnerable services
            if record.database:
                attack_surface['vulnerable_services'].add(record.database)

        # Compile reconnaissance data
        attack_surface['recon_data'] = {
            'total_entry_points': len(attack_surface['entry_points']),
            'total_credential_pairs': len(attack_surface['credential_pairs']),
            'total_vulnerable_services': len(attack_surface['vulnerable_services']),
            'unique_emails': len([r for r in records if r.email]),
            'unique_usernames': len([r for r in records if r.username]),
            'unique_passwords': len(set([r.password for r in records if r.password]))
        }

        return {
            'entry_points': list(attack_surface['entry_points'])[:20],
            'credential_pairs_count': attack_surface['recon_data']['total_credential_pairs'],
            'vulnerable_services': list(attack_surface['vulnerable_services']),
            'recon_data': attack_surface['recon_data']
        }

    def _calculate_correlation_strength(self, records: List[Any]) -> float:
        """
        Calculate overall correlation strength

        Args:
            records: Breach records

        Returns:
            Correlation strength score (0-1)
        """
        if not records:
            return 0.0

        score = 0.0

        # Multiple databases increase correlation
        unique_databases = len(set(r.database for r in records))
        if unique_databases > 1:
            score += min(0.3, unique_databases * 0.1)

        # Password reuse increases correlation
        passwords = [r.password for r in records if r.password]
        if len(passwords) != len(set(passwords)):
            score += 0.3

        # Multiple attributes per record increase correlation
        avg_attributes = sum([
            1 for r in records if r.email
        ] + [
            1 for r in records if r.username
        ] + [
            1 for r in records if r.password
        ]) / len(records)

        score += min(0.4, avg_attributes * 0.1)

        return min(1.0, score)

    def find_pivot_points(self, records: List[Any]) -> Dict[str, List[str]]:
        """
        Find pivot points for further investigation

        Args:
            records: Breach records

        Returns:
            Dictionary of pivot points
        """
        pivots = {
            'emails': [],
            'usernames': [],
            'passwords': [],
            'ip_addresses': [],
            'domains': []
        }

        # Find high-value emails (appeared in multiple databases)
        email_databases = defaultdict(set)
        for record in records:
            if record.email:
                email_databases[record.email].add(record.database)

        pivots['emails'] = [
            email for email, dbs in email_databases.items()
            if len(dbs) > 1
        ]

        # Find high-value usernames
        username_databases = defaultdict(set)
        for record in records:
            if record.username:
                username_databases[record.username].add(record.database)

        pivots['usernames'] = [
            username for username, dbs in username_databases.items()
            if len(dbs) > 1
        ]

        # Extract domains from emails
        domains = set()
        for record in records:
            if record.email and '@' in record.email:
                domain = record.email.split('@')[1]
                domains.add(domain)

        pivots['domains'] = list(domains)

        return pivots


if __name__ == "__main__":
    # Example usage
    from dataclasses import dataclass
    from datetime import datetime

    @dataclass
    class MockRecord:
        source: str
        database: str
        breach_date: datetime
        email: str = None
        username: str = None
        password: str = None
        ip_address: str = None

    # Create mock records
    records = [
        MockRecord('DeHashed', 'LinkedIn', datetime(2021, 1, 1),
                  email='user@example.com', username='user123', password='password123'),
        MockRecord('HIBP', 'Adobe', datetime(2020, 6, 1),
                  email='user@example.com', username='user123', password='adobe123'),
        MockRecord('Snusbase', 'MySpace', datetime(2019, 3, 1),
                  email='user2@example.com', username='user123', password='password123'),
    ]

    correlator = BreachCorrelator()
    results = correlator.correlate_records(records)

    print(f"Correlation Strength: {results['correlation_strength']}")
    print(f"Password Reuse: {results['password_reuse']}")
    print(f"Related Accounts: {results['related_accounts']}")
