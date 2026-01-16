"""
Neo4j Storage Module for BBOT Results
=====================================

Stores reconnaissance results in Neo4j for relationship mapping,
visualization, and advanced graph queries.

Features:
- Domain relationship graphs
- Subdomain hierarchy visualization
- Technology stack mapping
- Vulnerability correlation
- Historical scan tracking

Author: Apollo Intelligence Platform
Version: 2.0.0
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass

# Try to import neo4j driver
try:
    from neo4j import AsyncGraphDatabase, AsyncDriver
    from neo4j.exceptions import ServiceUnavailable
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class Neo4jConfig:
    """Neo4j connection configuration"""
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    max_connection_pool_size: int = 50
    connection_timeout: int = 30


class BBOTNeo4jStorage:
    """
    Neo4j storage for BBOT reconnaissance results

    Stores scan results as a graph database for relationship analysis
    and visualization.

    Node Types:
    - Domain: Root domain being scanned
    - Subdomain: Discovered subdomains
    - IP: IP addresses
    - Port: Open ports
    - Service: Detected services
    - Technology: Detected technologies
    - Vulnerability: Found vulnerabilities
    - Scan: Scan metadata

    Relationship Types:
    - HAS_SUBDOMAIN: Domain -> Subdomain
    - RESOLVES_TO: Subdomain/Domain -> IP
    - HAS_PORT: IP -> Port
    - RUNS_SERVICE: Port -> Service
    - USES_TECHNOLOGY: Domain/Subdomain -> Technology
    - HAS_VULNERABILITY: Domain/Subdomain/Technology -> Vulnerability
    - SCAN_RESULT: Scan -> Domain
    """

    def __init__(self, config: Optional[Neo4jConfig] = None):
        """
        Initialize Neo4j storage

        Args:
            config: Neo4j connection configuration
        """
        if not NEO4J_AVAILABLE:
            logger.warning(
                "Neo4j driver not available. "
                "Install with: pip install neo4j"
            )
            self.driver = None
            return

        self.config = config or Neo4jConfig()
        self.driver: Optional[AsyncDriver] = None

    async def connect(self) -> bool:
        """
        Connect to Neo4j database

        Returns:
            True if connection successful
        """
        if not NEO4J_AVAILABLE:
            return False

        try:
            self.driver = AsyncGraphDatabase.driver(
                self.config.uri,
                auth=(self.config.username, self.config.password),
                max_connection_pool_size=self.config.max_connection_pool_size,
                connection_timeout=self.config.connection_timeout
            )

            # Verify connection
            async with self.driver.session(database=self.config.database) as session:
                await session.run("RETURN 1")

            logger.info(f"Connected to Neo4j at {self.config.uri}")
            return True

        except ServiceUnavailable as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.driver = None
            return False
        except Exception as e:
            logger.error(f"Neo4j connection error: {e}")
            self.driver = None
            return False

    async def close(self):
        """Close Neo4j connection"""
        if self.driver:
            await self.driver.close()
            self.driver = None
            logger.info("Neo4j connection closed")

    async def initialize_schema(self):
        """Create indexes and constraints for optimal performance"""
        if not self.driver:
            return

        constraints_and_indexes = [
            # Unique constraints
            "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE",
            "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT scan_id IF NOT EXISTS FOR (sc:Scan) REQUIRE sc.scan_id IS UNIQUE",

            # Indexes for faster lookups
            "CREATE INDEX domain_created IF NOT EXISTS FOR (d:Domain) ON (d.created_at)",
            "CREATE INDEX subdomain_source IF NOT EXISTS FOR (s:Subdomain) ON (s.source)",
            "CREATE INDEX port_number IF NOT EXISTS FOR (p:Port) ON (p.number)",
            "CREATE INDEX technology_name IF NOT EXISTS FOR (t:Technology) ON (t.name)",
            "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX scan_status IF NOT EXISTS FOR (sc:Scan) ON (sc.status)",
        ]

        async with self.driver.session(database=self.config.database) as session:
            for statement in constraints_and_indexes:
                try:
                    await session.run(statement)
                except Exception as e:
                    logger.debug(f"Schema statement skipped: {e}")

        logger.info("Neo4j schema initialized")

    async def store_scan_result(self, scan_result: Dict) -> str:
        """
        Store complete scan result in Neo4j

        Args:
            scan_result: Scan result dictionary

        Returns:
            Scan node ID
        """
        if not self.driver:
            logger.warning("Neo4j not connected, skipping storage")
            return ""

        scan_id = scan_result.get('scan_id', '')
        target = scan_result.get('target', '')

        async with self.driver.session(database=self.config.database) as session:
            # Create Scan node
            scan_node = await self._create_scan_node(session, scan_result)

            # Create Domain node
            domain_node = await self._create_domain_node(session, target, scan_id)

            # Create relationship Scan -> Domain
            await session.run(
                """
                MATCH (sc:Scan {scan_id: $scan_id})
                MATCH (d:Domain {name: $domain})
                MERGE (sc)-[:SCAN_RESULT]->(d)
                """,
                scan_id=scan_id, domain=target
            )

            # Store subdomains
            for subdomain in scan_result.get('subdomains', []):
                await self._store_subdomain(session, target, subdomain, scan_id)

            # Store ports
            for port in scan_result.get('open_ports', []):
                await self._store_port(session, port, scan_id)

            # Store technologies
            for tech in scan_result.get('technologies', []):
                await self._store_technology(session, target, tech, scan_id)

            # Store vulnerabilities
            for vuln in scan_result.get('vulnerabilities', []):
                await self._store_vulnerability(session, target, vuln, scan_id)

        logger.info(f"Stored scan result {scan_id} in Neo4j")
        return scan_id

    async def _create_scan_node(self, session, scan_result: Dict) -> str:
        """Create Scan node"""
        result = await session.run(
            """
            MERGE (sc:Scan {scan_id: $scan_id})
            ON CREATE SET
                sc.target = $target,
                sc.preset = $preset,
                sc.status = $status,
                sc.start_time = $start_time,
                sc.end_time = $end_time,
                sc.duration_seconds = $duration,
                sc.subdomains_count = $subdomains_count,
                sc.ports_count = $ports_count,
                sc.technologies_count = $tech_count,
                sc.vulnerabilities_count = $vuln_count,
                sc.created_at = datetime()
            RETURN sc.scan_id AS scan_id
            """,
            scan_id=scan_result.get('scan_id', ''),
            target=scan_result.get('target', ''),
            preset=scan_result.get('preset', ''),
            status=scan_result.get('status', ''),
            start_time=scan_result.get('start_time', ''),
            end_time=scan_result.get('end_time', ''),
            duration=scan_result.get('duration_seconds', 0),
            subdomains_count=len(scan_result.get('subdomains', [])),
            ports_count=len(scan_result.get('open_ports', [])),
            tech_count=len(scan_result.get('technologies', [])),
            vuln_count=len(scan_result.get('vulnerabilities', []))
        )
        record = await result.single()
        return record['scan_id'] if record else ''

    async def _create_domain_node(self, session, domain: str, scan_id: str) -> str:
        """Create Domain node"""
        result = await session.run(
            """
            MERGE (d:Domain {name: $domain})
            ON CREATE SET
                d.created_at = datetime(),
                d.first_seen_scan = $scan_id
            SET d.last_scan_id = $scan_id,
                d.last_scanned = datetime()
            RETURN d.name AS name
            """,
            domain=domain, scan_id=scan_id
        )
        record = await result.single()
        return record['name'] if record else ''

    async def _store_subdomain(self, session, domain: str, subdomain: Dict, scan_id: str):
        """Store subdomain and create relationships"""
        fqdn = subdomain.get('subdomain', '')
        if not fqdn:
            return

        # Create Subdomain node
        await session.run(
            """
            MERGE (s:Subdomain {fqdn: $fqdn})
            ON CREATE SET
                s.source = $source,
                s.is_wildcard = $is_wildcard,
                s.created_at = datetime(),
                s.first_seen_scan = $scan_id
            SET s.last_scan_id = $scan_id,
                s.last_seen = datetime()
            """,
            fqdn=fqdn,
            source=subdomain.get('source', 'unknown'),
            is_wildcard=subdomain.get('is_wildcard', False),
            scan_id=scan_id
        )

        # Create relationship Domain -> Subdomain
        await session.run(
            """
            MATCH (d:Domain {name: $domain})
            MATCH (s:Subdomain {fqdn: $fqdn})
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """,
            domain=domain, fqdn=fqdn
        )

        # Store IP addresses and create relationships
        for ip in subdomain.get('ip_addresses', []):
            await session.run(
                """
                MERGE (i:IP {address: $ip})
                ON CREATE SET i.created_at = datetime()
                WITH i
                MATCH (s:Subdomain {fqdn: $fqdn})
                MERGE (s)-[:RESOLVES_TO]->(i)
                """,
                ip=ip, fqdn=fqdn
            )

    async def _store_port(self, session, port: Dict, scan_id: str):
        """Store port and service information"""
        host = port.get('host', '')
        port_num = port.get('port', 0)

        if not host or not port_num:
            return

        # Ensure IP node exists
        await session.run(
            """
            MERGE (i:IP {address: $host})
            ON CREATE SET i.created_at = datetime()
            """,
            host=host
        )

        # Create Port node
        await session.run(
            """
            MERGE (p:Port {host: $host, number: $port})
            ON CREATE SET
                p.protocol = $protocol,
                p.state = $state,
                p.created_at = datetime()
            SET p.service = $service,
                p.version = $version,
                p.banner = $banner,
                p.last_seen = datetime()
            """,
            host=host,
            port=port_num,
            protocol=port.get('protocol', 'tcp'),
            state=port.get('state', 'open'),
            service=port.get('service', ''),
            version=port.get('version', ''),
            banner=port.get('banner', '')
        )

        # Create relationship IP -> Port
        await session.run(
            """
            MATCH (i:IP {address: $host})
            MATCH (p:Port {host: $host, number: $port})
            MERGE (i)-[:HAS_PORT]->(p)
            """,
            host=host, port=port_num
        )

        # Create Service node if service detected
        if port.get('service'):
            await session.run(
                """
                MERGE (svc:Service {name: $service})
                ON CREATE SET svc.created_at = datetime()
                WITH svc
                MATCH (p:Port {host: $host, number: $port})
                MERGE (p)-[:RUNS_SERVICE {version: $version}]->(svc)
                """,
                service=port.get('service'),
                version=port.get('version', ''),
                host=host,
                port=port_num
            )

    async def _store_technology(self, session, domain: str, tech: Dict, scan_id: str):
        """Store technology information"""
        tech_name = tech.get('name', '')
        if not tech_name:
            return

        # Create Technology node
        await session.run(
            """
            MERGE (t:Technology {name: $name})
            ON CREATE SET
                t.category = $category,
                t.created_at = datetime()
            SET t.version = $version,
                t.confidence = $confidence,
                t.detection_method = $method,
                t.last_seen = datetime()
            """,
            name=tech_name,
            category=tech.get('category', 'Unknown'),
            version=tech.get('version', ''),
            confidence=tech.get('confidence', 0),
            method=tech.get('detection_method', '')
        )

        # Create relationship Domain -> Technology
        await session.run(
            """
            MATCH (d:Domain {name: $domain})
            MATCH (t:Technology {name: $tech})
            MERGE (d)-[:USES_TECHNOLOGY {scan_id: $scan_id}]->(t)
            """,
            domain=domain, tech=tech_name, scan_id=scan_id
        )

    async def _store_vulnerability(self, session, domain: str, vuln: Dict, scan_id: str):
        """Store vulnerability information"""
        title = vuln.get('title', '')
        if not title:
            return

        # Create Vulnerability node
        await session.run(
            """
            MERGE (v:Vulnerability {title: $title, domain: $domain})
            ON CREATE SET
                v.created_at = datetime()
            SET v.severity = $severity,
                v.description = $description,
                v.cve = $cve,
                v.cvss_score = $cvss,
                v.affected_component = $component,
                v.remediation = $remediation,
                v.scan_id = $scan_id,
                v.last_seen = datetime()
            """,
            title=title,
            domain=domain,
            severity=vuln.get('severity', 'unknown'),
            description=vuln.get('description', ''),
            cve=vuln.get('cve', ''),
            cvss=vuln.get('cvss_score', 0),
            component=vuln.get('affected_component', ''),
            remediation=vuln.get('remediation', ''),
            scan_id=scan_id
        )

        # Create relationship Domain -> Vulnerability
        await session.run(
            """
            MATCH (d:Domain {name: $domain})
            MATCH (v:Vulnerability {title: $title, domain: $domain})
            MERGE (d)-[:HAS_VULNERABILITY {scan_id: $scan_id}]->(v)
            """,
            domain=domain, title=title, scan_id=scan_id
        )

    async def get_domain_graph(self, domain: str) -> Dict:
        """
        Get complete graph for a domain

        Args:
            domain: Domain name

        Returns:
            Graph data with nodes and relationships
        """
        if not self.driver:
            return {'nodes': [], 'relationships': []}

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH path = (d:Domain {name: $domain})-[*0..3]-(connected)
                RETURN nodes(path) AS nodes, relationships(path) AS rels
                """,
                domain=domain
            )

            nodes = {}
            relationships = []

            async for record in result:
                for node in record['nodes']:
                    node_id = node.element_id
                    if node_id not in nodes:
                        nodes[node_id] = {
                            'id': node_id,
                            'labels': list(node.labels),
                            'properties': dict(node)
                        }

                for rel in record['rels']:
                    relationships.append({
                        'type': rel.type,
                        'start_node': rel.start_node.element_id,
                        'end_node': rel.end_node.element_id,
                        'properties': dict(rel)
                    })

            return {
                'nodes': list(nodes.values()),
                'relationships': relationships
            }

    async def get_subdomains_for_domain(self, domain: str) -> List[Dict]:
        """Get all subdomains for a domain"""
        if not self.driver:
            return []

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
                RETURN s.fqdn AS subdomain,
                       s.source AS source,
                       s.is_wildcard AS is_wildcard,
                       collect(DISTINCT i.address) AS ip_addresses
                ORDER BY s.fqdn
                """,
                domain=domain
            )

            subdomains = []
            async for record in result:
                subdomains.append({
                    'subdomain': record['subdomain'],
                    'source': record['source'],
                    'is_wildcard': record['is_wildcard'],
                    'ip_addresses': record['ip_addresses']
                })

            return subdomains

    async def get_technologies_for_domain(self, domain: str) -> List[Dict]:
        """Get all technologies for a domain"""
        if not self.driver:
            return []

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH (d:Domain {name: $domain})-[:USES_TECHNOLOGY]->(t:Technology)
                RETURN t.name AS name,
                       t.category AS category,
                       t.version AS version,
                       t.confidence AS confidence
                ORDER BY t.category, t.name
                """,
                domain=domain
            )

            technologies = []
            async for record in result:
                technologies.append({
                    'name': record['name'],
                    'category': record['category'],
                    'version': record['version'],
                    'confidence': record['confidence']
                })

            return technologies

    async def get_vulnerabilities_for_domain(self, domain: str) -> List[Dict]:
        """Get all vulnerabilities for a domain"""
        if not self.driver:
            return []

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH (d:Domain {name: $domain})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                RETURN v.title AS title,
                       v.severity AS severity,
                       v.description AS description,
                       v.cve AS cve,
                       v.cvss_score AS cvss_score,
                       v.remediation AS remediation
                ORDER BY
                    CASE v.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END
                """,
                domain=domain
            )

            vulnerabilities = []
            async for record in result:
                vulnerabilities.append({
                    'title': record['title'],
                    'severity': record['severity'],
                    'description': record['description'],
                    'cve': record['cve'],
                    'cvss_score': record['cvss_score'],
                    'remediation': record['remediation']
                })

            return vulnerabilities

    async def get_scan_history(self, domain: str, limit: int = 10) -> List[Dict]:
        """Get scan history for a domain"""
        if not self.driver:
            return []

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH (sc:Scan)-[:SCAN_RESULT]->(d:Domain {name: $domain})
                RETURN sc.scan_id AS scan_id,
                       sc.preset AS preset,
                       sc.status AS status,
                       sc.start_time AS start_time,
                       sc.duration_seconds AS duration,
                       sc.subdomains_count AS subdomains,
                       sc.vulnerabilities_count AS vulnerabilities
                ORDER BY sc.start_time DESC
                LIMIT $limit
                """,
                domain=domain, limit=limit
            )

            scans = []
            async for record in result:
                scans.append({
                    'scan_id': record['scan_id'],
                    'preset': record['preset'],
                    'status': record['status'],
                    'start_time': record['start_time'],
                    'duration': record['duration'],
                    'subdomains': record['subdomains'],
                    'vulnerabilities': record['vulnerabilities']
                })

            return scans

    async def search_by_technology(self, technology: str) -> List[str]:
        """Find all domains using a specific technology"""
        if not self.driver:
            return []

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(
                """
                MATCH (d:Domain)-[:USES_TECHNOLOGY]->(t:Technology)
                WHERE t.name CONTAINS $technology
                RETURN DISTINCT d.name AS domain
                ORDER BY d.name
                """,
                technology=technology
            )

            domains = []
            async for record in result:
                domains.append(record['domain'])

            return domains

    async def search_by_vulnerability(self, severity: str = None, cve: str = None) -> List[Dict]:
        """Find domains with specific vulnerabilities"""
        if not self.driver:
            return []

        query = """
            MATCH (d:Domain)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE 1=1
        """
        params = {}

        if severity:
            query += " AND v.severity = $severity"
            params['severity'] = severity

        if cve:
            query += " AND v.cve CONTAINS $cve"
            params['cve'] = cve

        query += """
            RETURN d.name AS domain,
                   v.title AS vulnerability,
                   v.severity AS severity,
                   v.cve AS cve
            ORDER BY d.name
        """

        async with self.driver.session(database=self.config.database) as session:
            result = await session.run(query, **params)

            findings = []
            async for record in result:
                findings.append({
                    'domain': record['domain'],
                    'vulnerability': record['vulnerability'],
                    'severity': record['severity'],
                    'cve': record['cve']
                })

            return findings


# Convenience function
async def store_in_neo4j(scan_result: Dict, config: Optional[Neo4jConfig] = None) -> bool:
    """
    Store scan result in Neo4j

    Args:
        scan_result: Scan result dictionary
        config: Optional Neo4j configuration

    Returns:
        True if storage successful
    """
    storage = BBOTNeo4jStorage(config)

    if not await storage.connect():
        return False

    try:
        await storage.initialize_schema()
        await storage.store_scan_result(scan_result)
        return True
    finally:
        await storage.close()
