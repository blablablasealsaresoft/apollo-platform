#!/usr/bin/env python3
"""
TimescaleDB Storage for Dark Web Monitoring
Time-series storage for search results, breach data, and paste monitoring

Features:
- Hypertable storage for time-series data
- Automatic data retention policies
- Continuous aggregation for statistics
- Efficient querying of historical data
"""

import asyncio
import asyncpg
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import json
import hashlib
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class StorageConfig:
    """Storage configuration"""
    host: str = "localhost"
    port: int = 5432
    database: str = "apollo_darkweb"
    user: str = "apollo"
    password: str = ""
    min_connections: int = 2
    max_connections: int = 10
    retention_days: int = 90


class DarkWebStorage:
    """
    TimescaleDB storage for dark web monitoring data

    Uses hypertables for efficient time-series storage:
    - darkweb_search_results: Search results from Ahmia, etc.
    - breach_check_results: Breach check results
    - paste_monitoring_results: Paste site monitoring data
    - darkweb_alerts: Generated alerts
    """

    # Schema version for migrations
    SCHEMA_VERSION = 1

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "apollo_darkweb",
        user: str = "apollo",
        password: str = "",
        retention_days: int = 90
    ):
        """
        Initialize storage

        Args:
            host: TimescaleDB host
            port: TimescaleDB port
            database: Database name
            user: Database user
            password: Database password
            retention_days: Data retention period
        """
        self.config = StorageConfig(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            retention_days=retention_days
        )

        self._pool: Optional[asyncpg.Pool] = None
        self._initialized = False

    async def connect(self):
        """Establish database connection pool"""
        if self._pool is not None:
            return

        try:
            self._pool = await asyncpg.create_pool(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
                min_size=self.config.min_connections,
                max_size=self.config.max_connections
            )

            logger.info(f"Connected to TimescaleDB at {self.config.host}:{self.config.port}")

            # Initialize schema if needed
            if not self._initialized:
                await self._initialize_schema()
                self._initialized = True

        except Exception as e:
            logger.error(f"Failed to connect to TimescaleDB: {e}")
            raise

    async def disconnect(self):
        """Close database connection pool"""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Disconnected from TimescaleDB")

    async def _initialize_schema(self):
        """Initialize database schema with hypertables"""
        async with self._pool.acquire() as conn:
            # Enable TimescaleDB extension
            await conn.execute("""
                CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
            """)

            # Create schema version table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Check current schema version
            version = await conn.fetchval(
                "SELECT MAX(version) FROM schema_version"
            )

            if version is None or version < self.SCHEMA_VERSION:
                await self._apply_migrations(conn, version or 0)

    async def _apply_migrations(self, conn, current_version: int):
        """Apply schema migrations"""
        logger.info(f"Applying migrations from v{current_version} to v{self.SCHEMA_VERSION}")

        if current_version < 1:
            await self._migration_v1(conn)

        # Record schema version
        await conn.execute("""
            INSERT INTO schema_version (version) VALUES ($1)
            ON CONFLICT (version) DO NOTHING
        """, self.SCHEMA_VERSION)

    async def _migration_v1(self, conn):
        """Schema migration version 1"""
        logger.info("Applying migration v1: Initial schema")

        # Dark web search results table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS darkweb_search_results (
                time TIMESTAMPTZ NOT NULL,
                result_id TEXT NOT NULL,
                query TEXT NOT NULL,
                query_hash TEXT NOT NULL,
                engine TEXT NOT NULL,
                url TEXT NOT NULL,
                title TEXT,
                description TEXT,
                relevance_score FLOAT,
                keywords_matched TEXT[],
                raw_data JSONB,
                PRIMARY KEY (time, result_id)
            );
        """)

        # Convert to hypertable
        await conn.execute("""
            SELECT create_hypertable(
                'darkweb_search_results',
                'time',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 day'
            );
        """)

        # Breach check results table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS breach_check_results (
                time TIMESTAMPTZ NOT NULL,
                check_id TEXT NOT NULL,
                query TEXT NOT NULL,
                query_hash TEXT NOT NULL,
                query_type TEXT NOT NULL,
                breaches_found INTEGER DEFAULT 0,
                pastes_found INTEGER DEFAULT 0,
                credentials_count INTEGER DEFAULT 0,
                severity TEXT,
                sources_checked TEXT[],
                breaches_data JSONB,
                raw_data JSONB,
                PRIMARY KEY (time, check_id)
            );
        """)

        await conn.execute("""
            SELECT create_hypertable(
                'breach_check_results',
                'time',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 day'
            );
        """)

        # Paste monitoring results table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS paste_monitoring_results (
                time TIMESTAMPTZ NOT NULL,
                paste_id TEXT NOT NULL,
                site TEXT NOT NULL,
                url TEXT NOT NULL,
                title TEXT,
                author TEXT,
                content_hash TEXT NOT NULL,
                raw_size INTEGER,
                language TEXT,
                paste_type TEXT,
                severity TEXT,
                risk_score INTEGER,
                keywords_matched TEXT[],
                emails_count INTEGER DEFAULT 0,
                passwords_count INTEGER DEFAULT 0,
                crypto_addresses JSONB,
                raw_data JSONB,
                PRIMARY KEY (time, paste_id)
            );
        """)

        await conn.execute("""
            SELECT create_hypertable(
                'paste_monitoring_results',
                'time',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 day'
            );
        """)

        # Dark web alerts table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS darkweb_alerts (
                time TIMESTAMPTZ NOT NULL,
                alert_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                related_id TEXT,
                keywords TEXT[],
                acknowledged BOOLEAN DEFAULT FALSE,
                acknowledged_at TIMESTAMPTZ,
                acknowledged_by TEXT,
                raw_data JSONB,
                PRIMARY KEY (time, alert_id)
            );
        """)

        await conn.execute("""
            SELECT create_hypertable(
                'darkweb_alerts',
                'time',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 day'
            );
        """)

        # Create indexes for efficient querying
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_search_query_hash
            ON darkweb_search_results (query_hash, time DESC);

            CREATE INDEX IF NOT EXISTS idx_search_engine
            ON darkweb_search_results (engine, time DESC);

            CREATE INDEX IF NOT EXISTS idx_breach_query_hash
            ON breach_check_results (query_hash, time DESC);

            CREATE INDEX IF NOT EXISTS idx_breach_severity
            ON breach_check_results (severity, time DESC);

            CREATE INDEX IF NOT EXISTS idx_paste_site
            ON paste_monitoring_results (site, time DESC);

            CREATE INDEX IF NOT EXISTS idx_paste_severity
            ON paste_monitoring_results (severity, time DESC);

            CREATE INDEX IF NOT EXISTS idx_alert_type
            ON darkweb_alerts (alert_type, time DESC);

            CREATE INDEX IF NOT EXISTS idx_alert_unacknowledged
            ON darkweb_alerts (acknowledged, time DESC)
            WHERE acknowledged = FALSE;
        """)

        # Create continuous aggregates for statistics
        await conn.execute("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS search_stats_hourly
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('1 hour', time) AS bucket,
                engine,
                COUNT(*) as total_results,
                COUNT(DISTINCT query_hash) as unique_queries,
                AVG(relevance_score) as avg_relevance
            FROM darkweb_search_results
            GROUP BY bucket, engine
            WITH NO DATA;
        """)

        await conn.execute("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS breach_stats_daily
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('1 day', time) AS bucket,
                query_type,
                severity,
                COUNT(*) as total_checks,
                SUM(breaches_found) as total_breaches,
                SUM(credentials_count) as total_credentials
            FROM breach_check_results
            GROUP BY bucket, query_type, severity
            WITH NO DATA;
        """)

        await conn.execute("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS paste_stats_daily
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('1 day', time) AS bucket,
                site,
                severity,
                COUNT(*) as total_pastes,
                SUM(emails_count) as total_emails,
                SUM(passwords_count) as total_passwords,
                AVG(risk_score) as avg_risk_score
            FROM paste_monitoring_results
            GROUP BY bucket, site, severity
            WITH NO DATA;
        """)

        # Set up retention policy
        retention_interval = f"{self.config.retention_days} days"
        await conn.execute(f"""
            SELECT add_retention_policy(
                'darkweb_search_results',
                INTERVAL '{retention_interval}',
                if_not_exists => TRUE
            );

            SELECT add_retention_policy(
                'breach_check_results',
                INTERVAL '{retention_interval}',
                if_not_exists => TRUE
            );

            SELECT add_retention_policy(
                'paste_monitoring_results',
                INTERVAL '{retention_interval}',
                if_not_exists => TRUE
            );

            SELECT add_retention_policy(
                'darkweb_alerts',
                INTERVAL '{retention_interval}',
                if_not_exists => TRUE
            );
        """)

        logger.info("Migration v1 complete")

    # ============== Storage Methods ==============

    async def store_search_results(
        self,
        query: str,
        results: List[Dict[str, Any]]
    ):
        """
        Store dark web search results

        Args:
            query: Search query
            results: List of search result dictionaries
        """
        if not self._pool:
            await self.connect()

        query_hash = hashlib.md5(query.lower().encode()).hexdigest()
        now = datetime.utcnow()

        async with self._pool.acquire() as conn:
            for result in results:
                try:
                    await conn.execute("""
                        INSERT INTO darkweb_search_results (
                            time, result_id, query, query_hash, engine,
                            url, title, description, relevance_score,
                            keywords_matched, raw_data
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        ON CONFLICT (time, result_id) DO UPDATE SET
                            relevance_score = EXCLUDED.relevance_score,
                            raw_data = EXCLUDED.raw_data
                    """,
                        now,
                        result.get('result_id', hashlib.md5(result.get('url', '').encode()).hexdigest()[:16]),
                        query,
                        query_hash,
                        result.get('engine', 'unknown'),
                        result.get('url', ''),
                        result.get('title', ''),
                        result.get('description', ''),
                        result.get('relevance_score', 0.0),
                        result.get('keywords_matched', []),
                        json.dumps(result)
                    )
                except Exception as e:
                    logger.error(f"Error storing search result: {e}")

        logger.debug(f"Stored {len(results)} search results for query: {query[:50]}...")

    async def store_breach_result(
        self,
        query: str,
        query_type: str,
        result: Dict[str, Any]
    ):
        """
        Store breach check result

        Args:
            query: Checked identifier
            query_type: Type of identifier (email, domain, etc.)
            result: Breach check result dictionary
        """
        if not self._pool:
            await self.connect()

        query_hash = hashlib.md5(query.lower().encode()).hexdigest()
        check_id = hashlib.md5(f"{query}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        now = datetime.utcnow()

        async with self._pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO breach_check_results (
                        time, check_id, query, query_hash, query_type,
                        breaches_found, pastes_found, credentials_count,
                        severity, sources_checked, breaches_data, raw_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                """,
                    now,
                    check_id,
                    query,
                    query_hash,
                    query_type,
                    result.get('breaches_found', 0),
                    result.get('pastes_found', 0),
                    result.get('credentials_count', 0),
                    result.get('severity', 'unknown'),
                    result.get('sources_checked', []),
                    json.dumps(result.get('breaches', [])),
                    json.dumps(result)
                )

                logger.debug(f"Stored breach result for: {query_type}:{query[:20]}...")

            except Exception as e:
                logger.error(f"Error storing breach result: {e}")

    async def store_paste_result(self, paste: Dict[str, Any]):
        """
        Store paste monitoring result

        Args:
            paste: Paste record dictionary
        """
        if not self._pool:
            await self.connect()

        now = datetime.utcnow()
        content_hash = hashlib.md5(paste.get('content', '').encode()).hexdigest()

        async with self._pool.acquire() as conn:
            try:
                extracted = paste.get('extracted_data', {})

                await conn.execute("""
                    INSERT INTO paste_monitoring_results (
                        time, paste_id, site, url, title, author,
                        content_hash, raw_size, language, paste_type,
                        severity, risk_score, keywords_matched,
                        emails_count, passwords_count, crypto_addresses,
                        raw_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                    ON CONFLICT (time, paste_id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        raw_data = EXCLUDED.raw_data
                """,
                    now,
                    paste.get('paste_id', content_hash[:16]),
                    paste.get('site', 'unknown'),
                    paste.get('url', ''),
                    paste.get('title', ''),
                    paste.get('author', ''),
                    content_hash,
                    paste.get('raw_size', 0),
                    paste.get('language'),
                    paste.get('paste_type', 'unknown'),
                    paste.get('severity', 'INFO'),
                    paste.get('risk_score', 0),
                    paste.get('keywords_matched', []),
                    extracted.get('emails_count', 0),
                    extracted.get('passwords_count', 0),
                    json.dumps(extracted.get('crypto_addresses', {})),
                    json.dumps(paste)
                )

                logger.debug(f"Stored paste result: {paste.get('paste_id', 'unknown')}")

            except Exception as e:
                logger.error(f"Error storing paste result: {e}")

    async def store_alert(
        self,
        alert_type: str,
        severity: str,
        source: str,
        title: str,
        description: Optional[str] = None,
        related_id: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store dark web alert

        Args:
            alert_type: Type of alert
            severity: Alert severity
            source: Alert source
            title: Alert title
            description: Alert description
            related_id: Related entity ID
            keywords: Related keywords
            data: Additional data

        Returns:
            Alert ID
        """
        if not self._pool:
            await self.connect()

        alert_id = hashlib.md5(
            f"{alert_type}_{source}_{title}_{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        now = datetime.utcnow()

        async with self._pool.acquire() as conn:
            try:
                await conn.execute("""
                    INSERT INTO darkweb_alerts (
                        time, alert_id, alert_type, severity, source,
                        title, description, related_id, keywords, raw_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """,
                    now,
                    alert_id,
                    alert_type,
                    severity,
                    source,
                    title,
                    description,
                    related_id,
                    keywords or [],
                    json.dumps(data or {})
                )

                logger.info(f"Stored alert: {alert_type} - {title}")
                return alert_id

            except Exception as e:
                logger.error(f"Error storing alert: {e}")
                raise

    # ============== Query Methods ==============

    async def get_breach_results(
        self,
        query: str,
        query_type: str,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get cached breach results for a query

        Args:
            query: Identifier to look up
            query_type: Type of identifier
            since: Only return results after this time

        Returns:
            List of breach check results
        """
        if not self._pool:
            await self.connect()

        query_hash = hashlib.md5(query.lower().encode()).hexdigest()
        since = since or datetime.utcnow() - timedelta(days=1)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    time, check_id, query_type, breaches_found,
                    pastes_found, credentials_count, severity,
                    sources_checked, breaches_data
                FROM breach_check_results
                WHERE query_hash = $1
                    AND query_type = $2
                    AND time > $3
                ORDER BY time DESC
                LIMIT 10
            """, query_hash, query_type, since)

            results = []
            for row in rows:
                results.append({
                    'time': row['time'].isoformat(),
                    'check_id': row['check_id'],
                    'query_type': row['query_type'],
                    'breaches_found': row['breaches_found'],
                    'pastes_found': row['pastes_found'],
                    'credentials_count': row['credentials_count'],
                    'severity': row['severity'],
                    'sources_checked': row['sources_checked'],
                    'breaches': json.loads(row['breaches_data']) if row['breaches_data'] else []
                })

            return results

    async def get_search_results(
        self,
        query: str,
        since: Optional[datetime] = None,
        engine: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get cached search results

        Args:
            query: Search query
            since: Only return results after this time
            engine: Filter by search engine
            limit: Maximum results

        Returns:
            List of search results
        """
        if not self._pool:
            await self.connect()

        query_hash = hashlib.md5(query.lower().encode()).hexdigest()
        since = since or datetime.utcnow() - timedelta(days=7)

        async with self._pool.acquire() as conn:
            if engine:
                rows = await conn.fetch("""
                    SELECT time, result_id, url, title, description,
                           relevance_score, keywords_matched, raw_data
                    FROM darkweb_search_results
                    WHERE query_hash = $1 AND engine = $2 AND time > $3
                    ORDER BY relevance_score DESC, time DESC
                    LIMIT $4
                """, query_hash, engine, since, limit)
            else:
                rows = await conn.fetch("""
                    SELECT time, result_id, engine, url, title, description,
                           relevance_score, keywords_matched, raw_data
                    FROM darkweb_search_results
                    WHERE query_hash = $1 AND time > $2
                    ORDER BY relevance_score DESC, time DESC
                    LIMIT $3
                """, query_hash, since, limit)

            results = []
            for row in rows:
                results.append({
                    'time': row['time'].isoformat(),
                    'result_id': row['result_id'],
                    'engine': row.get('engine'),
                    'url': row['url'],
                    'title': row['title'],
                    'description': row['description'],
                    'relevance_score': row['relevance_score'],
                    'keywords_matched': row['keywords_matched']
                })

            return results

    async def get_paste_results(
        self,
        site: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get paste monitoring results

        Args:
            site: Filter by paste site
            severity: Filter by severity
            since: Only return results after this time
            limit: Maximum results

        Returns:
            List of paste results
        """
        if not self._pool:
            await self.connect()

        since = since or datetime.utcnow() - timedelta(days=7)

        async with self._pool.acquire() as conn:
            query = """
                SELECT time, paste_id, site, url, title, severity,
                       risk_score, keywords_matched, emails_count,
                       passwords_count
                FROM paste_monitoring_results
                WHERE time > $1
            """
            params = [since]

            if site:
                query += " AND site = $2"
                params.append(site)

            if severity:
                query += f" AND severity = ${len(params) + 1}"
                params.append(severity)

            query += f" ORDER BY time DESC LIMIT ${len(params) + 1}"
            params.append(limit)

            rows = await conn.fetch(query, *params)

            results = []
            for row in rows:
                results.append({
                    'time': row['time'].isoformat(),
                    'paste_id': row['paste_id'],
                    'site': row['site'],
                    'url': row['url'],
                    'title': row['title'],
                    'severity': row['severity'],
                    'risk_score': row['risk_score'],
                    'keywords_matched': row['keywords_matched'],
                    'emails_count': row['emails_count'],
                    'passwords_count': row['passwords_count']
                })

            return results

    async def get_alerts(
        self,
        unacknowledged_only: bool = False,
        alert_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get dark web alerts

        Args:
            unacknowledged_only: Only return unacknowledged alerts
            alert_type: Filter by alert type
            since: Only return alerts after this time
            limit: Maximum alerts

        Returns:
            List of alerts
        """
        if not self._pool:
            await self.connect()

        since = since or datetime.utcnow() - timedelta(days=7)

        async with self._pool.acquire() as conn:
            query = """
                SELECT time, alert_id, alert_type, severity, source,
                       title, description, related_id, keywords,
                       acknowledged, acknowledged_at, acknowledged_by
                FROM darkweb_alerts
                WHERE time > $1
            """
            params = [since]

            if unacknowledged_only:
                query += " AND acknowledged = FALSE"

            if alert_type:
                query += f" AND alert_type = ${len(params) + 1}"
                params.append(alert_type)

            query += f" ORDER BY time DESC LIMIT ${len(params) + 1}"
            params.append(limit)

            rows = await conn.fetch(query, *params)

            alerts = []
            for row in rows:
                alerts.append({
                    'time': row['time'].isoformat(),
                    'alert_id': row['alert_id'],
                    'alert_type': row['alert_type'],
                    'severity': row['severity'],
                    'source': row['source'],
                    'title': row['title'],
                    'description': row['description'],
                    'related_id': row['related_id'],
                    'keywords': row['keywords'],
                    'acknowledged': row['acknowledged'],
                    'acknowledged_at': row['acknowledged_at'].isoformat() if row['acknowledged_at'] else None,
                    'acknowledged_by': row['acknowledged_by']
                })

            return alerts

    async def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str
    ) -> bool:
        """
        Acknowledge an alert

        Args:
            alert_id: Alert ID
            acknowledged_by: User acknowledging the alert

        Returns:
            True if successful
        """
        if not self._pool:
            await self.connect()

        async with self._pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE darkweb_alerts
                SET acknowledged = TRUE,
                    acknowledged_at = NOW(),
                    acknowledged_by = $2
                WHERE alert_id = $1 AND acknowledged = FALSE
            """, alert_id, acknowledged_by)

            return result == "UPDATE 1"

    # ============== Statistics Methods ==============

    async def get_statistics(
        self,
        since: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics

        Args:
            since: Start time for statistics

        Returns:
            Statistics dictionary
        """
        if not self._pool:
            await self.connect()

        since = since or datetime.utcnow() - timedelta(days=30)

        async with self._pool.acquire() as conn:
            # Search stats
            search_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_results,
                    COUNT(DISTINCT query_hash) as unique_queries,
                    COUNT(DISTINCT engine) as engines_used,
                    AVG(relevance_score) as avg_relevance
                FROM darkweb_search_results
                WHERE time > $1
            """, since)

            # Breach stats
            breach_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_checks,
                    SUM(breaches_found) as total_breaches,
                    SUM(credentials_count) as total_credentials,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count
                FROM breach_check_results
                WHERE time > $1
            """, since)

            # Paste stats
            paste_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_pastes,
                    SUM(emails_count) as total_emails,
                    SUM(passwords_count) as total_passwords,
                    AVG(risk_score) as avg_risk_score,
                    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_pastes
                FROM paste_monitoring_results
                WHERE time > $1
            """, since)

            # Alert stats
            alert_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_alerts,
                    COUNT(CASE WHEN acknowledged = FALSE THEN 1 END) as unacknowledged,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_alerts
                FROM darkweb_alerts
                WHERE time > $1
            """, since)

            return {
                'period_start': since.isoformat(),
                'period_end': datetime.utcnow().isoformat(),
                'search': {
                    'total_results': search_stats['total_results'] or 0,
                    'unique_queries': search_stats['unique_queries'] or 0,
                    'engines_used': search_stats['engines_used'] or 0,
                    'avg_relevance': float(search_stats['avg_relevance'] or 0)
                },
                'breach': {
                    'total_checks': breach_stats['total_checks'] or 0,
                    'total_breaches': breach_stats['total_breaches'] or 0,
                    'total_credentials': breach_stats['total_credentials'] or 0,
                    'critical_count': breach_stats['critical_count'] or 0
                },
                'paste': {
                    'total_pastes': paste_stats['total_pastes'] or 0,
                    'total_emails': paste_stats['total_emails'] or 0,
                    'total_passwords': paste_stats['total_passwords'] or 0,
                    'avg_risk_score': float(paste_stats['avg_risk_score'] or 0),
                    'critical_pastes': paste_stats['critical_pastes'] or 0
                },
                'alerts': {
                    'total_alerts': alert_stats['total_alerts'] or 0,
                    'unacknowledged': alert_stats['unacknowledged'] or 0,
                    'critical_alerts': alert_stats['critical_alerts'] or 0
                }
            }


async def main():
    """Example usage"""
    storage = DarkWebStorage(
        host="localhost",
        port=5432,
        database="apollo_darkweb",
        user="apollo",
        password="your_password"
    )

    try:
        await storage.connect()

        # Store some test data
        await storage.store_search_results(
            query="cryptocurrency fraud",
            results=[
                {
                    'result_id': 'test123',
                    'engine': 'ahmia',
                    'url': 'http://example.onion',
                    'title': 'Test Result',
                    'description': 'Test description',
                    'relevance_score': 85.0,
                    'keywords_matched': ['cryptocurrency', 'fraud']
                }
            ]
        )

        # Get statistics
        stats = await storage.get_statistics()
        print(f"Statistics: {stats}")

    finally:
        await storage.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
