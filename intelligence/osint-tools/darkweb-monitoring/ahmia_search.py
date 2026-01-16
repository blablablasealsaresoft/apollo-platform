#!/usr/bin/env python3
"""
Ahmia.fi Dark Web Search Integration
Clearnet search engine for Tor hidden services
https://ahmia.fi - Legal and ethical dark web search

This module provides:
- Clearnet access to dark web search results (no Tor required for search)
- Keyword monitoring and alerting
- Site availability tracking
- OnionSearch integration
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import re
import logging
import hashlib
from urllib.parse import quote_plus, urljoin
from bs4 import BeautifulSoup


@dataclass
class DarkWebSearchResult:
    """Search result from dark web search engine"""
    result_id: str
    engine: str
    url: str
    title: str
    description: str
    timestamp: datetime
    last_seen: Optional[datetime] = None
    is_online: Optional[bool] = None
    relevance_score: float = 0.0
    keywords_matched: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'result_id': self.result_id,
            'engine': self.engine,
            'url': self.url,
            'title': self.title,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_online': self.is_online,
            'relevance_score': self.relevance_score,
            'keywords_matched': self.keywords_matched,
            'categories': self.categories,
            'metadata': self.metadata
        }


@dataclass
class MonitoringAlert:
    """Alert from keyword monitoring"""
    alert_id: str
    keyword: str
    result: DarkWebSearchResult
    alert_type: str
    severity: str
    created_at: datetime
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'keyword': self.keyword,
            'result': self.result.to_dict(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'created_at': self.created_at.isoformat(),
            'acknowledged': self.acknowledged
        }


class AhmiaSearch:
    """
    Ahmia.fi search engine integration

    Ahmia is a search engine for Tor hidden services that:
    - Filters out abuse material
    - Provides clearnet access to dark web search
    - Is operated by the Tor Project
    """

    # Ahmia endpoints
    AHMIA_SEARCH_URL = "https://ahmia.fi/search/"
    AHMIA_API_URL = "https://ahmia.fi/search/v2"
    AHMIA_STATS_URL = "https://ahmia.fi/stats/"

    # Alternative search engines
    SEARCH_ENGINES = {
        'ahmia': {
            'name': 'Ahmia.fi',
            'url': 'https://ahmia.fi/search/',
            'api_url': 'https://ahmia.fi/search/v2',
            'type': 'clearnet',
            'description': 'Tor Project affiliated search engine'
        },
        'onionland': {
            'name': 'OnionLand Search',
            'url': 'https://onionlandsearchengine.net/search',
            'type': 'clearnet',
            'description': 'Alternative dark web search engine'
        },
        'darksearch': {
            'name': 'DarkSearch',
            'url': 'https://darksearch.io/api/search',
            'type': 'api',
            'description': 'DarkSearch API (requires API key)'
        },
        'torch': {
            'name': 'Torch',
            'onion_url': 'http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega',
            'type': 'onion',
            'description': 'Tor-only search engine'
        }
    }

    def __init__(
        self,
        darksearch_api_key: Optional[str] = None,
        cache_duration: int = 3600,
        rate_limit_delay: float = 2.0
    ):
        """
        Initialize Ahmia search client

        Args:
            darksearch_api_key: Optional DarkSearch API key
            cache_duration: Cache duration in seconds
            rate_limit_delay: Delay between requests in seconds
        """
        self.darksearch_api_key = darksearch_api_key
        self.cache_duration = cache_duration
        self.rate_limit_delay = rate_limit_delay

        self.logger = self._setup_logging()

        # Caching
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_timestamps: Dict[str, datetime] = {}

        # Results tracking
        self.results: List[DarkWebSearchResult] = []
        self.seen_urls: Set[str] = set()

        # Monitoring
        self.monitored_keywords: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[MonitoringAlert] = []

        # Statistics
        self.stats = {
            'total_searches': 0,
            'total_results': 0,
            'engines_used': set(),
            'last_search': None
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("AhmiaSearch")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def search(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        max_results: int = 100,
        safe_search: bool = True
    ) -> List[DarkWebSearchResult]:
        """
        Search dark web using clearnet search engines

        Args:
            query: Search query
            engines: List of engines to use (default: ahmia)
            max_results: Maximum results to return
            safe_search: Enable safe search filtering

        Returns:
            List of search results
        """
        engines = engines or ['ahmia']
        self.logger.info(f"Searching for: '{query}' using engines: {engines}")

        all_results = []

        for engine in engines:
            try:
                if engine == 'ahmia':
                    results = await self._search_ahmia(query, max_results // len(engines))
                elif engine == 'darksearch' and self.darksearch_api_key:
                    results = await self._search_darksearch(query, max_results // len(engines))
                else:
                    self.logger.warning(f"Engine '{engine}' not available or not supported")
                    continue

                all_results.extend(results)
                self.stats['engines_used'].add(engine)

                # Rate limiting between engines
                await asyncio.sleep(self.rate_limit_delay)

            except Exception as e:
                self.logger.error(f"Error searching {engine}: {e}")

        # Deduplicate results
        unique_results = self._deduplicate_results(all_results)

        # Calculate relevance scores
        for result in unique_results:
            result.relevance_score = self._calculate_relevance(result, query)

        # Sort by relevance
        unique_results.sort(key=lambda x: x.relevance_score, reverse=True)

        # Update statistics
        self.stats['total_searches'] += 1
        self.stats['total_results'] += len(unique_results)
        self.stats['last_search'] = datetime.utcnow()

        # Store results
        self.results.extend(unique_results[:max_results])

        # Check for monitoring alerts
        await self._check_monitoring_alerts(query, unique_results)

        self.logger.info(f"Search complete: {len(unique_results)} results")
        return unique_results[:max_results]

    async def _search_ahmia(self, query: str, limit: int) -> List[DarkWebSearchResult]:
        """
        Search using Ahmia.fi

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of results
        """
        results = []

        # Check cache
        cache_key = f"ahmia_{hashlib.md5(query.encode()).hexdigest()}"
        if self._is_cached(cache_key):
            self.logger.debug(f"Using cached results for '{query}'")
            return self._cache[cache_key]['results']

        try:
            async with aiohttp.ClientSession() as session:
                # Ahmia search endpoint
                url = f"{self.AHMIA_SEARCH_URL}?q={quote_plus(query)}"

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win:64; x64) Firefox/120.0',
                    'Accept': 'text/html,application/xhtml+xml',
                    'Accept-Language': 'en-US,en;q=0.5'
                }

                async with session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        html = await response.text()
                        results = self._parse_ahmia_results(html, query)
                        self.logger.info(f"Ahmia returned {len(results)} results")

                        # Cache results
                        self._cache_results(cache_key, results)
                    else:
                        self.logger.warning(f"Ahmia returned status {response.status}")

        except asyncio.TimeoutError:
            self.logger.warning("Ahmia search timed out")
        except Exception as e:
            self.logger.error(f"Ahmia search error: {e}")

        return results[:limit]

    def _parse_ahmia_results(self, html: str, query: str) -> List[DarkWebSearchResult]:
        """
        Parse Ahmia search results from HTML

        Args:
            html: HTML content
            query: Original query

        Returns:
            List of parsed results
        """
        results = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Find search result items
            result_items = soup.find_all('li', class_='result')

            for i, item in enumerate(result_items):
                try:
                    # Extract URL
                    link = item.find('a', href=True)
                    if not link:
                        continue

                    url = link.get('href', '')
                    if not url or '.onion' not in url:
                        continue

                    # Extract title
                    title_elem = item.find('h4') or item.find('a')
                    title = title_elem.get_text(strip=True) if title_elem else 'Untitled'

                    # Extract description
                    desc_elem = item.find('p') or item.find('span', class_='description')
                    description = desc_elem.get_text(strip=True) if desc_elem else ''

                    # Extract date if available
                    date_elem = item.find('span', class_='date')
                    last_seen = None
                    if date_elem:
                        try:
                            date_text = date_elem.get_text(strip=True)
                            # Parse date (format varies)
                            last_seen = datetime.utcnow()
                        except:
                            pass

                    result = DarkWebSearchResult(
                        result_id=hashlib.md5(url.encode()).hexdigest()[:16],
                        engine='ahmia',
                        url=url,
                        title=title[:200],
                        description=description[:500],
                        timestamp=datetime.utcnow(),
                        last_seen=last_seen,
                        keywords_matched=[query],
                        metadata={
                            'rank': i + 1,
                            'raw_title': title
                        }
                    )

                    results.append(result)

                except Exception as e:
                    self.logger.debug(f"Error parsing result item: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Error parsing Ahmia HTML: {e}")

        return results

    async def _search_darksearch(self, query: str, limit: int) -> List[DarkWebSearchResult]:
        """
        Search using DarkSearch API

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of results
        """
        if not self.darksearch_api_key:
            self.logger.warning("DarkSearch API key not configured")
            return []

        results = []

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://darksearch.io/api/search?query={quote_plus(query)}"

                headers = {
                    'Authorization': f'Bearer {self.darksearch_api_key}',
                    'User-Agent': 'Apollo-Intelligence-Platform/1.0'
                }

                async with session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()

                        for i, item in enumerate(data.get('data', [])):
                            result = DarkWebSearchResult(
                                result_id=hashlib.md5(item.get('link', '').encode()).hexdigest()[:16],
                                engine='darksearch',
                                url=item.get('link', ''),
                                title=item.get('title', 'Untitled'),
                                description=item.get('description', ''),
                                timestamp=datetime.utcnow(),
                                keywords_matched=[query],
                                metadata={
                                    'rank': i + 1,
                                    'protocol': item.get('protocol')
                                }
                            )
                            results.append(result)

                        self.logger.info(f"DarkSearch returned {len(results)} results")
                    else:
                        self.logger.warning(f"DarkSearch returned status {response.status}")

        except Exception as e:
            self.logger.error(f"DarkSearch error: {e}")

        return results[:limit]

    def _deduplicate_results(self, results: List[DarkWebSearchResult]) -> List[DarkWebSearchResult]:
        """Remove duplicate results based on URL"""
        seen = set()
        unique = []

        for result in results:
            # Normalize URL for comparison
            normalized_url = result.url.lower().rstrip('/')

            if normalized_url not in seen:
                seen.add(normalized_url)
                unique.append(result)

        return unique

    def _calculate_relevance(self, result: DarkWebSearchResult, query: str) -> float:
        """
        Calculate relevance score for a result

        Args:
            result: Search result
            query: Original query

        Returns:
            Relevance score (0-100)
        """
        score = 0.0
        query_terms = query.lower().split()

        # Title match (highest weight)
        title_lower = result.title.lower()
        for term in query_terms:
            if term in title_lower:
                score += 20

        # Exact phrase in title
        if query.lower() in title_lower:
            score += 30

        # Description match
        desc_lower = result.description.lower()
        for term in query_terms:
            if term in desc_lower:
                score += 10

        # URL match
        url_lower = result.url.lower()
        for term in query_terms:
            if term in url_lower:
                score += 5

        # Rank bonus (earlier results get higher score)
        rank = result.metadata.get('rank', 100)
        score += max(0, 20 - rank)

        # Normalize to 0-100
        return min(score, 100)

    def _is_cached(self, key: str) -> bool:
        """Check if cache is valid"""
        if key not in self._cache:
            return False

        cache_time = self._cache_timestamps.get(key)
        if not cache_time:
            return False

        age = (datetime.utcnow() - cache_time).total_seconds()
        return age < self.cache_duration

    def _cache_results(self, key: str, results: List[DarkWebSearchResult]):
        """Cache search results"""
        self._cache[key] = {'results': results}
        self._cache_timestamps[key] = datetime.utcnow()

    # Monitoring Functions

    async def add_keyword_monitor(
        self,
        keyword: str,
        check_interval: int = 3600,
        alert_threshold: int = 1,
        engines: Optional[List[str]] = None
    ) -> str:
        """
        Add keyword to monitoring list

        Args:
            keyword: Keyword to monitor
            check_interval: Check interval in seconds
            alert_threshold: Number of new results to trigger alert
            engines: Engines to use for monitoring

        Returns:
            Monitor ID
        """
        monitor_id = hashlib.md5(f"{keyword}_{datetime.utcnow()}".encode()).hexdigest()[:12]

        self.monitored_keywords[monitor_id] = {
            'keyword': keyword,
            'check_interval': check_interval,
            'alert_threshold': alert_threshold,
            'engines': engines or ['ahmia'],
            'created_at': datetime.utcnow(),
            'last_check': None,
            'last_results': [],
            'total_alerts': 0,
            'active': True
        }

        self.logger.info(f"Added keyword monitor: '{keyword}' (ID: {monitor_id})")
        return monitor_id

    async def remove_keyword_monitor(self, monitor_id: str) -> bool:
        """Remove keyword from monitoring"""
        if monitor_id in self.monitored_keywords:
            del self.monitored_keywords[monitor_id]
            self.logger.info(f"Removed keyword monitor: {monitor_id}")
            return True
        return False

    async def check_all_monitors(self) -> List[MonitoringAlert]:
        """
        Check all monitored keywords

        Returns:
            List of new alerts
        """
        new_alerts = []

        for monitor_id, config in self.monitored_keywords.items():
            if not config['active']:
                continue

            # Check if it's time to check
            last_check = config.get('last_check')
            if last_check:
                elapsed = (datetime.utcnow() - last_check).total_seconds()
                if elapsed < config['check_interval']:
                    continue

            # Perform search
            keyword = config['keyword']
            results = await self.search(
                keyword,
                engines=config['engines'],
                max_results=50
            )

            # Check for new results
            previous_urls = set(r.url for r in config.get('last_results', []))
            new_results = [r for r in results if r.url not in previous_urls]

            # Generate alerts if threshold met
            if len(new_results) >= config['alert_threshold']:
                for result in new_results:
                    alert = MonitoringAlert(
                        alert_id=hashlib.md5(f"{monitor_id}_{result.result_id}".encode()).hexdigest()[:12],
                        keyword=keyword,
                        result=result,
                        alert_type='new_result',
                        severity=self._calculate_alert_severity(result, keyword),
                        created_at=datetime.utcnow()
                    )
                    new_alerts.append(alert)
                    self.alerts.append(alert)

                config['total_alerts'] += len(new_results)

            # Update monitor state
            config['last_check'] = datetime.utcnow()
            config['last_results'] = results

            self.logger.info(f"Checked monitor '{keyword}': {len(new_results)} new results")

        return new_alerts

    async def _check_monitoring_alerts(
        self,
        query: str,
        results: List[DarkWebSearchResult]
    ):
        """Check search results against monitored keywords"""
        for monitor_id, config in self.monitored_keywords.items():
            keyword = config['keyword'].lower()

            if keyword in query.lower():
                # This search was for a monitored keyword
                previous_urls = set(r.url for r in config.get('last_results', []))
                new_results = [r for r in results if r.url not in previous_urls]

                for result in new_results:
                    alert = MonitoringAlert(
                        alert_id=hashlib.md5(f"{monitor_id}_{result.result_id}".encode()).hexdigest()[:12],
                        keyword=keyword,
                        result=result,
                        alert_type='keyword_match',
                        severity=self._calculate_alert_severity(result, keyword),
                        created_at=datetime.utcnow()
                    )
                    self.alerts.append(alert)

    def _calculate_alert_severity(self, result: DarkWebSearchResult, keyword: str) -> str:
        """Calculate alert severity based on result content"""
        high_risk_terms = ['leak', 'breach', 'dump', 'hack', 'credential', 'database', 'exploit']
        critical_terms = ['zero-day', '0day', 'ransomware', 'botnet', 'malware']

        content = f"{result.title} {result.description}".lower()

        for term in critical_terms:
            if term in content:
                return 'critical'

        for term in high_risk_terms:
            if term in content:
                return 'high'

        if result.relevance_score > 80:
            return 'medium'

        return 'low'

    def get_alerts(
        self,
        severity: Optional[str] = None,
        unacknowledged_only: bool = False,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get alerts with optional filtering

        Args:
            severity: Filter by severity
            unacknowledged_only: Only return unacknowledged alerts
            limit: Maximum alerts to return

        Returns:
            List of alert dictionaries
        """
        filtered = self.alerts

        if severity:
            filtered = [a for a in filtered if a.severity == severity]

        if unacknowledged_only:
            filtered = [a for a in filtered if not a.acknowledged]

        return [a.to_dict() for a in filtered[-limit:]]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    # Site Availability Tracking

    async def check_site_availability(
        self,
        onion_url: str,
        tor_proxy_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if an onion site is available

        Args:
            onion_url: The .onion URL to check
            tor_proxy_url: SOCKS5 proxy URL for Tor (e.g., socks5://127.0.0.1:9050)

        Returns:
            Availability status dictionary
        """
        if not tor_proxy_url:
            # Can't check availability without Tor
            return {
                'url': onion_url,
                'status': 'unknown',
                'error': 'Tor proxy required for availability check'
            }

        try:
            from aiohttp_socks import ProxyConnector

            connector = ProxyConnector.from_url(tor_proxy_url, rdns=True)

            async with aiohttp.ClientSession(connector=connector) as session:
                start_time = datetime.utcnow()

                async with session.get(
                    onion_url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    allow_redirects=True
                ) as response:
                    latency = (datetime.utcnow() - start_time).total_seconds()

                    return {
                        'url': onion_url,
                        'status': 'online',
                        'status_code': response.status,
                        'latency_seconds': latency,
                        'content_type': response.headers.get('Content-Type'),
                        'content_length': response.headers.get('Content-Length'),
                        'checked_at': datetime.utcnow().isoformat()
                    }

        except asyncio.TimeoutError:
            return {
                'url': onion_url,
                'status': 'timeout',
                'error': 'Connection timed out',
                'checked_at': datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                'url': onion_url,
                'status': 'offline',
                'error': str(e),
                'checked_at': datetime.utcnow().isoformat()
            }

    async def track_site_availability(
        self,
        onion_url: str,
        check_interval: int = 3600,
        tor_proxy_url: Optional[str] = None
    ) -> str:
        """
        Add site to availability tracking

        Args:
            onion_url: The .onion URL to track
            check_interval: Check interval in seconds
            tor_proxy_url: SOCKS5 proxy URL

        Returns:
            Tracking ID
        """
        # This would be implemented with background tasks
        # For now, return placeholder
        tracking_id = hashlib.md5(onion_url.encode()).hexdigest()[:12]
        self.logger.info(f"Added site tracking: {onion_url} (ID: {tracking_id})")
        return tracking_id

    # Statistics and Export

    def get_statistics(self) -> Dict[str, Any]:
        """Get search statistics"""
        return {
            'total_searches': self.stats['total_searches'],
            'total_results': self.stats['total_results'],
            'engines_used': list(self.stats['engines_used']),
            'last_search': self.stats['last_search'].isoformat() if self.stats['last_search'] else None,
            'monitored_keywords': len(self.monitored_keywords),
            'total_alerts': len(self.alerts),
            'unacknowledged_alerts': sum(1 for a in self.alerts if not a.acknowledged)
        }

    def export_results(self, output_file: str):
        """Export search results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'statistics': self.get_statistics(),
            'results': [r.to_dict() for r in self.results],
            'alerts': [a.to_dict() for a in self.alerts]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results exported to {output_file}")


class OnionSearch:
    """
    OnionSearch integration for multi-engine dark web search
    Aggregates results from multiple Tor search engines
    """

    # OnionSearch supported engines (accessed via Tor)
    ONION_ENGINES = {
        'ahmia_onion': 'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion',
        'torch': 'http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion',
        'haystack': 'http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion',
        'darkowl': 'http://darkowlvffwir3gdd7pj2vuv7tpwpz3pvqkpgpl2cqrjk2vgkfap2ad.onion',
        'excavator': 'http://2fd6cemt4gmccflhm6imvdfvli3nber7cq6c6q2pxieyucrmhwvq2had.onion'
    }

    def __init__(self, tor_proxy_url: str = "socks5://127.0.0.1:9050"):
        """
        Initialize OnionSearch

        Args:
            tor_proxy_url: Tor SOCKS5 proxy URL
        """
        self.tor_proxy_url = tor_proxy_url
        self.logger = logging.getLogger("OnionSearch")

    async def search(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        max_results: int = 100
    ) -> List[DarkWebSearchResult]:
        """
        Search multiple onion search engines via Tor

        Args:
            query: Search query
            engines: Engines to use (default: all)
            max_results: Maximum results

        Returns:
            Aggregated search results
        """
        engines = engines or list(self.ONION_ENGINES.keys())
        results = []

        # This would require an active Tor connection
        self.logger.info(f"OnionSearch query: '{query}' across {len(engines)} engines")
        self.logger.warning("OnionSearch requires active Tor connection - implement with TorProxyEnhanced")

        return results


async def main():
    """Example usage"""
    # Initialize search client
    search = AhmiaSearch()

    print("[*] Apollo Dark Web Search Engine")
    print("=" * 50)

    # Perform search
    query = "cryptocurrency fraud investigation"
    print(f"\n[*] Searching for: '{query}'")

    results = await search.search(query, engines=['ahmia'], max_results=20)

    print(f"\n[+] Found {len(results)} results")

    for i, result in enumerate(results[:5], 1):
        print(f"\n{i}. {result.title}")
        print(f"   URL: {result.url}")
        print(f"   Relevance: {result.relevance_score:.1f}")
        print(f"   Description: {result.description[:100]}...")

    # Add keyword monitoring
    print("\n[*] Adding keyword monitor...")
    monitor_id = await search.add_keyword_monitor(
        keyword="cryptoqueen",
        check_interval=1800,  # 30 minutes
        alert_threshold=1
    )
    print(f"[+] Monitor added: {monitor_id}")

    # Get statistics
    stats = search.get_statistics()
    print(f"\n[*] Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")

    # Export results
    search.export_results("ahmia_search_results.json")
    print("\n[+] Results exported to ahmia_search_results.json")


if __name__ == "__main__":
    asyncio.run(main())
