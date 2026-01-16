#!/usr/bin/env python3
"""
Dark Web Monitoring System
Comprehensive intelligence gathering from dark web sources
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from urllib.parse import urlparse, urljoin
import hashlib
import re

from tor_proxy import TorProxy
from onion_crawler import OnionCrawler
from marketplace_tracker import MarketplaceTracker
from forum_scraper import ForumScraper
from paste_monitor import PasteMonitor
from telegram_darkweb import TelegramDarkWeb
from darkweb_alerts import DarkWebAlerts


@dataclass
class MonitoringConfig:
    """Configuration for dark web monitoring"""
    keywords: List[str]
    marketplaces: List[str]
    forums: List[str]
    paste_sites: List[str]
    telegram_channels: List[str]
    tor_search_engines: List[str]
    continuous: bool = False
    interval: int = 3600  # seconds
    max_depth: int = 3
    output_dir: str = "darkweb_results"
    db_path: str = "darkweb_intel.db"
    enable_alerts: bool = True
    alert_webhook: Optional[str] = None
    user_agents_rotation: bool = True
    circuit_rotation_interval: int = 600


@dataclass
class DarkWebResult:
    """Dark web monitoring result"""
    id: str
    timestamp: datetime
    source: str
    source_type: str
    url: str
    title: str
    content: str
    keywords_found: List[str]
    metadata: Dict[str, Any]
    risk_score: int
    entities: List[str]
    cryptocurrency_addresses: List[str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class DarkWebMonitor:
    """Main dark web monitoring system"""

    def __init__(self, config: Optional[MonitoringConfig] = None):
        """Initialize dark web monitor"""
        self.config = config or self._default_config()
        self.logger = self._setup_logging()

        # Initialize components
        self.tor_proxy = TorProxy()
        self.onion_crawler = OnionCrawler(self.tor_proxy)
        self.marketplace_tracker = MarketplaceTracker(self.tor_proxy)
        self.forum_scraper = ForumScraper(self.tor_proxy)
        self.paste_monitor = PasteMonitor()
        self.telegram_monitor = TelegramDarkWeb()
        self.alerts = DarkWebAlerts(webhook_url=self.config.alert_webhook)

        # Setup database
        self.db_path = Path(self.config.output_dir) / self.config.db_path
        self._setup_database()

        # Monitoring state
        self.running = False
        self.results: List[DarkWebResult] = []
        self.processed_urls: Set[str] = set()

        self.logger.info("Dark Web Monitor initialized")

    def _default_config(self) -> MonitoringConfig:
        """Default monitoring configuration"""
        return MonitoringConfig(
            keywords=[],
            marketplaces=["alphabay", "hydra", "darkbay", "tormarket"],
            forums=["dread", "envoy", "darknetlive", "raidforums"],
            paste_sites=["pastebin", "ghostbin", "0bin", "rentry"],
            telegram_channels=[],
            tor_search_engines=["ahmia", "onionland", "darksearch", "torch"]
        )

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("DarkWebMonitor")
        logger.setLevel(logging.INFO)

        # File handler
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        fh = logging.FileHandler(output_dir / "darkweb_monitor.log")
        fh.setLevel(logging.INFO)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        return logger

    def _setup_database(self):
        """Setup SQLite database for results"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                source TEXT,
                source_type TEXT,
                url TEXT,
                title TEXT,
                content TEXT,
                keywords_found TEXT,
                metadata TEXT,
                risk_score INTEGER,
                entities TEXT,
                crypto_addresses TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                session_id TEXT PRIMARY KEY,
                start_time TEXT,
                end_time TEXT,
                keywords TEXT,
                results_count INTEGER,
                status TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                result_id TEXT,
                notified INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

        self.logger.info(f"Database initialized at {self.db_path}")

    async def start_monitoring(
        self,
        keywords: Optional[List[str]] = None,
        marketplaces: Optional[List[str]] = None,
        forums: Optional[List[str]] = None,
        continuous: bool = False,
        duration: Optional[int] = None
    ) -> List[DarkWebResult]:
        """
        Start dark web monitoring

        Args:
            keywords: Keywords to monitor
            marketplaces: Marketplaces to track
            forums: Forums to scrape
            continuous: Run continuously
            duration: Duration in seconds (for continuous mode)

        Returns:
            List of monitoring results
        """
        self.running = True
        session_id = self._generate_id("session")
        start_time = datetime.utcnow()

        # Update config
        if keywords:
            self.config.keywords = keywords
        if marketplaces:
            self.config.marketplaces = marketplaces
        if forums:
            self.config.forums = forums

        self.logger.info(f"Starting monitoring session {session_id}")
        self.logger.info(f"Keywords: {self.config.keywords}")

        try:
            # Start Tor proxy
            await self.tor_proxy.start()
            self.logger.info("Tor proxy started")

            if continuous:
                await self._continuous_monitoring(session_id, duration)
            else:
                await self._single_scan(session_id)

        except Exception as e:
            self.logger.error(f"Monitoring error: {e}", exc_info=True)
        finally:
            self.running = False
            await self.tor_proxy.stop()

            # Save session
            self._save_session(session_id, start_time, datetime.utcnow())

        return self.results

    async def _continuous_monitoring(self, session_id: str, duration: Optional[int]):
        """Run continuous monitoring"""
        start_time = datetime.utcnow()

        self.logger.info("Starting continuous monitoring")

        while self.running:
            # Check duration limit
            if duration and (datetime.utcnow() - start_time).seconds > duration:
                self.logger.info("Duration limit reached")
                break

            # Run scan
            await self._single_scan(session_id)

            # Wait for next interval
            self.logger.info(f"Waiting {self.config.interval} seconds until next scan")
            await asyncio.sleep(self.config.interval)

    async def _single_scan(self, session_id: str):
        """Run single monitoring scan"""
        self.logger.info("Starting monitoring scan")

        # Create tasks for parallel execution
        tasks = []

        # Tor search engines
        tasks.append(self._search_tor_engines())

        # Marketplace tracking
        if self.config.marketplaces:
            tasks.append(self._track_marketplaces())

        # Forum scraping
        if self.config.forums:
            tasks.append(self._scrape_forums())

        # Paste site monitoring
        if self.config.paste_sites:
            tasks.append(self._monitor_paste_sites())

        # Telegram monitoring
        if self.config.telegram_channels:
            tasks.append(self._monitor_telegram())

        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Task error: {result}")
            elif result:
                await self._process_results(result, session_id)

        self.logger.info(f"Scan complete. Found {len(self.results)} results")

    async def _search_tor_engines(self) -> List[DarkWebResult]:
        """Search Tor search engines"""
        self.logger.info("Searching Tor search engines")
        results = []

        for keyword in self.config.keywords:
            for engine in self.config.tor_search_engines:
                try:
                    search_results = await self._search_engine(engine, keyword)
                    results.extend(search_results)
                except Exception as e:
                    self.logger.error(f"Error searching {engine}: {e}")

        return results

    async def _search_engine(self, engine: str, keyword: str) -> List[DarkWebResult]:
        """Search specific Tor search engine"""
        results = []

        # Search engine endpoints
        engines = {
            "ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={}",
            "onionland": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={}",
            "darksearch": "http://darksearch3zkx2vdm6mupx7z3hq2sktbdqfzqrg5wfkdimx3tbrfzoad.onion/api/search?query={}",
            "torch": "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={}"
        }

        if engine not in engines:
            return results

        url = engines[engine].format(keyword)

        try:
            async with self.tor_proxy.get_session() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Parse results based on engine
                        if engine == "ahmia":
                            results = self._parse_ahmia_results(content, keyword)
                        elif engine == "darksearch":
                            results = self._parse_darksearch_results(content, keyword)
                        else:
                            results = self._parse_generic_results(content, keyword, engine)

                        self.logger.info(f"Found {len(results)} results from {engine}")

        except Exception as e:
            self.logger.error(f"Error searching {engine} for '{keyword}': {e}")

        return results

    def _parse_ahmia_results(self, html: str, keyword: str) -> List[DarkWebResult]:
        """Parse Ahmia search results"""
        results = []

        # Simple regex parsing (in production, use BeautifulSoup)
        url_pattern = r'href="([^"]+\.onion[^"]*)"'
        title_pattern = r'<h4[^>]*>([^<]+)</h4>'

        urls = re.findall(url_pattern, html)
        titles = re.findall(title_pattern, html)

        for i, (url, title) in enumerate(zip(urls, titles)):
            result = DarkWebResult(
                id=self._generate_id(url),
                timestamp=datetime.utcnow(),
                source="Ahmia",
                source_type="tor_search",
                url=url,
                title=title.strip(),
                content="",
                keywords_found=[keyword],
                metadata={"search_engine": "ahmia", "rank": i + 1},
                risk_score=self._calculate_risk_score([keyword], title),
                entities=[],
                cryptocurrency_addresses=[]
            )
            results.append(result)

        return results

    def _parse_darksearch_results(self, json_str: str, keyword: str) -> List[DarkWebResult]:
        """Parse DarkSearch API results"""
        results = []

        try:
            data = json.loads(json_str)

            for i, item in enumerate(data.get('data', [])):
                result = DarkWebResult(
                    id=self._generate_id(item.get('link', '')),
                    timestamp=datetime.utcnow(),
                    source="DarkSearch",
                    source_type="tor_search",
                    url=item.get('link', ''),
                    title=item.get('title', ''),
                    content=item.get('description', ''),
                    keywords_found=[keyword],
                    metadata={
                        "search_engine": "darksearch",
                        "rank": i + 1,
                        "updated": item.get('updated')
                    },
                    risk_score=self._calculate_risk_score([keyword], item.get('title', '')),
                    entities=[],
                    cryptocurrency_addresses=[]
                )
                results.append(result)

        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing DarkSearch JSON: {e}")

        return results

    def _parse_generic_results(self, html: str, keyword: str, engine: str) -> List[DarkWebResult]:
        """Parse generic search results"""
        results = []

        # Basic onion URL extraction
        url_pattern = r'https?://[a-z2-7]{16,56}\.onion[^\s<>"]*'
        urls = re.findall(url_pattern, html)

        for url in set(urls):  # Remove duplicates
            result = DarkWebResult(
                id=self._generate_id(url),
                timestamp=datetime.utcnow(),
                source=engine.capitalize(),
                source_type="tor_search",
                url=url,
                title="",
                content="",
                keywords_found=[keyword],
                metadata={"search_engine": engine},
                risk_score=50,
                entities=[],
                cryptocurrency_addresses=[]
            )
            results.append(result)

        return results

    async def _track_marketplaces(self) -> List[DarkWebResult]:
        """Track dark web marketplaces"""
        self.logger.info("Tracking dark web marketplaces")
        results = []

        for marketplace in self.config.marketplaces:
            try:
                marketplace_results = await self.marketplace_tracker.track_marketplace(
                    marketplace,
                    keywords=self.config.keywords
                )

                # Convert to DarkWebResult format
                for mr in marketplace_results:
                    result = DarkWebResult(
                        id=self._generate_id(mr.get('url', '')),
                        timestamp=datetime.utcnow(),
                        source=marketplace,
                        source_type="marketplace",
                        url=mr.get('url', ''),
                        title=mr.get('title', ''),
                        content=mr.get('description', ''),
                        keywords_found=mr.get('keywords_found', []),
                        metadata=mr.get('metadata', {}),
                        risk_score=mr.get('risk_score', 75),
                        entities=mr.get('entities', []),
                        cryptocurrency_addresses=mr.get('crypto_addresses', [])
                    )
                    results.append(result)

                self.logger.info(f"Found {len(marketplace_results)} results from {marketplace}")

            except Exception as e:
                self.logger.error(f"Error tracking marketplace {marketplace}: {e}")

        return results

    async def _scrape_forums(self) -> List[DarkWebResult]:
        """Scrape dark web forums"""
        self.logger.info("Scraping dark web forums")
        results = []

        for forum in self.config.forums:
            try:
                forum_results = await self.forum_scraper.scrape_forum(
                    forum,
                    keywords=self.config.keywords,
                    max_pages=10
                )

                # Convert to DarkWebResult format
                for fr in forum_results:
                    result = DarkWebResult(
                        id=self._generate_id(fr.get('url', '')),
                        timestamp=datetime.utcnow(),
                        source=forum,
                        source_type="forum",
                        url=fr.get('url', ''),
                        title=fr.get('title', ''),
                        content=fr.get('content', ''),
                        keywords_found=fr.get('keywords_found', []),
                        metadata=fr.get('metadata', {}),
                        risk_score=fr.get('risk_score', 60),
                        entities=fr.get('entities', []),
                        cryptocurrency_addresses=fr.get('crypto_addresses', [])
                    )
                    results.append(result)

                self.logger.info(f"Found {len(forum_results)} results from {forum}")

            except Exception as e:
                self.logger.error(f"Error scraping forum {forum}: {e}")

        return results

    async def _monitor_paste_sites(self) -> List[DarkWebResult]:
        """Monitor paste sites for leaks"""
        self.logger.info("Monitoring paste sites")
        results = []

        try:
            paste_results = await self.paste_monitor.monitor(
                keywords=self.config.keywords,
                sites=self.config.paste_sites
            )

            # Convert to DarkWebResult format
            for pr in paste_results:
                result = DarkWebResult(
                    id=self._generate_id(pr.get('url', '')),
                    timestamp=datetime.utcnow(),
                    source=pr.get('site', 'Unknown'),
                    source_type="paste_site",
                    url=pr.get('url', ''),
                    title=pr.get('title', ''),
                    content=pr.get('content', ''),
                    keywords_found=pr.get('keywords_found', []),
                    metadata=pr.get('metadata', {}),
                    risk_score=pr.get('risk_score', 80),
                    entities=pr.get('entities', []),
                    cryptocurrency_addresses=pr.get('crypto_addresses', [])
                )
                results.append(result)

            self.logger.info(f"Found {len(paste_results)} paste results")

        except Exception as e:
            self.logger.error(f"Error monitoring paste sites: {e}")

        return results

    async def _monitor_telegram(self) -> List[DarkWebResult]:
        """Monitor Telegram dark web channels"""
        self.logger.info("Monitoring Telegram channels")
        results = []

        try:
            telegram_results = await self.telegram_monitor.monitor_channels(
                channels=self.config.telegram_channels,
                keywords=self.config.keywords
            )

            # Convert to DarkWebResult format
            for tr in telegram_results:
                result = DarkWebResult(
                    id=self._generate_id(tr.get('message_id', '')),
                    timestamp=datetime.utcnow(),
                    source=tr.get('channel', 'Unknown'),
                    source_type="telegram",
                    url=tr.get('url', ''),
                    title=f"Message from {tr.get('author', 'Unknown')}",
                    content=tr.get('text', ''),
                    keywords_found=tr.get('keywords_found', []),
                    metadata=tr.get('metadata', {}),
                    risk_score=tr.get('risk_score', 70),
                    entities=tr.get('entities', []),
                    cryptocurrency_addresses=tr.get('crypto_addresses', [])
                )
                results.append(result)

            self.logger.info(f"Found {len(telegram_results)} Telegram results")

        except Exception as e:
            self.logger.error(f"Error monitoring Telegram: {e}")

        return results

    async def _process_results(self, results: List[DarkWebResult], session_id: str):
        """Process and store monitoring results"""
        for result in results:
            # Skip duplicates
            if result.url in self.processed_urls:
                continue

            # Extract entities and crypto addresses
            result.entities = self._extract_entities(result.content)
            result.cryptocurrency_addresses = self._extract_crypto_addresses(result.content)

            # Recalculate risk score with full content
            result.risk_score = self._calculate_risk_score(
                result.keywords_found,
                result.title + " " + result.content
            )

            # Save to database
            self._save_result(result)

            # Check for alerts
            if self.config.enable_alerts:
                await self._check_alerts(result)

            # Add to results
            self.results.append(result)
            self.processed_urls.add(result.url)

    def _extract_entities(self, text: str) -> List[str]:
        """Extract named entities from text"""
        entities = []

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        entities.extend(re.findall(email_pattern, text))

        # Phone numbers
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        entities.extend(re.findall(phone_pattern, text))

        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities.extend(re.findall(ip_pattern, text))

        return list(set(entities))

    def _extract_crypto_addresses(self, text: str) -> List[str]:
        """Extract cryptocurrency addresses from text"""
        addresses = []

        # Bitcoin addresses
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'
        addresses.extend(re.findall(btc_pattern, text))

        # Ethereum addresses
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        addresses.extend(re.findall(eth_pattern, text))

        # Monero addresses
        xmr_pattern = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        addresses.extend(re.findall(xmr_pattern, text))

        return list(set(addresses))

    def _calculate_risk_score(self, keywords: List[str], text: str) -> int:
        """Calculate risk score for content"""
        score = 0
        text_lower = text.lower()

        # Keyword matches
        score += len(keywords) * 10

        # High-risk terms
        high_risk_terms = [
            'drugs', 'weapons', 'stolen', 'hacked', 'exploit',
            'ransomware', 'malware', 'fraud', 'illegal', 'contraband',
            'credentials', 'database', 'breach', 'dump', 'leak'
        ]
        for term in high_risk_terms:
            if term in text_lower:
                score += 15

        # Cryptocurrency mentions
        crypto_terms = ['bitcoin', 'btc', 'ethereum', 'eth', 'monero', 'xmr', 'crypto']
        for term in crypto_terms:
            if term in text_lower:
                score += 5

        # Normalize to 0-100
        return min(score, 100)

    async def _check_alerts(self, result: DarkWebResult):
        """Check if result should trigger alerts"""
        alerts_triggered = []

        # High risk score alert
        if result.risk_score >= 80:
            alerts_triggered.append({
                'type': 'high_risk',
                'severity': 'high',
                'message': f"High risk content detected: {result.title}"
            })

        # Cryptocurrency address alert
        if result.cryptocurrency_addresses:
            alerts_triggered.append({
                'type': 'crypto_address',
                'severity': 'medium',
                'message': f"Cryptocurrency addresses found: {len(result.cryptocurrency_addresses)}"
            })

        # Entity mention alert
        if result.entities:
            alerts_triggered.append({
                'type': 'entity_mention',
                'severity': 'medium',
                'message': f"Entities detected: {', '.join(result.entities[:3])}"
            })

        # Send alerts
        for alert in alerts_triggered:
            await self.alerts.send_alert(
                alert_type=alert['type'],
                severity=alert['severity'],
                message=alert['message'],
                result=result
            )

            # Save alert to database
            self._save_alert(alert, result.id)

    def _save_result(self, result: DarkWebResult):
        """Save result to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO results
            (id, timestamp, source, source_type, url, title, content,
             keywords_found, metadata, risk_score, entities, crypto_addresses)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.id,
            result.timestamp.isoformat(),
            result.source,
            result.source_type,
            result.url,
            result.title,
            result.content,
            json.dumps(result.keywords_found),
            json.dumps(result.metadata),
            result.risk_score,
            json.dumps(result.entities),
            json.dumps(result.cryptocurrency_addresses)
        ))

        conn.commit()
        conn.close()

    def _save_alert(self, alert: Dict[str, Any], result_id: str):
        """Save alert to database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        alert_id = self._generate_id(f"alert_{result_id}")

        cursor.execute('''
            INSERT INTO alerts
            (alert_id, timestamp, alert_type, severity, message, result_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert_id,
            datetime.utcnow().isoformat(),
            alert['type'],
            alert['severity'],
            alert['message'],
            result_id
        ))

        conn.commit()
        conn.close()

    def _save_session(self, session_id: str, start_time: datetime, end_time: datetime):
        """Save monitoring session"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO monitoring_sessions
            (session_id, start_time, end_time, keywords, results_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            start_time.isoformat(),
            end_time.isoformat(),
            json.dumps(self.config.keywords),
            len(self.results),
            'completed'
        ))

        conn.commit()
        conn.close()

    def _generate_id(self, seed: str) -> str:
        """Generate unique ID"""
        return hashlib.sha256(f"{seed}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

    def export_results(self, format: str = 'json', output_file: Optional[str] = None) -> str:
        """
        Export monitoring results

        Args:
            format: Output format (json, csv, html)
            output_file: Output file path

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output_file = f"darkweb_results_{timestamp}.{format}"

        output_path = Path(self.config.output_dir) / output_file

        if format == 'json':
            self._export_json(output_path)
        elif format == 'csv':
            self._export_csv(output_path)
        elif format == 'html':
            self._export_html(output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Results exported to {output_path}")
        return str(output_path)

    def _export_json(self, output_path: Path):
        """Export results to JSON"""
        data = {
            'metadata': {
                'export_time': datetime.utcnow().isoformat(),
                'total_results': len(self.results),
                'keywords': self.config.keywords
            },
            'results': [result.to_dict() for result in self.results]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _export_csv(self, output_path: Path):
        """Export results to CSV"""
        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if not self.results:
                return

            fieldnames = ['timestamp', 'source', 'source_type', 'url', 'title',
                         'keywords_found', 'risk_score', 'entities']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in self.results:
                writer.writerow({
                    'timestamp': result.timestamp.isoformat(),
                    'source': result.source,
                    'source_type': result.source_type,
                    'url': result.url,
                    'title': result.title,
                    'keywords_found': ', '.join(result.keywords_found),
                    'risk_score': result.risk_score,
                    'entities': ', '.join(result.entities)
                })

    def _export_html(self, output_path: Path):
        """Export results to HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dark Web Monitoring Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .result {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
                .high-risk {{ border-left: 5px solid red; }}
                .medium-risk {{ border-left: 5px solid orange; }}
                .low-risk {{ border-left: 5px solid green; }}
                .metadata {{ color: #666; font-size: 0.9em; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 15px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>Dark Web Monitoring Report</h1>
            <div class="summary">
                <p><strong>Generated:</strong> {datetime.utcnow().isoformat()}</p>
                <p><strong>Total Results:</strong> {len(self.results)}</p>
                <p><strong>Keywords:</strong> {', '.join(self.config.keywords)}</p>
            </div>
        """

        for result in self.results:
            risk_class = 'high-risk' if result.risk_score >= 80 else 'medium-risk' if result.risk_score >= 50 else 'low-risk'

            html += f"""
            <div class="result {risk_class}">
                <h3>{result.title or 'Untitled'}</h3>
                <div class="metadata">
                    <p><strong>Source:</strong> {result.source} ({result.source_type})</p>
                    <p><strong>URL:</strong> <a href="{result.url}">{result.url}</a></p>
                    <p><strong>Risk Score:</strong> {result.risk_score}/100</p>
                    <p><strong>Keywords:</strong> {', '.join(result.keywords_found)}</p>
                    <p><strong>Timestamp:</strong> {result.timestamp.isoformat()}</p>
                </div>
                <p>{result.content[:500]}...</p>
            </div>
            """

        html += """
        </body>
        </html>
        """

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Stopping dark web monitor")

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Total results
        cursor.execute('SELECT COUNT(*) FROM results')
        total_results = cursor.fetchone()[0]

        # Results by source type
        cursor.execute('SELECT source_type, COUNT(*) FROM results GROUP BY source_type')
        by_source_type = dict(cursor.fetchall())

        # High risk results
        cursor.execute('SELECT COUNT(*) FROM results WHERE risk_score >= 80')
        high_risk = cursor.fetchone()[0]

        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]

        conn.close()

        return {
            'total_results': total_results,
            'by_source_type': by_source_type,
            'high_risk_results': high_risk,
            'total_alerts': total_alerts,
            'current_session_results': len(self.results)
        }


def main():
    """Example usage"""
    import sys

    # Configuration
    config = MonitoringConfig(
        keywords=["onecoin", "ruja ignatova", "cryptoqueen"],
        marketplaces=["alphabay", "darkbay"],
        forums=["dread", "darknetlive"],
        paste_sites=["pastebin", "ghostbin"],
        telegram_channels=[],
        continuous=False
    )

    # Create monitor
    monitor = DarkWebMonitor(config)

    # Start monitoring
    print("[*] Starting dark web monitoring...")
    print(f"[*] Keywords: {config.keywords}")

    results = asyncio.run(monitor.start_monitoring())

    print(f"\n[+] Monitoring complete!")
    print(f"[+] Found {len(results)} results")

    # Export results
    json_file = monitor.export_results(format='json')
    html_file = monitor.export_results(format='html')

    print(f"[+] Results exported:")
    print(f"    - JSON: {json_file}")
    print(f"    - HTML: {html_file}")

    # Statistics
    stats = monitor.get_statistics()
    print(f"\n[+] Statistics:")
    for key, value in stats.items():
        print(f"    - {key}: {value}")


if __name__ == "__main__":
    main()
