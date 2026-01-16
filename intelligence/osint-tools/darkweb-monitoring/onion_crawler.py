#!/usr/bin/env python3
"""
Onion Crawler - Tor Hidden Service Crawler
Automated crawling and content extraction from .onion sites
"""

import asyncio
import aiohttp
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re
import json
import hashlib
from urllib.parse import urlparse, urljoin
from collections import deque
import logging


@dataclass
class OnionPage:
    """Represents a crawled onion page"""
    url: str
    title: str
    content: str
    links: List[str]
    depth: int
    timestamp: datetime
    status_code: int
    content_type: str
    response_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'title': self.title,
            'content': self.content[:1000],  # Truncate for storage
            'links': self.links,
            'depth': self.depth,
            'timestamp': self.timestamp.isoformat(),
            'status_code': self.status_code,
            'content_type': self.content_type,
            'response_time': self.response_time,
            'metadata': self.metadata
        }


@dataclass
class CrawlConfig:
    """Crawler configuration"""
    max_depth: int = 3
    max_pages: int = 100
    timeout: int = 30
    delay: float = 2.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    follow_external: bool = False
    extract_emails: bool = True
    extract_crypto: bool = True
    respect_robots: bool = True
    max_concurrent: int = 5


class OnionCrawler:
    """Tor hidden service crawler"""

    def __init__(self, tor_proxy, config: Optional[CrawlConfig] = None):
        """
        Initialize onion crawler

        Args:
            tor_proxy: TorProxy instance for Tor connectivity
            config: Crawler configuration
        """
        self.tor_proxy = tor_proxy
        self.config = config or CrawlConfig()
        self.logger = self._setup_logging()

        # Crawl state
        self.visited_urls: Set[str] = set()
        self.pages: List[OnionPage] = []
        self.queue: deque = deque()
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)

        # Statistics
        self.stats = {
            'total_pages': 0,
            'failed_pages': 0,
            'total_links': 0,
            'emails_found': 0,
            'crypto_addresses_found': 0
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("OnionCrawler")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def crawl(
        self,
        start_url: str,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None
    ) -> List[OnionPage]:
        """
        Crawl onion site starting from URL

        Args:
            start_url: Starting onion URL
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl

        Returns:
            List of crawled pages
        """
        # Update config if specified
        if max_depth is not None:
            self.config.max_depth = max_depth
        if max_pages is not None:
            self.config.max_pages = max_pages

        # Validate onion URL
        if not self._is_onion_url(start_url):
            raise ValueError(f"Invalid onion URL: {start_url}")

        self.logger.info(f"Starting crawl of {start_url}")
        self.logger.info(f"Max depth: {self.config.max_depth}, Max pages: {self.config.max_pages}")

        # Initialize queue
        self.queue.append((start_url, 0))

        # Crawl loop
        while self.queue and len(self.pages) < self.config.max_pages:
            url, depth = self.queue.popleft()

            # Skip if already visited
            if url in self.visited_urls:
                continue

            # Skip if depth exceeded
            if depth > self.config.max_depth:
                continue

            # Mark as visited
            self.visited_urls.add(url)

            # Crawl page
            async with self.semaphore:
                page = await self._crawl_page(url, depth)

                if page:
                    self.pages.append(page)
                    self.stats['total_pages'] += 1

                    # Add links to queue
                    for link in page.links:
                        if link not in self.visited_urls:
                            self.queue.append((link, depth + 1))
                            self.stats['total_links'] += 1

                    # Delay between requests
                    await asyncio.sleep(self.config.delay)

        self.logger.info(f"Crawl complete. Pages crawled: {len(self.pages)}")
        return self.pages

    async def _crawl_page(self, url: str, depth: int) -> Optional[OnionPage]:
        """
        Crawl single page

        Args:
            url: Page URL
            depth: Current depth

        Returns:
            OnionPage or None if failed
        """
        try:
            start_time = datetime.utcnow()

            # Fetch page
            async with self.tor_proxy.get_session() as session:
                headers = {'User-Agent': self.config.user_agent}

                async with session.get(
                    url,
                    headers=headers,
                    timeout=self.config.timeout,
                    allow_redirects=True
                ) as response:
                    status_code = response.status
                    content_type = response.headers.get('Content-Type', 'unknown')

                    # Only process HTML
                    if 'text/html' not in content_type.lower():
                        self.logger.debug(f"Skipping non-HTML: {url} ({content_type})")
                        return None

                    html = await response.text()
                    response_time = (datetime.utcnow() - start_time).total_seconds()

                    # Extract information
                    title = self._extract_title(html)
                    content = self._extract_text(html)
                    links = self._extract_links(html, url)

                    # Create page object
                    page = OnionPage(
                        url=url,
                        title=title,
                        content=content,
                        links=links,
                        depth=depth,
                        timestamp=datetime.utcnow(),
                        status_code=status_code,
                        content_type=content_type,
                        response_time=response_time,
                        metadata={}
                    )

                    # Extract additional data
                    if self.config.extract_emails:
                        emails = self._extract_emails(html)
                        page.metadata['emails'] = emails
                        self.stats['emails_found'] += len(emails)

                    if self.config.extract_crypto:
                        crypto = self._extract_crypto_addresses(html)
                        page.metadata['crypto_addresses'] = crypto
                        self.stats['crypto_addresses_found'] += len(crypto)

                    self.logger.info(f"Crawled: {url} (depth={depth}, links={len(links)})")
                    return page

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout crawling {url}")
            self.stats['failed_pages'] += 1
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
            self.stats['failed_pages'] += 1

        return None

    def _is_onion_url(self, url: str) -> bool:
        """Check if URL is a valid onion address"""
        try:
            parsed = urlparse(url)
            return parsed.hostname and parsed.hostname.endswith('.onion')
        except:
            return False

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_text(self, html: str) -> str:
        """Extract text content from HTML"""
        # Remove scripts and styles
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Clean whitespace
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        parsed_base = urlparse(base_url)

        # Find all href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, html, re.IGNORECASE)

        for match in matches:
            # Convert to absolute URL
            absolute_url = urljoin(base_url, match)

            # Validate and filter
            if self._should_follow_link(absolute_url, parsed_base):
                links.append(absolute_url)

        return list(set(links))  # Remove duplicates

    def _should_follow_link(self, url: str, base_parsed) -> bool:
        """Determine if link should be followed"""
        try:
            parsed = urlparse(url)

            # Must be HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False

            # Must be onion
            if not parsed.hostname or not parsed.hostname.endswith('.onion'):
                return False

            # Check external links
            if not self.config.follow_external:
                if parsed.hostname != base_parsed.hostname:
                    return False

            # Skip common non-content URLs
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe']
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return False

            return True

        except:
            return False

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        return list(set(emails))

    def _extract_crypto_addresses(self, text: str) -> Dict[str, List[str]]:
        """Extract cryptocurrency addresses from text"""
        addresses = {
            'bitcoin': [],
            'ethereum': [],
            'monero': []
        }

        # Bitcoin
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'
        addresses['bitcoin'] = list(set(re.findall(btc_pattern, text)))

        # Ethereum
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        addresses['ethereum'] = list(set(re.findall(eth_pattern, text)))

        # Monero
        xmr_pattern = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        addresses['monero'] = list(set(re.findall(xmr_pattern, text)))

        return addresses

    def generate_sitemap(self, output_file: Optional[str] = None) -> str:
        """
        Generate sitemap of crawled pages

        Args:
            output_file: Output file path

        Returns:
            Sitemap as string
        """
        sitemap = []
        sitemap.append("# Onion Site Sitemap")
        sitemap.append(f"# Generated: {datetime.utcnow().isoformat()}")
        sitemap.append(f"# Total pages: {len(self.pages)}\n")

        # Group by depth
        by_depth = {}
        for page in self.pages:
            if page.depth not in by_depth:
                by_depth[page.depth] = []
            by_depth[page.depth].append(page)

        # Generate sitemap
        for depth in sorted(by_depth.keys()):
            sitemap.append(f"\n## Depth {depth}\n")
            for page in by_depth[depth]:
                sitemap.append(f"- [{page.title or 'Untitled'}]({page.url})")
                if page.metadata.get('emails'):
                    sitemap.append(f"  - Emails: {len(page.metadata['emails'])}")
                if page.metadata.get('crypto_addresses'):
                    total_crypto = sum(len(addrs) for addrs in page.metadata['crypto_addresses'].values())
                    if total_crypto > 0:
                        sitemap.append(f"  - Crypto addresses: {total_crypto}")

        sitemap_str = '\n'.join(sitemap)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(sitemap_str)
            self.logger.info(f"Sitemap saved to {output_file}")

        return sitemap_str

    def export_results(self, output_file: str):
        """
        Export crawl results to JSON

        Args:
            output_file: Output file path
        """
        data = {
            'metadata': {
                'crawl_time': datetime.utcnow().isoformat(),
                'total_pages': len(self.pages),
                'statistics': self.stats,
                'config': {
                    'max_depth': self.config.max_depth,
                    'max_pages': self.config.max_pages
                }
            },
            'pages': [page.to_dict() for page in self.pages]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results exported to {output_file}")

    def find_hidden_services(self, text: str) -> List[str]:
        """
        Find onion URLs in text

        Args:
            text: Text to search

        Returns:
            List of found onion URLs
        """
        onion_pattern = r'https?://[a-z2-7]{16,56}\.onion(?:/[^\s]*)?'
        urls = re.findall(onion_pattern, text, re.IGNORECASE)
        return list(set(urls))

    def get_statistics(self) -> Dict[str, Any]:
        """Get crawl statistics"""
        return {
            **self.stats,
            'pages_crawled': len(self.pages),
            'urls_visited': len(self.visited_urls),
            'success_rate': (self.stats['total_pages'] / max(len(self.visited_urls), 1)) * 100
        }


async def main():
    """Example usage"""
    from tor_proxy import TorProxy

    # Initialize Tor proxy
    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        # Create crawler
        config = CrawlConfig(
            max_depth=2,
            max_pages=50,
            delay=3.0
        )
        crawler = OnionCrawler(tor_proxy, config)

        # Example onion URL (replace with actual URL)
        start_url = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"

        # Crawl
        pages = await crawler.crawl(start_url)

        print(f"\n[+] Crawl complete!")
        print(f"[+] Pages crawled: {len(pages)}")

        # Generate sitemap
        sitemap = crawler.generate_sitemap("sitemap.md")
        print(f"[+] Sitemap generated")

        # Export results
        crawler.export_results("crawl_results.json")
        print(f"[+] Results exported")

        # Statistics
        stats = crawler.get_statistics()
        print(f"\n[+] Statistics:")
        for key, value in stats.items():
            print(f"    - {key}: {value}")

    finally:
        await tor_proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
