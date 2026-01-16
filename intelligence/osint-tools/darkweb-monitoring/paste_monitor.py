#!/usr/bin/env python3
"""
Paste Site Monitor
Monitoring paste sites for leaked credentials and sensitive data
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import re
import logging
import hashlib


@dataclass
class PasteResult:
    """Paste monitoring result"""
    paste_id: str
    site: str
    url: str
    title: str
    author: str
    content: str
    created: datetime
    expires: Optional[datetime]
    keywords_found: List[str] = field(default_factory=list)
    emails_found: List[str] = field(default_factory=list)
    passwords_found: int = 0
    crypto_addresses: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    risk_score: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'paste_id': self.paste_id,
            'site': self.site,
            'url': self.url,
            'title': self.title,
            'author': self.author,
            'content': self.content[:1000],  # Truncate
            'created': self.created.isoformat(),
            'expires': self.expires.isoformat() if self.expires else None,
            'keywords_found': self.keywords_found,
            'emails_found': self.emails_found,
            'passwords_found': self.passwords_found,
            'crypto_addresses': self.crypto_addresses,
            'ip_addresses': self.ip_addresses,
            'domains': self.domains,
            'risk_score': self.risk_score,
            'metadata': self.metadata
        }


class PasteMonitor:
    """Paste site monitoring system"""

    # Paste site configurations
    PASTE_SITES = {
        "pastebin": {
            "name": "Pastebin",
            "url": "https://pastebin.com",
            "api_url": "https://scrape.pastebin.com/api_scraping.php",
            "raw_url": "https://pastebin.com/raw/{}",
            "requires_auth": True,
            "rate_limit": 1  # seconds between requests
        },
        "ghostbin": {
            "name": "Ghostbin",
            "url": "https://ghostbin.com",
            "raw_url": "https://ghostbin.com/{}/raw",
            "requires_auth": False,
            "rate_limit": 2
        },
        "0bin": {
            "name": "0bin",
            "url": "https://0bin.net",
            "requires_auth": False,
            "rate_limit": 2
        },
        "rentry": {
            "name": "Rentry",
            "url": "https://rentry.co",
            "raw_url": "https://rentry.co/{}/raw",
            "requires_auth": False,
            "rate_limit": 2
        }
    }

    def __init__(self):
        """Initialize paste monitor"""
        self.logger = self._setup_logging()
        self.results: List[PasteResult] = []
        self.monitored_paste_ids: Set[str] = set()

        # Statistics
        self.stats = {
            'total_pastes': 0,
            'credentials_found': 0,
            'high_risk_pastes': 0,
            'total_emails': 0,
            'total_crypto': 0
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("PasteMonitor")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def monitor(
        self,
        keywords: List[str],
        sites: Optional[List[str]] = None,
        duration: Optional[int] = None,
        continuous: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Monitor paste sites

        Args:
            keywords: Keywords to search for
            sites: Paste sites to monitor
            duration: Duration in seconds
            continuous: Run continuously

        Returns:
            List of paste results
        """
        target_sites = sites if sites else list(self.PASTE_SITES.keys())
        self.logger.info(f"Starting paste monitoring for {len(target_sites)} sites")
        self.logger.info(f"Keywords: {keywords}")

        results = []
        start_time = datetime.utcnow()

        try:
            if continuous:
                while True:
                    # Check duration limit
                    if duration and (datetime.utcnow() - start_time).seconds > duration:
                        break

                    # Monitor each site
                    for site in target_sites:
                        site_results = await self._monitor_site(site, keywords)
                        results.extend(site_results)

                    # Wait before next check
                    await asyncio.sleep(60)  # Check every minute
            else:
                # Single scan
                for site in target_sites:
                    site_results = await self._monitor_site(site, keywords)
                    results.extend(site_results)

        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")

        # Convert to standard format
        formatted_results = []
        for result in results:
            formatted_results.append({
                'url': result.url,
                'title': result.title,
                'content': result.content,
                'site': result.site,
                'keywords_found': result.keywords_found,
                'metadata': {
                    'paste_id': result.paste_id,
                    'author': result.author,
                    'created': result.created.isoformat(),
                    'emails_found': result.emails_found,
                    'passwords_found': result.passwords_found,
                    'crypto_addresses': result.crypto_addresses,
                    'ip_addresses': result.ip_addresses
                },
                'risk_score': result.risk_score,
                'entities': result.emails_found + result.ip_addresses + result.domains,
                'crypto_addresses': result.crypto_addresses
            })

        self.logger.info(f"Monitoring complete. Found {len(formatted_results)} results")
        return formatted_results

    async def _monitor_site(
        self,
        site: str,
        keywords: List[str]
    ) -> List[PasteResult]:
        """
        Monitor specific paste site

        Args:
            site: Paste site name
            keywords: Keywords to search

        Returns:
            List of PasteResult objects
        """
        if site not in self.PASTE_SITES:
            self.logger.warning(f"Unknown paste site: {site}")
            return []

        site_config = self.PASTE_SITES[site]
        self.logger.info(f"Monitoring {site_config['name']}")

        results = []

        try:
            # Different monitoring strategies based on site
            if site == "pastebin":
                results = await self._monitor_pastebin(keywords, site_config)
            else:
                results = await self._monitor_generic_site(site, keywords, site_config)

            self.logger.info(f"Found {len(results)} results from {site}")

        except Exception as e:
            self.logger.error(f"Error monitoring {site}: {e}")

        return results

    async def _monitor_pastebin(
        self,
        keywords: List[str],
        config: Dict[str, Any]
    ) -> List[PasteResult]:
        """
        Monitor Pastebin (requires API access)

        Args:
            keywords: Keywords to search
            config: Site configuration

        Returns:
            List of results
        """
        results = []

        # Note: Real implementation would require Pastebin API key
        self.logger.warning("Pastebin API monitoring requires authentication - simulating results")

        # Simulate some results for demonstration
        for keyword in keywords:
            paste_id = hashlib.md5(f"pastebin_{keyword}".encode()).hexdigest()[:8]

            # Skip if already monitored
            if paste_id in self.monitored_paste_ids:
                continue

            result = PasteResult(
                paste_id=paste_id,
                site="pastebin",
                url=f"{config['url']}/{paste_id}",
                title=f"Simulated paste containing '{keyword}'",
                author="Anonymous",
                content=f"This is a simulated paste for demonstration. Keyword: {keyword}",
                created=datetime.utcnow(),
                expires=None,
                keywords_found=[keyword]
            )

            # Analyze content
            self._analyze_paste_content(result)

            results.append(result)
            self.monitored_paste_ids.add(paste_id)

        return results

    async def _monitor_generic_site(
        self,
        site: str,
        keywords: List[str],
        config: Dict[str, Any]
    ) -> List[PasteResult]:
        """
        Monitor generic paste site

        Args:
            site: Site name
            keywords: Keywords to search
            config: Site configuration

        Returns:
            List of results
        """
        results = []

        # Simulate monitoring (real implementation would scrape recent pastes)
        self.logger.warning(f"{site} monitoring not fully implemented - simulating results")

        for keyword in keywords:
            paste_id = hashlib.md5(f"{site}_{keyword}".encode()).hexdigest()[:8]

            # Skip if already monitored
            if paste_id in self.monitored_paste_ids:
                continue

            result = PasteResult(
                paste_id=paste_id,
                site=site,
                url=f"{config['url']}/{paste_id}",
                title=f"Paste matching '{keyword}'",
                author="Anonymous",
                content=f"Simulated paste content for keyword: {keyword}",
                created=datetime.utcnow(),
                expires=datetime.utcnow() + timedelta(days=30)
            )

            result.keywords_found = [keyword]
            self._analyze_paste_content(result)

            results.append(result)
            self.monitored_paste_ids.add(paste_id)

        return results

    def _analyze_paste_content(self, paste: PasteResult):
        """
        Analyze paste content for sensitive information

        Args:
            paste: PasteResult object to analyze
        """
        content = paste.content

        # Extract emails
        paste.emails_found = self._extract_emails(content)
        self.stats['total_emails'] += len(paste.emails_found)

        # Extract passwords (look for credential patterns)
        paste.passwords_found = self._count_passwords(content)
        if paste.passwords_found > 0:
            self.stats['credentials_found'] += 1

        # Extract crypto addresses
        paste.crypto_addresses = self._extract_crypto_addresses(content)
        self.stats['total_crypto'] += len(paste.crypto_addresses)

        # Extract IP addresses
        paste.ip_addresses = self._extract_ip_addresses(content)

        # Extract domains
        paste.domains = self._extract_domains(content)

        # Calculate risk score
        paste.risk_score = self._calculate_risk_score(paste)

        if paste.risk_score >= 80:
            self.stats['high_risk_pastes'] += 1

        # Add metadata
        paste.metadata['leak_type'] = self._classify_leak_type(paste)

        self.stats['total_pastes'] += 1

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(pattern, text)
        return list(set(emails))

    def _count_passwords(self, text: str) -> int:
        """Count potential passwords in text"""
        # Look for credential patterns
        patterns = [
            r'password[:\s]+([^\s]+)',
            r'pass[:\s]+([^\s]+)',
            r'pwd[:\s]+([^\s]+)',
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+'  # email:password
        ]

        count = 0
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            count += len(matches)

        return count

    def _extract_crypto_addresses(self, text: str) -> List[str]:
        """Extract cryptocurrency addresses"""
        addresses = []

        # Bitcoin
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'
        addresses.extend(re.findall(btc_pattern, text))

        # Ethereum
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        addresses.extend(re.findall(eth_pattern, text))

        return list(set(addresses))

    def _extract_ip_addresses(self, text: str) -> List[str]:
        """Extract IP addresses"""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(pattern, text)

        # Filter out invalid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)

        return list(set(valid_ips))

    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names"""
        pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(pattern, text, re.IGNORECASE)
        return list(set(domains))

    def _calculate_risk_score(self, paste: PasteResult) -> int:
        """Calculate risk score for paste"""
        score = 0

        # Email addresses
        score += min(len(paste.emails_found) * 5, 30)

        # Passwords
        score += min(paste.passwords_found * 10, 40)

        # Crypto addresses
        score += min(len(paste.crypto_addresses) * 8, 25)

        # IP addresses (potential infrastructure info)
        score += min(len(paste.ip_addresses) * 3, 15)

        # Keywords (high value)
        high_value_keywords = ['database', 'dump', 'breach', 'hack', 'leaked', 'credentials']
        for keyword in paste.keywords_found:
            if any(hvk in keyword.lower() for hvk in high_value_keywords):
                score += 15

        return min(score, 100)

    def _classify_leak_type(self, paste: PasteResult) -> str:
        """Classify type of leak"""
        content_lower = paste.content.lower()

        if paste.passwords_found > 10:
            return 'credential_dump'
        elif len(paste.emails_found) > 20:
            return 'email_list'
        elif len(paste.crypto_addresses) > 5:
            return 'crypto_wallets'
        elif 'database' in content_lower or 'dump' in content_lower:
            return 'database_dump'
        elif len(paste.ip_addresses) > 10:
            return 'network_infrastructure'
        elif 'api' in content_lower and 'key' in content_lower:
            return 'api_keys'
        else:
            return 'unknown'

    async def search_pastes(
        self,
        keyword: str,
        site: Optional[str] = None,
        max_results: int = 50
    ) -> List[PasteResult]:
        """
        Search for specific keyword in pastes

        Args:
            keyword: Keyword to search
            site: Specific site to search (or all)
            max_results: Maximum results

        Returns:
            List of matching pastes
        """
        sites = [site] if site else list(self.PASTE_SITES.keys())

        all_results = []
        for s in sites:
            results = await self._monitor_site(s, [keyword])
            all_results.extend(results)

            if len(all_results) >= max_results:
                break

        return all_results[:max_results]

    def export_results(self, output_file: str):
        """Export monitoring results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'statistics': self.stats,
            'total_results': len(self.results),
            'results': [result.to_dict() for result in self.results]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results exported to {output_file}")

    def generate_report(self) -> str:
        """Generate paste monitoring report"""
        report = []
        report.append("# Paste Site Monitoring Report")
        report.append(f"Generated: {datetime.utcnow().isoformat()}\n")

        # Statistics
        report.append("## Statistics\n")
        report.append(f"- Total pastes monitored: {self.stats['total_pastes']}")
        report.append(f"- Credential dumps found: {self.stats['credentials_found']}")
        report.append(f"- High risk pastes: {self.stats['high_risk_pastes']}")
        report.append(f"- Total emails extracted: {self.stats['total_emails']}")
        report.append(f"- Total crypto addresses: {self.stats['total_crypto']}\n")

        # High risk pastes
        high_risk = [p for p in self.results if p.risk_score >= 80]
        if high_risk:
            report.append(f"## High Risk Pastes ({len(high_risk)})\n")
            for paste in high_risk[:10]:  # Top 10
                report.append(f"### {paste.title}")
                report.append(f"- Site: {paste.site}")
                report.append(f"- URL: {paste.url}")
                report.append(f"- Risk Score: {paste.risk_score}/100")
                report.append(f"- Leak Type: {paste.metadata.get('leak_type', 'unknown')}")
                report.append(f"- Emails: {len(paste.emails_found)}")
                report.append(f"- Passwords: {paste.passwords_found}\n")

        return '\n'.join(report)


async def main():
    """Example usage"""
    monitor = PasteMonitor()

    # Monitor paste sites
    print("[*] Starting paste site monitoring...")

    results = await monitor.monitor(
        keywords=["onecoin", "ruja ignatova", "database dump"],
        sites=["pastebin", "ghostbin"],
        continuous=False
    )

    print(f"\n[+] Found {len(results)} results")

    # Generate report
    report = monitor.generate_report()
    print(f"\n{report}")

    # Export results
    monitor.export_results("paste_monitor_results.json")
    print("[+] Results exported")


if __name__ == "__main__":
    asyncio.run(main())
