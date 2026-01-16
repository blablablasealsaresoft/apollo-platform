#!/usr/bin/env python3
"""
Enhanced Paste Site Monitor
Comprehensive monitoring of paste sites for leaked data

This module provides:
- Pastebin API integration
- GitHub Gist monitoring
- Alternative paste site monitoring
- Keyword/regex alerting
- Credential leak detection
- Real-time monitoring via websockets/polling
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Any, Set, Pattern
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import re
import logging
import hashlib
from enum import Enum
from pathlib import Path


class PasteSeverity(Enum):
    """Paste severity levels"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class PasteType(Enum):
    """Types of paste content"""
    UNKNOWN = "unknown"
    CREDENTIALS = "credentials"
    DATABASE_DUMP = "database_dump"
    EMAIL_LIST = "email_list"
    API_KEYS = "api_keys"
    CONFIG_FILE = "config_file"
    SOURCE_CODE = "source_code"
    PII = "pii"
    CRYPTO_WALLETS = "crypto_wallets"
    NETWORK_INFO = "network_info"


@dataclass
class ExtractedData:
    """Data extracted from paste content"""
    emails: List[str] = field(default_factory=list)
    passwords: int = 0
    hashes: List[Dict[str, str]] = field(default_factory=list)
    api_keys: List[Dict[str, str]] = field(default_factory=list)
    crypto_addresses: Dict[str, List[str]] = field(default_factory=dict)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    credit_cards: int = 0
    ssn_count: int = 0
    urls: List[str] = field(default_factory=list)
    onion_urls: List[str] = field(default_factory=list)


@dataclass
class PasteRecord:
    """Enhanced paste record with detailed analysis"""
    paste_id: str
    site: str
    url: str
    title: str
    author: str
    content: str
    raw_size: int
    language: Optional[str]
    created: datetime
    expires: Optional[datetime]
    views: Optional[int]

    # Analysis results
    keywords_matched: List[str] = field(default_factory=list)
    extracted_data: ExtractedData = field(default_factory=ExtractedData)
    paste_type: PasteType = PasteType.UNKNOWN
    severity: PasteSeverity = PasteSeverity.INFO
    risk_score: int = 0
    is_encrypted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_content: bool = False) -> Dict[str, Any]:
        data = {
            'paste_id': self.paste_id,
            'site': self.site,
            'url': self.url,
            'title': self.title,
            'author': self.author,
            'raw_size': self.raw_size,
            'language': self.language,
            'created': self.created.isoformat(),
            'expires': self.expires.isoformat() if self.expires else None,
            'views': self.views,
            'keywords_matched': self.keywords_matched,
            'paste_type': self.paste_type.value,
            'severity': self.severity.name,
            'risk_score': self.risk_score,
            'is_encrypted': self.is_encrypted,
            'extracted_data': {
                'emails_count': len(self.extracted_data.emails),
                'passwords_count': self.extracted_data.passwords,
                'hashes_count': len(self.extracted_data.hashes),
                'api_keys_count': len(self.extracted_data.api_keys),
                'crypto_addresses': {
                    k: len(v) for k, v in self.extracted_data.crypto_addresses.items()
                },
                'ip_addresses_count': len(self.extracted_data.ip_addresses),
                'domains_count': len(self.extracted_data.domains),
                'onion_urls_count': len(self.extracted_data.onion_urls)
            },
            'metadata': self.metadata
        }

        if include_content:
            # Truncate content for safety
            data['content_preview'] = self.content[:500] if self.content else ''

        return data


@dataclass
class MonitoringRule:
    """Rule for paste monitoring"""
    rule_id: str
    name: str
    keywords: List[str] = field(default_factory=list)
    regex_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    min_severity: PasteSeverity = PasteSeverity.LOW
    sites: List[str] = field(default_factory=list)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    matches: int = 0


class PasteMonitorEnhanced:
    """
    Enhanced paste site monitoring system

    Supports:
    - Pastebin (Pro API)
    - GitHub Gist
    - Ghostbin, Rentry, 0bin
    - Custom paste sites
    """

    # Paste site configurations
    PASTE_SITES = {
        "pastebin": {
            "name": "Pastebin",
            "base_url": "https://pastebin.com",
            "api_url": "https://scrape.pastebin.com/api_scraping.php",
            "raw_url": "https://pastebin.com/raw/{}",
            "requires_api": True,
            "rate_limit": 1,  # seconds between requests
            "supports_scraping": True
        },
        "github_gist": {
            "name": "GitHub Gist",
            "base_url": "https://gist.github.com",
            "api_url": "https://api.github.com/gists/public",
            "raw_url": "https://gist.githubusercontent.com/{}/raw",
            "requires_api": False,
            "rate_limit": 0.5,
            "supports_scraping": True
        },
        "rentry": {
            "name": "Rentry",
            "base_url": "https://rentry.co",
            "raw_url": "https://rentry.co/{}/raw",
            "requires_api": False,
            "rate_limit": 2,
            "supports_scraping": False
        },
        "dpaste": {
            "name": "dpaste",
            "base_url": "https://dpaste.org",
            "api_url": "https://dpaste.org/api/",
            "raw_url": "https://dpaste.org/{}/raw",
            "requires_api": False,
            "rate_limit": 2,
            "supports_scraping": True
        },
        "ghostbin": {
            "name": "Ghostbin",
            "base_url": "https://ghostbin.com",
            "raw_url": "https://ghostbin.com/{}/raw",
            "requires_api": False,
            "rate_limit": 2,
            "supports_scraping": False
        },
        "hastebin": {
            "name": "Hastebin",
            "base_url": "https://hastebin.com",
            "raw_url": "https://hastebin.com/raw/{}",
            "requires_api": False,
            "rate_limit": 2,
            "supports_scraping": False
        }
    }

    # Detection patterns
    DETECTION_PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'password_combo': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[:;,|]\S+',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'btc_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b',
        'eth_address': r'\b0x[a-fA-F0-9]{40}\b',
        'xmr_address': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        'md5_hash': r'\b[a-fA-F0-9]{32}\b',
        'sha1_hash': r'\b[a-fA-F0-9]{40}\b',
        'sha256_hash': r'\b[a-fA-F0-9]{64}\b',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret': r'[A-Za-z0-9/+=]{40}',
        'github_token': r'ghp_[a-zA-Z0-9]{36}',
        'google_api_key': r'AIza[0-9A-Za-z\\-_]{35}',
        'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'private_key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        'onion_url': r'https?://[a-z2-7]{16,56}\.onion[^\s]*',
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
    }

    def __init__(
        self,
        pastebin_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
        output_dir: str = "paste_monitor_results"
    ):
        """
        Initialize paste monitor

        Args:
            pastebin_api_key: Pastebin Pro API key (for scraping API)
            github_token: GitHub personal access token
            output_dir: Directory for output files
        """
        self.pastebin_api_key = pastebin_api_key
        self.github_token = github_token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.logger = self._setup_logging()

        # Compiled patterns
        self._compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.DETECTION_PATTERNS.items()
        }

        # State
        self.pastes: List[PasteRecord] = []
        self.seen_paste_ids: Set[str] = set()
        self.monitoring_rules: Dict[str, MonitoringRule] = {}
        self.alerts: List[Dict[str, Any]] = []

        # Statistics
        self.stats = {
            'total_pastes': 0,
            'by_site': {},
            'by_severity': {},
            'credentials_found': 0,
            'api_keys_found': 0,
            'crypto_addresses_found': 0,
            'start_time': None,
            'last_scan': None
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("PasteMonitorEnhanced")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def start_monitoring(
        self,
        keywords: List[str],
        sites: Optional[List[str]] = None,
        interval: int = 60,
        duration: Optional[int] = None,
        callback: Optional[callable] = None
    ) -> List[PasteRecord]:
        """
        Start monitoring paste sites

        Args:
            keywords: Keywords to monitor
            sites: Sites to monitor (default: all supported)
            interval: Scan interval in seconds
            duration: Total duration in seconds (None = continuous)
            callback: Callback function for new pastes

        Returns:
            List of found pastes
        """
        sites = sites or list(self.PASTE_SITES.keys())
        self.logger.info(f"Starting paste monitoring for {len(sites)} sites")
        self.logger.info(f"Keywords: {keywords}")

        self.stats['start_time'] = datetime.utcnow()
        start_time = datetime.utcnow()
        found_pastes = []

        try:
            while True:
                # Check duration limit
                if duration:
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    if elapsed >= duration:
                        self.logger.info("Duration limit reached")
                        break

                # Scan all sites
                for site in sites:
                    try:
                        new_pastes = await self._scan_site(site, keywords)

                        for paste in new_pastes:
                            if paste.paste_id not in self.seen_paste_ids:
                                self.seen_paste_ids.add(paste.paste_id)
                                found_pastes.append(paste)
                                self.pastes.append(paste)

                                # Update statistics
                                self._update_stats(paste)

                                # Check monitoring rules
                                await self._check_rules(paste)

                                # Call callback if provided
                                if callback:
                                    await callback(paste)

                                self.logger.info(
                                    f"New paste: {paste.url} "
                                    f"(severity: {paste.severity.name}, score: {paste.risk_score})"
                                )

                    except Exception as e:
                        self.logger.error(f"Error scanning {site}: {e}")

                self.stats['last_scan'] = datetime.utcnow()

                # Wait for next interval
                self.logger.debug(f"Waiting {interval}s until next scan")
                await asyncio.sleep(interval)

        except asyncio.CancelledError:
            self.logger.info("Monitoring cancelled")

        return found_pastes

    async def _scan_site(
        self,
        site: str,
        keywords: List[str]
    ) -> List[PasteRecord]:
        """
        Scan specific paste site

        Args:
            site: Site name
            keywords: Keywords to search for

        Returns:
            List of matching pastes
        """
        if site not in self.PASTE_SITES:
            return []

        config = self.PASTE_SITES[site]

        if site == "pastebin":
            return await self._scan_pastebin(keywords)
        elif site == "github_gist":
            return await self._scan_github_gist(keywords)
        else:
            # Generic scanning for other sites
            return await self._scan_generic_site(site, keywords)

    async def _scan_pastebin(self, keywords: List[str]) -> List[PasteRecord]:
        """
        Scan Pastebin using scraping API

        Args:
            keywords: Keywords to search for

        Returns:
            List of matching pastes
        """
        pastes = []

        if not self.pastebin_api_key:
            self.logger.warning(
                "Pastebin API key not configured. "
                "Get a Pro account at https://pastebin.com/pro"
            )
            return pastes

        try:
            async with aiohttp.ClientSession() as session:
                # Get recent pastes
                params = {'limit': 250}  # Max allowed
                headers = {'User-Agent': 'Apollo-Intelligence-Platform'}

                async with session.get(
                    self.PASTE_SITES['pastebin']['api_url'],
                    params=params,
                    headers=headers,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for item in data:
                            paste_key = item.get('key', '')

                            # Get paste content
                            raw_url = self.PASTE_SITES['pastebin']['raw_url'].format(paste_key)

                            try:
                                async with session.get(raw_url, timeout=15) as raw_response:
                                    if raw_response.status == 200:
                                        content = await raw_response.text()

                                        # Check for keyword matches
                                        matched_keywords = self._check_keywords(content, keywords)

                                        if matched_keywords or self._contains_sensitive_data(content):
                                            paste = PasteRecord(
                                                paste_id=paste_key,
                                                site='pastebin',
                                                url=f"https://pastebin.com/{paste_key}",
                                                title=item.get('title', 'Untitled'),
                                                author=item.get('user', 'Anonymous'),
                                                content=content,
                                                raw_size=item.get('size', len(content)),
                                                language=item.get('syntax'),
                                                created=datetime.fromtimestamp(
                                                    int(item.get('date', 0))
                                                ) if item.get('date') else datetime.utcnow(),
                                                expires=datetime.fromtimestamp(
                                                    int(item.get('expire', 0))
                                                ) if item.get('expire') else None,
                                                views=item.get('hits'),
                                                keywords_matched=matched_keywords
                                            )

                                            # Analyze paste
                                            self._analyze_paste(paste)
                                            pastes.append(paste)

                            except Exception as e:
                                self.logger.debug(f"Error fetching paste {paste_key}: {e}")

                            # Rate limiting
                            await asyncio.sleep(
                                self.PASTE_SITES['pastebin']['rate_limit']
                            )

                    else:
                        self.logger.warning(f"Pastebin API returned {response.status}")

        except Exception as e:
            self.logger.error(f"Pastebin scan error: {e}")

        return pastes

    async def _scan_github_gist(self, keywords: List[str]) -> List[PasteRecord]:
        """
        Scan GitHub Gist for public gists

        Args:
            keywords: Keywords to search for

        Returns:
            List of matching pastes
        """
        pastes = []

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Apollo-Intelligence-Platform'
                }

                if self.github_token:
                    headers['Authorization'] = f'token {self.github_token}'

                # Get public gists
                async with session.get(
                    self.PASTE_SITES['github_gist']['api_url'],
                    headers=headers,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for gist in data:
                            gist_id = gist.get('id', '')

                            # Get files in gist
                            files = gist.get('files', {})
                            for filename, file_info in files.items():
                                raw_url = file_info.get('raw_url', '')

                                if not raw_url:
                                    continue

                                try:
                                    async with session.get(
                                        raw_url,
                                        headers=headers,
                                        timeout=15
                                    ) as raw_response:
                                        if raw_response.status == 200:
                                            content = await raw_response.text()

                                            # Check for keyword matches
                                            matched_keywords = self._check_keywords(content, keywords)

                                            if matched_keywords or self._contains_sensitive_data(content):
                                                paste = PasteRecord(
                                                    paste_id=f"{gist_id}_{filename}",
                                                    site='github_gist',
                                                    url=gist.get('html_url', ''),
                                                    title=gist.get('description', filename),
                                                    author=gist.get('owner', {}).get('login', 'Anonymous'),
                                                    content=content,
                                                    raw_size=file_info.get('size', len(content)),
                                                    language=file_info.get('language'),
                                                    created=datetime.fromisoformat(
                                                        gist.get('created_at', '').replace('Z', '+00:00')
                                                    ) if gist.get('created_at') else datetime.utcnow(),
                                                    expires=None,
                                                    views=None,
                                                    keywords_matched=matched_keywords,
                                                    metadata={
                                                        'filename': filename,
                                                        'public': gist.get('public', True)
                                                    }
                                                )

                                                # Analyze paste
                                                self._analyze_paste(paste)
                                                pastes.append(paste)

                                except Exception as e:
                                    self.logger.debug(f"Error fetching gist {gist_id}: {e}")

                            # Rate limiting
                            await asyncio.sleep(
                                self.PASTE_SITES['github_gist']['rate_limit']
                            )

                    elif response.status == 403:
                        self.logger.warning("GitHub API rate limit exceeded")
                    else:
                        self.logger.warning(f"GitHub API returned {response.status}")

        except Exception as e:
            self.logger.error(f"GitHub Gist scan error: {e}")

        return pastes

    async def _scan_generic_site(
        self,
        site: str,
        keywords: List[str]
    ) -> List[PasteRecord]:
        """
        Generic paste site scanning (placeholder for sites without APIs)
        """
        self.logger.debug(f"Generic scanning for {site} not implemented")
        return []

    def _check_keywords(self, content: str, keywords: List[str]) -> List[str]:
        """Check content for keyword matches"""
        matched = []
        content_lower = content.lower()

        for keyword in keywords:
            if keyword.lower() in content_lower:
                matched.append(keyword)

        return matched

    def _contains_sensitive_data(self, content: str) -> bool:
        """Quick check for sensitive data patterns"""
        # Check for obvious sensitive data
        sensitive_patterns = [
            self._compiled_patterns['password_combo'],
            self._compiled_patterns['private_key'],
            self._compiled_patterns['aws_key'],
            self._compiled_patterns['credit_card']
        ]

        for pattern in sensitive_patterns:
            if pattern.search(content):
                return True

        return False

    def _analyze_paste(self, paste: PasteRecord):
        """
        Analyze paste content for sensitive data

        Args:
            paste: PasteRecord to analyze
        """
        content = paste.content
        extracted = ExtractedData()

        # Extract emails
        emails = self._compiled_patterns['email'].findall(content)
        extracted.emails = list(set(emails))

        # Count password combos
        password_combos = self._compiled_patterns['password_combo'].findall(content)
        extracted.passwords = len(password_combos)

        # Extract hashes
        for hash_type in ['md5_hash', 'sha1_hash', 'sha256_hash']:
            matches = self._compiled_patterns[hash_type].findall(content)
            for match in matches[:100]:  # Limit to prevent memory issues
                extracted.hashes.append({
                    'type': hash_type.replace('_hash', ''),
                    'value': match
                })

        # Extract API keys
        for key_type in ['aws_key', 'github_token', 'google_api_key', 'slack_token']:
            matches = self._compiled_patterns[key_type].findall(content)
            for match in matches:
                extracted.api_keys.append({
                    'type': key_type,
                    'value': match[:20] + '...'  # Truncate for safety
                })

        # Extract crypto addresses
        for crypto in ['btc_address', 'eth_address', 'xmr_address']:
            matches = self._compiled_patterns[crypto].findall(content)
            if matches:
                crypto_name = crypto.replace('_address', '')
                extracted.crypto_addresses[crypto_name] = list(set(matches))

        # Extract IPs
        ip_matches = self._compiled_patterns['ip_address'].findall(content)
        extracted.ip_addresses = list(set(ip_matches))

        # Extract domains
        domain_matches = self._compiled_patterns['domain'].findall(content)
        extracted.domains = list(set(domain_matches))[:100]

        # Extract onion URLs
        onion_matches = self._compiled_patterns['onion_url'].findall(content)
        extracted.onion_urls = list(set(onion_matches))

        # Extract regular URLs
        url_matches = self._compiled_patterns['url'].findall(content)
        extracted.urls = list(set(url_matches))[:100]

        # Count credit cards
        cc_matches = self._compiled_patterns['credit_card'].findall(content)
        extracted.credit_cards = len(cc_matches)

        # Count potential SSNs
        ssn_matches = self._compiled_patterns['ssn'].findall(content)
        extracted.ssn_count = len(ssn_matches)

        # Check for private keys
        paste.is_encrypted = bool(self._compiled_patterns['private_key'].search(content))

        paste.extracted_data = extracted

        # Classify paste type
        paste.paste_type = self._classify_paste_type(paste)

        # Calculate risk score and severity
        paste.risk_score = self._calculate_risk_score(paste)
        paste.severity = self._determine_severity(paste)

    def _classify_paste_type(self, paste: PasteRecord) -> PasteType:
        """Classify the type of paste based on content"""
        extracted = paste.extracted_data

        if extracted.passwords > 10:
            return PasteType.CREDENTIALS
        elif extracted.credit_cards > 0 or extracted.ssn_count > 0:
            return PasteType.PII
        elif len(extracted.api_keys) > 0:
            return PasteType.API_KEYS
        elif len(extracted.emails) > 50:
            return PasteType.EMAIL_LIST
        elif any(extracted.crypto_addresses.values()):
            return PasteType.CRYPTO_WALLETS
        elif len(extracted.ip_addresses) > 10:
            return PasteType.NETWORK_INFO
        elif paste.is_encrypted:
            return PasteType.CONFIG_FILE

        return PasteType.UNKNOWN

    def _calculate_risk_score(self, paste: PasteRecord) -> int:
        """Calculate risk score (0-100)"""
        score = 0
        extracted = paste.extracted_data

        # Credentials are high risk
        score += min(extracted.passwords * 5, 30)

        # Credit cards are critical
        score += min(extracted.credit_cards * 15, 30)

        # SSNs are critical
        score += min(extracted.ssn_count * 20, 40)

        # API keys are high risk
        score += min(len(extracted.api_keys) * 10, 30)

        # Private keys are critical
        if paste.is_encrypted:
            score += 25

        # Large email lists
        if len(extracted.emails) > 100:
            score += 20
        elif len(extracted.emails) > 20:
            score += 10

        # Crypto addresses
        total_crypto = sum(len(addrs) for addrs in extracted.crypto_addresses.values())
        score += min(total_crypto * 3, 15)

        # Onion URLs
        score += min(len(extracted.onion_urls) * 5, 15)

        # Keyword matches boost score
        score += len(paste.keywords_matched) * 5

        return min(score, 100)

    def _determine_severity(self, paste: PasteRecord) -> PasteSeverity:
        """Determine severity level based on risk score and content"""
        extracted = paste.extracted_data

        # Critical: Credit cards, SSNs, or private keys
        if (extracted.credit_cards > 0 or
            extracted.ssn_count > 0 or
            paste.is_encrypted or
            paste.risk_score >= 80):
            return PasteSeverity.CRITICAL

        # High: Large credential dumps or API keys
        if (extracted.passwords > 50 or
            len(extracted.api_keys) > 0 or
            paste.risk_score >= 60):
            return PasteSeverity.HIGH

        # Medium: Some credentials or large email list
        if (extracted.passwords > 5 or
            len(extracted.emails) > 50 or
            paste.risk_score >= 40):
            return PasteSeverity.MEDIUM

        # Low: Some data extracted
        if paste.risk_score >= 20:
            return PasteSeverity.LOW

        return PasteSeverity.INFO

    def _update_stats(self, paste: PasteRecord):
        """Update statistics with new paste"""
        self.stats['total_pastes'] += 1

        # By site
        if paste.site not in self.stats['by_site']:
            self.stats['by_site'][paste.site] = 0
        self.stats['by_site'][paste.site] += 1

        # By severity
        sev_name = paste.severity.name
        if sev_name not in self.stats['by_severity']:
            self.stats['by_severity'][sev_name] = 0
        self.stats['by_severity'][sev_name] += 1

        # Specific counts
        if paste.extracted_data.passwords > 0:
            self.stats['credentials_found'] += paste.extracted_data.passwords

        if len(paste.extracted_data.api_keys) > 0:
            self.stats['api_keys_found'] += len(paste.extracted_data.api_keys)

        total_crypto = sum(
            len(addrs) for addrs in paste.extracted_data.crypto_addresses.values()
        )
        self.stats['crypto_addresses_found'] += total_crypto

    # Monitoring Rules

    def add_monitoring_rule(
        self,
        name: str,
        keywords: Optional[List[str]] = None,
        regex_patterns: Optional[List[str]] = None,
        min_severity: PasteSeverity = PasteSeverity.LOW,
        sites: Optional[List[str]] = None
    ) -> str:
        """Add a monitoring rule"""
        rule_id = hashlib.md5(f"{name}_{datetime.utcnow()}".encode()).hexdigest()[:12]

        rule = MonitoringRule(
            rule_id=rule_id,
            name=name,
            keywords=keywords or [],
            regex_patterns=regex_patterns or [],
            min_severity=min_severity,
            sites=sites or []
        )

        self.monitoring_rules[rule_id] = rule
        self.logger.info(f"Added monitoring rule: {name} (ID: {rule_id})")

        return rule_id

    async def _check_rules(self, paste: PasteRecord):
        """Check paste against monitoring rules"""
        for rule_id, rule in self.monitoring_rules.items():
            if not rule.enabled:
                continue

            # Check site filter
            if rule.sites and paste.site not in rule.sites:
                continue

            # Check severity threshold
            if paste.severity.value < rule.min_severity.value:
                continue

            matched = False

            # Check keywords
            for keyword in rule.keywords:
                if keyword.lower() in paste.content.lower():
                    matched = True
                    break

            # Check regex patterns
            if not matched:
                for pattern in rule.regex_patterns:
                    try:
                        if re.search(pattern, paste.content, re.IGNORECASE):
                            matched = True
                            break
                    except re.error:
                        self.logger.warning(f"Invalid regex pattern in rule {rule_id}")

            if matched:
                rule.matches += 1
                alert = {
                    'alert_id': hashlib.md5(f"{rule_id}_{paste.paste_id}".encode()).hexdigest()[:12],
                    'rule_id': rule_id,
                    'rule_name': rule.name,
                    'paste': paste.to_dict(),
                    'timestamp': datetime.utcnow().isoformat()
                }
                self.alerts.append(alert)
                self.logger.warning(f"Rule '{rule.name}' matched paste {paste.paste_id}")

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alerts[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            **self.stats,
            'monitoring_rules': len(self.monitoring_rules),
            'total_alerts': len(self.alerts),
            'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
            'last_scan': self.stats['last_scan'].isoformat() if self.stats['last_scan'] else None
        }

    def export_results(self, output_file: str, include_content: bool = False):
        """Export monitoring results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'statistics': self.get_statistics(),
            'pastes': [p.to_dict(include_content) for p in self.pastes],
            'alerts': self.alerts
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results exported to {output_file}")


async def main():
    """Example usage"""
    monitor = PasteMonitorEnhanced(
        pastebin_api_key=None,  # Get from pastebin.com/pro
        github_token=None  # Optional GitHub token
    )

    print("[*] Apollo Enhanced Paste Monitor")
    print("=" * 50)

    # Add monitoring rules
    monitor.add_monitoring_rule(
        name="Credential Leaks",
        keywords=["password", "credentials", "dump"],
        min_severity=PasteSeverity.MEDIUM
    )

    monitor.add_monitoring_rule(
        name="API Key Exposure",
        regex_patterns=[r'AKIA[0-9A-Z]{16}', r'ghp_[a-zA-Z0-9]{36}'],
        min_severity=PasteSeverity.HIGH
    )

    print("\n[*] Starting monitoring (5 minute demo)...")
    print("    Note: Full functionality requires Pastebin Pro API key")

    # Start monitoring
    results = await monitor.start_monitoring(
        keywords=["database", "leak", "password", "credentials"],
        sites=["github_gist"],  # Using GitHub Gist as it doesn't require API key
        interval=30,
        duration=300  # 5 minutes for demo
    )

    print(f"\n[+] Found {len(results)} pastes")

    # Get statistics
    stats = monitor.get_statistics()
    print(f"\n[*] Statistics:")
    for key, value in stats.items():
        print(f"    {key}: {value}")

    # Get alerts
    alerts = monitor.get_alerts()
    print(f"\n[*] Alerts: {len(alerts)}")

    # Export results
    monitor.export_results("paste_monitor_results.json")
    print("\n[+] Results exported")


if __name__ == "__main__":
    asyncio.run(main())
