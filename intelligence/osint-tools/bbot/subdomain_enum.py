"""
Subdomain Enumeration Module
Advanced subdomain discovery using multiple techniques and sources
"""

import asyncio
import aiohttp
import dns.resolver
import dns.zone
import dns.query
import logging
import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
import socket
from pathlib import Path
import hashlib


@dataclass
class SubdomainResult:
    """Container for subdomain information"""
    subdomain: str
    ip_addresses: List[str]
    source: str
    cname: Optional[str] = None
    mx_records: Optional[List[str]] = None
    txt_records: Optional[List[str]] = None
    is_wildcard: bool = False


class SubdomainEnumerator:
    """
    Advanced subdomain enumeration using multiple sources and techniques
    """

    def __init__(self, config: Dict):
        """Initialize subdomain enumerator"""
        self.config = config.get('subdomain', {})
        self.timeout = config.get('timeout', 30)
        self.logger = logging.getLogger('SubdomainEnum')

        # DNS resolver configuration
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

        # Wordlists
        self.wordlists = {
            'small': self._get_small_wordlist(),
            'medium': self._get_medium_wordlist(),
            'large': self._get_large_wordlist()
        }

    async def enumerate(self, domain: str, deep_scan: bool = False) -> List[Dict]:
        """
        Enumerate subdomains using multiple techniques

        Args:
            domain: Target domain
            deep_scan: Enable deep scanning with brute force

        Returns:
            List of discovered subdomains with metadata
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")

        discovered_subdomains: Set[str] = set()
        subdomain_data: Dict[str, SubdomainResult] = {}

        # Check for wildcard DNS
        has_wildcard = await self._check_wildcard(domain)
        if has_wildcard:
            self.logger.warning(f"Wildcard DNS detected for {domain}")

        # Passive enumeration sources
        tasks = []
        sources = self.config.get('sources', ['crtsh', 'virustotal', 'hackertarget'])

        if 'crtsh' in sources:
            tasks.append(self._enum_crtsh(domain))
        if 'virustotal' in sources:
            tasks.append(self._enum_virustotal(domain))
        if 'hackertarget' in sources:
            tasks.append(self._enum_hackertarget(domain))
        if 'dnsdumpster' in sources:
            tasks.append(self._enum_dnsdumpster(domain))

        # Run passive enumeration
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Enumeration error: {result}")
                continue
            if result:
                discovered_subdomains.update(result)

        self.logger.info(f"Passive enumeration found {len(discovered_subdomains)} subdomains")

        # Active enumeration
        if deep_scan and self.config.get('brute_force', False):
            self.logger.info("Starting DNS brute force")
            brute_results = await self._brute_force_dns(domain)
            discovered_subdomains.update(brute_results)
            self.logger.info(f"Brute force found {len(brute_results)} additional subdomains")

        # Resolve all discovered subdomains
        for subdomain in discovered_subdomains:
            try:
                result = await self._resolve_subdomain(subdomain, domain)
                if result:
                    result.is_wildcard = has_wildcard
                    subdomain_data[subdomain] = result
            except Exception as e:
                self.logger.debug(f"Failed to resolve {subdomain}: {e}")

        # Try zone transfer (usually fails but worth trying)
        if deep_scan:
            zone_results = await self._try_zone_transfer(domain)
            for subdomain in zone_results:
                if subdomain not in subdomain_data:
                    result = await self._resolve_subdomain(subdomain, domain)
                    if result:
                        subdomain_data[subdomain] = result

        # Convert to list of dicts
        results_list = []
        for subdomain, data in subdomain_data.items():
            results_list.append({
                'subdomain': data.subdomain,
                'ip_addresses': data.ip_addresses,
                'source': data.source,
                'cname': data.cname,
                'mx_records': data.mx_records,
                'txt_records': data.txt_records,
                'is_wildcard': data.is_wildcard
            })

        self.logger.info(f"Total subdomains discovered: {len(results_list)}")
        return sorted(results_list, key=lambda x: x['subdomain'])

    async def _check_wildcard(self, domain: str) -> bool:
        """Check if domain has wildcard DNS configured"""
        random_subdomain = hashlib.md5(domain.encode()).hexdigest()[:16]
        test_domain = f"{random_subdomain}.{domain}"

        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, test_domain, 'A'
            )
            return True  # If random subdomain resolves, wildcard exists
        except:
            return False

    async def _enum_crtsh(self, domain: str) -> Set[str]:
        """Enumerate subdomains using crt.sh certificate transparency logs"""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Handle multiple domains in certificate
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip().lower()
                                # Remove wildcards
                                subdomain = subdomain.replace('*.', '')
                                if subdomain.endswith(domain) and subdomain != domain:
                                    subdomains.add(subdomain)

                        self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
        except Exception as e:
            self.logger.error(f"crt.sh enumeration failed: {e}")

        return subdomains

    async def _enum_virustotal(self, domain: str) -> Set[str]:
        """Enumerate subdomains using VirusTotal API (requires API key)"""
        subdomains = set()

        # Note: This requires a VirusTotal API key
        # For demo purposes, we'll return empty set
        # In production, implement with actual API key

        self.logger.debug("VirusTotal enumeration requires API key (skipped)")
        return subdomains

    async def _enum_hackertarget(self, domain: str) -> Set[str]:
        """Enumerate subdomains using HackerTarget API"""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                subdomain = line.split(',')[0].strip().lower()
                                if subdomain.endswith(domain):
                                    subdomains.add(subdomain)

                        self.logger.info(f"HackerTarget found {len(subdomains)} subdomains")
        except Exception as e:
            self.logger.error(f"HackerTarget enumeration failed: {e}")

        return subdomains

    async def _enum_dnsdumpster(self, domain: str) -> Set[str]:
        """Enumerate subdomains using DNSDumpster (requires scraping)"""
        subdomains = set()

        # Note: DNSDumpster requires CSRF token and session handling
        # For demo purposes, we'll return empty set
        # In production, implement proper scraping with session handling

        self.logger.debug("DNSDumpster enumeration requires session handling (skipped)")
        return subdomains

    async def _brute_force_dns(self, domain: str) -> Set[str]:
        """Brute force DNS enumeration using wordlist"""
        subdomains = set()
        wordlist_size = self.config.get('wordlist_size', 'medium')
        wordlist = self.wordlists.get(wordlist_size, self.wordlists['medium'])

        self.logger.info(f"Starting DNS brute force with {len(wordlist)} words")

        # Limit concurrent tasks to avoid overwhelming DNS servers
        semaphore = asyncio.Semaphore(50)

        async def check_subdomain(word: str):
            async with semaphore:
                subdomain = f"{word}.{domain}"
                try:
                    await asyncio.to_thread(self.resolver.resolve, subdomain, 'A')
                    return subdomain
                except:
                    return None

        tasks = [check_subdomain(word) for word in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                subdomains.add(result)

        return subdomains

    async def _resolve_subdomain(self, subdomain: str, base_domain: str) -> Optional[SubdomainResult]:
        """Resolve subdomain and gather DNS information"""
        ip_addresses = []
        cname = None
        mx_records = []
        txt_records = []

        try:
            # A records
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, subdomain, 'A'
                )
                ip_addresses.extend([str(rdata) for rdata in answers])
            except:
                pass

            # AAAA records (IPv6)
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, subdomain, 'AAAA'
                )
                ip_addresses.extend([str(rdata) for rdata in answers])
            except:
                pass

            # CNAME records
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, subdomain, 'CNAME'
                )
                cname = str(answers[0].target)
            except:
                pass

            # MX records
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, subdomain, 'MX'
                )
                mx_records = [str(rdata.exchange) for rdata in answers]
            except:
                pass

            # TXT records
            try:
                answers = await asyncio.to_thread(
                    self.resolver.resolve, subdomain, 'TXT'
                )
                txt_records = [str(rdata) for rdata in answers]
            except:
                pass

            if ip_addresses or cname:
                return SubdomainResult(
                    subdomain=subdomain,
                    ip_addresses=ip_addresses,
                    source='resolution',
                    cname=cname,
                    mx_records=mx_records if mx_records else None,
                    txt_records=txt_records if txt_records else None
                )

        except Exception as e:
            self.logger.debug(f"Resolution error for {subdomain}: {e}")

        return None

    async def _try_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer (AXFR)"""
        subdomains = set()

        try:
            # Get nameservers for domain
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, 'NS'
            )

            for ns in answers:
                ns_name = str(ns.target)
                try:
                    # Try zone transfer
                    zone = await asyncio.to_thread(
                        dns.zone.from_xfr,
                        dns.query.xfr(ns_name, domain, timeout=10)
                    )

                    # Extract subdomains
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            subdomains.add(subdomain)

                    self.logger.warning(f"Zone transfer successful on {ns_name}!")
                    break

                except Exception as e:
                    self.logger.debug(f"Zone transfer failed on {ns_name}: {e}")

        except Exception as e:
            self.logger.debug(f"Could not get nameservers: {e}")

        return subdomains

    def _get_small_wordlist(self) -> List[str]:
        """Get small wordlist for subdomain brute forcing"""
        return [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
            'webmail', 'admin', 'localhost', 'webdisk', 'cpanel', 'whm',
            'autodiscover', 'autoconfig', 'mobile', 'remote', 'blog',
            'dev', 'stage', 'staging', 'test', 'api', 'beta', 'vpn',
            'cdn', 'cloud', 'portal', 'secure', 'shop', 'store'
        ]

    def _get_medium_wordlist(self) -> List[str]:
        """Get medium wordlist for subdomain brute forcing"""
        small = self._get_small_wordlist()
        additional = [
            'm', 'ww1', 'ww2', 'exchange', 'mx', 'mx1', 'mx2', 'imap',
            'owa', 'news', 'db', 'mysql', 'forum', 'search', 'help',
            'support', 'apps', 'redirect', 'sso', 'direct', 'accounts',
            'images', 'img', 'video', 'videos', 'download', 'downloads',
            'upload', 'uploads', 'file', 'files', 'static', 'assets',
            'data', 'backup', 'backups', 'admin', 'administrator',
            'panel', 'dashboard', 'login', 'signin', 'signup', 'register',
            'git', 'svn', 'jenkins', 'ci', 'cd', 'staging', 'production',
            'prod', 'uat', 'qa', 'development', 'demo', 'sandbox',
            'internal', 'external', 'intranet', 'extranet', 'old',
            'new', 'legacy', 'v1', 'v2', 'app', 'application'
        ]
        return small + additional

    def _get_large_wordlist(self) -> List[str]:
        """Get large wordlist for subdomain brute forcing"""
        medium = self._get_medium_wordlist()
        additional = [
            f'www{i}' for i in range(1, 11)
        ] + [
            f'mail{i}' for i in range(1, 6)
        ] + [
            f'ns{i}' for i in range(1, 11)
        ] + [
            f'mx{i}' for i in range(1, 6)
        ] + [
            f'server{i}' for i in range(1, 11)
        ] + [
            'cpanel', 'whm', 'webmail', 'email', 'direct-connect',
            'direct', 'cpcontacts', 'cpcalendars', 'cpanelwebcall',
            'autodiscover', '_domainkey', 'default', '_dmarc',
            'autoconfig', '_autodiscover', 'mail2', 'smtp1', 'smtp2',
            'pop3', 'imap4', 'ns', 'dns', 'dns1', 'dns2', 'eshop',
            'shop', 'forum', 'blog', 'chat', 'conference', 'calendar'
        ]
        return medium + additional


async def main():
    """Test subdomain enumeration"""
    config = {
        'subdomain': {
            'sources': ['crtsh', 'hackertarget'],
            'brute_force': True,
            'wordlist_size': 'small'
        },
        'timeout': 30
    }

    enumerator = SubdomainEnumerator(config)
    results = await enumerator.enumerate('example.com', deep_scan=False)

    print(f"\nFound {len(results)} subdomains:")
    for result in results[:10]:  # Show first 10
        print(f"  {result['subdomain']} -> {result['ip_addresses']}")


if __name__ == '__main__':
    asyncio.run(main())
