"""
Subdomain Enumeration Module - Red Team Edition
================================================

Advanced subdomain discovery using multiple techniques and sources.
Designed for red team reconnaissance operations.

Features:
- Certificate transparency logs (crt.sh, CertSpotter)
- API-based enumeration (HackerTarget, VirusTotal)
- DNS brute forcing with smart wordlists
- Zone transfer attempts
- Permutation generation

Author: Apollo Red Team Toolkit
Version: 2.0.0
"""

import asyncio
import aiohttp
import dns.resolver
import dns.zone
import dns.query
import logging
import hashlib
from typing import List, Dict, Set, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Container for subdomain enumeration result"""
    subdomain: str
    ip_addresses: List[str]
    source: str
    cname: Optional[str] = None
    is_wildcard: bool = False


class SubdomainEnumerator:
    """
    Advanced subdomain enumeration for red team operations

    Uses multiple techniques:
    - Passive: Certificate transparency, API queries
    - Active: DNS brute force, zone transfer
    - Smart: Permutation generation, pattern detection
    """

    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
        'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
        'mx', 'mx1', 'mx2', 'email',
        'admin', 'administrator', 'panel', 'cpanel', 'whm',
        'api', 'app', 'apps', 'mobile', 'm',
        'dev', 'development', 'staging', 'stage', 'test', 'testing',
        'prod', 'production', 'live', 'demo', 'sandbox',
        'vpn', 'remote', 'rdp', 'gateway', 'gw',
        'portal', 'intranet', 'extranet', 'internal', 'external',
        'blog', 'news', 'forum', 'community', 'support', 'help',
        'shop', 'store', 'cart', 'checkout', 'payment',
        'cdn', 'static', 'assets', 'img', 'images', 'media',
        'git', 'svn', 'repo', 'jenkins', 'ci', 'build',
        'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
        'backup', 'backups', 'bak', 'old', 'new', 'legacy',
        'secure', 'ssl', 'login', 'auth', 'sso',
        'cloud', 'aws', 'azure', 'gcp',
        'office', 'mail2', 'smtp2', 'autodiscover',
        'video', 'streaming', 'stream', 'download', 'downloads',
        'files', 'file', 'upload', 'uploads', 'share'
    ]

    def __init__(self, timeout: int = 30, max_concurrent: int = 50):
        """
        Initialize subdomain enumerator

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def enumerate(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        brute_force: bool = False,
        wordlist: Optional[List[str]] = None
    ) -> List[SubdomainResult]:
        """
        Enumerate subdomains using multiple sources

        Args:
            domain: Target domain
            sources: List of sources to use (crtsh, hackertarget, certspotter, virustotal)
            brute_force: Enable DNS brute forcing
            wordlist: Custom wordlist for brute forcing

        Returns:
            List of SubdomainResult objects
        """
        logger.info(f"Starting subdomain enumeration for {domain}")

        if sources is None:
            sources = ['crtsh', 'hackertarget', 'certspotter']

        discovered: Set[str] = set()
        results: List[SubdomainResult] = []

        # Check for wildcard DNS
        has_wildcard = await self._check_wildcard(domain)
        if has_wildcard:
            logger.warning(f"Wildcard DNS detected for {domain}")

        # Passive enumeration
        tasks = []
        if 'crtsh' in sources:
            tasks.append(self._enum_crtsh(domain))
        if 'hackertarget' in sources:
            tasks.append(self._enum_hackertarget(domain))
        if 'certspotter' in sources:
            tasks.append(self._enum_certspotter(domain))
        if 'virustotal' in sources:
            tasks.append(self._enum_virustotal(domain))

        # Run passive enumeration
        enum_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in enum_results:
            if isinstance(result, Exception):
                logger.error(f"Enumeration error: {result}")
                continue
            if result:
                discovered.update(result)

        logger.info(f"Passive enumeration found {len(discovered)} subdomains")

        # DNS brute force
        if brute_force:
            logger.info("Starting DNS brute force")
            wordlist_to_use = wordlist or self.COMMON_SUBDOMAINS
            brute_results = await self._brute_force(domain, wordlist_to_use)
            discovered.update(brute_results)
            logger.info(f"Brute force found {len(brute_results)} additional subdomains")

        # Zone transfer attempt
        zone_results = await self._try_zone_transfer(domain)
        discovered.update(zone_results)

        # Resolve all discovered subdomains
        for subdomain in discovered:
            try:
                result = await self._resolve_subdomain(subdomain)
                if result:
                    result.is_wildcard = has_wildcard
                    results.append(result)
            except Exception as e:
                logger.debug(f"Failed to resolve {subdomain}: {e}")

        logger.info(f"Total subdomains discovered: {len(results)}")
        return results

    async def _check_wildcard(self, domain: str) -> bool:
        """Check if domain has wildcard DNS"""
        random_subdomain = hashlib.md5(domain.encode()).hexdigest()[:16]
        test_domain = f"{random_subdomain}.{domain}"

        try:
            await asyncio.to_thread(self.resolver.resolve, test_domain, 'A')
            return True
        except:
            return False

    async def _enum_crtsh(self, domain: str) -> Set[str]:
        """Enumerate using crt.sh certificate transparency"""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                for subdomain in name_value.split('\n'):
                                    subdomain = subdomain.strip().lower()
                                    subdomain = subdomain.replace('*.', '')
                                    if subdomain.endswith(domain) and subdomain != domain:
                                        subdomains.add(subdomain)

                            logger.info(f"crt.sh found {len(subdomains)} subdomains")

        except Exception as e:
            logger.error(f"crt.sh enumeration failed: {e}")

        return subdomains

    async def _enum_hackertarget(self, domain: str) -> Set[str]:
        """Enumerate using HackerTarget API"""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

        try:
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=self.timeout) as response:
                        if response.status == 200:
                            text = await response.text()
                            if 'error' not in text.lower():
                                for line in text.split('\n'):
                                    if ',' in line:
                                        subdomain = line.split(',')[0].strip().lower()
                                        if subdomain.endswith(domain):
                                            subdomains.add(subdomain)

                            logger.info(f"HackerTarget found {len(subdomains)} subdomains")

        except Exception as e:
            logger.error(f"HackerTarget enumeration failed: {e}")

        return subdomains

    async def _enum_certspotter(self, domain: str) -> Set[str]:
        """Enumerate using CertSpotter API"""
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"

        try:
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            for cert in data:
                                for name in cert.get('dns_names', []):
                                    name = name.lower().replace('*.', '')
                                    if name.endswith(domain) and name != domain:
                                        subdomains.add(name)

                            logger.info(f"CertSpotter found {len(subdomains)} subdomains")

        except Exception as e:
            logger.error(f"CertSpotter enumeration failed: {e}")

        return subdomains

    async def _enum_virustotal(self, domain: str) -> Set[str]:
        """Enumerate using VirusTotal (requires API key)"""
        subdomains = set()
        # Note: VirusTotal requires an API key
        # Set VIRUSTOTAL_API_KEY environment variable
        import os
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')

        if not api_key:
            logger.debug("VirusTotal API key not set, skipping")
            return subdomains

        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}

        try:
            async with self.semaphore:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.json()
                            for subdomain in data.get('subdomains', []):
                                subdomain = subdomain.lower()
                                if subdomain.endswith(domain):
                                    subdomains.add(subdomain)

                            logger.info(f"VirusTotal found {len(subdomains)} subdomains")

        except Exception as e:
            logger.error(f"VirusTotal enumeration failed: {e}")

        return subdomains

    async def _brute_force(self, domain: str, wordlist: List[str]) -> Set[str]:
        """DNS brute force enumeration"""
        subdomains = set()

        async def check_subdomain(word: str) -> Optional[str]:
            async with self.semaphore:
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

    async def _try_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer"""
        subdomains = set()

        try:
            # Get nameservers
            answers = await asyncio.to_thread(self.resolver.resolve, domain, 'NS')

            for ns in answers:
                ns_name = str(ns.target)
                try:
                    # Attempt zone transfer
                    zone = await asyncio.to_thread(
                        dns.zone.from_xfr,
                        dns.query.xfr(ns_name, domain, timeout=10)
                    )

                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}"
                        if subdomain != domain:
                            subdomains.add(subdomain)

                    logger.warning(f"Zone transfer successful on {ns_name}!")
                    break

                except Exception as e:
                    logger.debug(f"Zone transfer failed on {ns_name}: {e}")

        except Exception as e:
            logger.debug(f"Could not get nameservers for {domain}: {e}")

        return subdomains

    async def _resolve_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Resolve subdomain and gather DNS information"""
        ip_addresses = []
        cname = None

        try:
            # A records
            try:
                answers = await asyncio.to_thread(self.resolver.resolve, subdomain, 'A')
                ip_addresses.extend([str(rdata) for rdata in answers])
            except:
                pass

            # AAAA records (IPv6)
            try:
                answers = await asyncio.to_thread(self.resolver.resolve, subdomain, 'AAAA')
                ip_addresses.extend([str(rdata) for rdata in answers])
            except:
                pass

            # CNAME records
            try:
                answers = await asyncio.to_thread(self.resolver.resolve, subdomain, 'CNAME')
                cname = str(answers[0].target)
            except:
                pass

            if ip_addresses or cname:
                return SubdomainResult(
                    subdomain=subdomain,
                    ip_addresses=ip_addresses,
                    source='resolution',
                    cname=cname
                )

        except Exception as e:
            logger.debug(f"Resolution error for {subdomain}: {e}")

        return None

    def generate_permutations(self, domain: str, subdomains: List[str]) -> List[str]:
        """
        Generate subdomain permutations based on discovered subdomains

        Args:
            domain: Base domain
            subdomains: List of discovered subdomains

        Returns:
            List of permutation candidates
        """
        permutations = set()

        # Extract subdomain parts
        parts = set()
        for subdomain in subdomains:
            prefix = subdomain.replace(f'.{domain}', '')
            parts.add(prefix)
            # Split by common separators
            for sep in ['-', '_', '.']:
                parts.update(prefix.split(sep))

        # Generate permutations
        prefixes = ['dev', 'test', 'staging', 'prod', 'api', 'admin', 'internal', 'new', 'old']
        suffixes = ['1', '2', '01', '02', 'dev', 'test', 'prod', 'internal']

        for part in parts:
            if not part or len(part) < 2:
                continue

            # Prefix permutations
            for prefix in prefixes:
                permutations.add(f"{prefix}-{part}.{domain}")
                permutations.add(f"{prefix}{part}.{domain}")

            # Suffix permutations
            for suffix in suffixes:
                permutations.add(f"{part}-{suffix}.{domain}")
                permutations.add(f"{part}{suffix}.{domain}")

        return list(permutations)


# Convenience function
async def quick_subdomain_scan(domain: str) -> List[str]:
    """Quick subdomain enumeration"""
    enumerator = SubdomainEnumerator()
    results = await enumerator.enumerate(domain)
    return [r.subdomain for r in results]


if __name__ == '__main__':
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python subdomain_enum.py <domain>")
            return

        domain = sys.argv[1]
        enumerator = SubdomainEnumerator()
        results = await enumerator.enumerate(domain, brute_force=False)

        print(f"\nFound {len(results)} subdomains:")
        for result in results[:20]:
            ips = ', '.join(result.ip_addresses) if result.ip_addresses else 'N/A'
            print(f"  {result.subdomain} -> {ips}")

    asyncio.run(main())
