"""
Subdomain Enumerator - Subdomain Discovery and Enumeration
Multiple techniques for comprehensive subdomain discovery
"""

import requests
import dns.resolver
import logging
from typing import List, Set, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json


class SubdomainEnumerator:
    """
    Subdomain discovery using multiple techniques:
    - Certificate Transparency (crt.sh)
    - DNS brute forcing
    - VirusTotal API
    - Search engine discovery
    - Chaos dataset
    """

    def __init__(self, virustotal_key: Optional[str] = None,
                 chaos_key: Optional[str] = None):
        """
        Initialize subdomain enumerator

        Args:
            virustotal_key: VirusTotal API key
            chaos_key: Chaos dataset API key
        """
        self.logger = logging.getLogger('SubdomainEnumerator')
        self.virustotal_key = virustotal_key
        self.chaos_key = chaos_key
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'api', 'blog', 'dev', 'staging', 'test', 'portal',
            'vpn', 'cdn', 'app', 'mobile', 'm', 'shop', 'store', 'forum',
            'support', 'help', 'docs', 'beta', 'alpha', 'demo', 'secure',
            'login', 'remote', 'proxy', 'git', 'gitlab', 'github', 'jenkins',
            'dashboard', 'panel', 'cpanel', 'backup', 'mysql', 'sql', 'db',
            'monitoring', 'grafana', 'kibana', 'elastic', 'confluence',
            'jira', 'wiki', 'status', 'chat', 'slack', 'mx', 'email'
        ]

    def enumerate(self, domain: str,
                  methods: Optional[List[str]] = None,
                  max_workers: int = 10) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains using multiple methods

        Args:
            domain: Target domain
            methods: List of methods to use (None = all available)
            max_workers: Number of concurrent workers

        Returns:
            List of discovered subdomains with metadata
        """
        self.logger.info(f"Enumerating subdomains for {domain}")

        if methods is None:
            methods = ['crtsh', 'brute', 'virustotal', 'chaos']

        all_subdomains = set()

        # Certificate Transparency
        if 'crtsh' in methods:
            try:
                self.logger.info("Searching certificate transparency logs...")
                crt_subs = self.enumerate_crtsh(domain)
                all_subdomains.update(crt_subs)
                self.logger.info(f"Found {len(crt_subs)} subdomains from crt.sh")
            except Exception as e:
                self.logger.error(f"crt.sh enumeration failed: {e}")

        # DNS Brute Force
        if 'brute' in methods:
            try:
                self.logger.info("Brute forcing common subdomains...")
                brute_subs = self.brute_force(domain, max_workers=max_workers)
                all_subdomains.update(brute_subs)
                self.logger.info(f"Found {len(brute_subs)} subdomains via brute force")
            except Exception as e:
                self.logger.error(f"Brute force enumeration failed: {e}")

        # VirusTotal
        if 'virustotal' in methods and self.virustotal_key:
            try:
                self.logger.info("Querying VirusTotal...")
                vt_subs = self.enumerate_virustotal(domain)
                all_subdomains.update(vt_subs)
                self.logger.info(f"Found {len(vt_subs)} subdomains from VirusTotal")
            except Exception as e:
                self.logger.error(f"VirusTotal enumeration failed: {e}")

        # Chaos Dataset
        if 'chaos' in methods and self.chaos_key:
            try:
                self.logger.info("Querying Chaos dataset...")
                chaos_subs = self.enumerate_chaos(domain)
                all_subdomains.update(chaos_subs)
                self.logger.info(f"Found {len(chaos_subs)} subdomains from Chaos")
            except Exception as e:
                self.logger.error(f"Chaos enumeration failed: {e}")

        # Verify and enrich subdomains
        self.logger.info("Verifying and enriching subdomain data...")
        verified_subdomains = self.verify_subdomains(list(all_subdomains), max_workers)

        self.logger.info(f"Total unique subdomains found: {len(verified_subdomains)}")
        return verified_subdomains

    def enumerate_crtsh(self, domain: str) -> Set[str]:
        """
        Enumerate subdomains using Certificate Transparency (crt.sh)

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name_value = entry.get('name_value', '')

                    # Split by newlines (crt.sh returns multiple domains)
                    names = name_value.split('\n')

                    for name in names:
                        name = name.strip().lower()

                        # Remove wildcards
                        name = name.replace('*.', '')

                        # Only include if it's a subdomain of target
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)

        except Exception as e:
            raise Exception(f"crt.sh query failed: {e}")

        return subdomains

    def brute_force(self, domain: str,
                   wordlist: Optional[List[str]] = None,
                   max_workers: int = 10) -> Set[str]:
        """
        Brute force subdomains using wordlist

        Args:
            domain: Target domain
            wordlist: Custom wordlist (None = use default)
            max_workers: Number of concurrent workers

        Returns:
            Set of discovered subdomains
        """
        if wordlist is None:
            wordlist = self.common_subdomains

        subdomains = set()

        def check_subdomain(subdomain: str) -> Optional[str]:
            """Check if subdomain exists"""
            fqdn = f"{subdomain}.{domain}"
            try:
                answers = self.resolver.resolve(fqdn, 'A')
                if answers:
                    return fqdn
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception:
                pass
            return None

        # Brute force with threading
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {
                executor.submit(check_subdomain, sub): sub
                for sub in wordlist
            }

            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    subdomains.add(result)

        return subdomains

    def enumerate_virustotal(self, domain: str) -> Set[str]:
        """
        Enumerate subdomains using VirusTotal API

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        if not self.virustotal_key:
            return set()

        subdomains = set()

        try:
            headers = {'x-apikey': self.virustotal_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for item in data.get('data', []):
                    subdomain = item.get('id', '').lower()
                    if subdomain and subdomain != domain:
                        subdomains.add(subdomain)

            # Handle pagination
            next_cursor = data.get('meta', {}).get('cursor')
            while next_cursor:
                params = {'cursor': next_cursor}
                response = requests.get(url, headers=headers, params=params, timeout=30)

                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('data', []):
                        subdomain = item.get('id', '').lower()
                        if subdomain and subdomain != domain:
                            subdomains.add(subdomain)
                    next_cursor = data.get('meta', {}).get('cursor')
                else:
                    break

                # Rate limiting
                time.sleep(1)

        except Exception as e:
            raise Exception(f"VirusTotal query failed: {e}")

        return subdomains

    def enumerate_chaos(self, domain: str) -> Set[str]:
        """
        Enumerate subdomains using Chaos dataset

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        if not self.chaos_key:
            return set()

        subdomains = set()

        try:
            headers = {'Authorization': self.chaos_key}
            url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for subdomain in data.get('subdomains', []):
                    fqdn = f"{subdomain}.{domain}".lower()
                    subdomains.add(fqdn)

        except Exception as e:
            raise Exception(f"Chaos query failed: {e}")

        return subdomains

    def verify_subdomains(self, subdomains: List[str],
                         max_workers: int = 20) -> List[Dict[str, Any]]:
        """
        Verify subdomains and gather additional information

        Args:
            subdomains: List of subdomains to verify
            max_workers: Number of concurrent workers

        Returns:
            List of verified subdomains with metadata
        """
        verified = []

        def verify_and_enrich(subdomain: str) -> Optional[Dict[str, Any]]:
            """Verify subdomain and gather metadata"""
            info = {
                'subdomain': subdomain,
                'ip_addresses': [],
                'cname': None,
                'verified': False,
                'http_status': None,
                'https_status': None
            }

            # DNS Verification
            try:
                # Try A records
                answers = self.resolver.resolve(subdomain, 'A')
                info['ip_addresses'] = [str(rdata) for rdata in answers]
                info['verified'] = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                pass

            # Try AAAA if no A records
            if not info['ip_addresses']:
                try:
                    answers = self.resolver.resolve(subdomain, 'AAAA')
                    info['ip_addresses'] = [str(rdata) for rdata in answers]
                    info['verified'] = True
                except Exception:
                    pass

            # Try CNAME
            try:
                answers = self.resolver.resolve(subdomain, 'CNAME')
                info['cname'] = str(answers[0].target)
                info['verified'] = True
            except Exception:
                pass

            # HTTP/HTTPS Status Check (quick)
            if info['verified']:
                # Check HTTP
                try:
                    resp = requests.head(f"http://{subdomain}",
                                       timeout=5,
                                       allow_redirects=True)
                    info['http_status'] = resp.status_code
                except Exception:
                    pass

                # Check HTTPS
                try:
                    resp = requests.head(f"https://{subdomain}",
                                       timeout=5,
                                       allow_redirects=True,
                                       verify=False)
                    info['https_status'] = resp.status_code
                except Exception:
                    pass

            return info if info['verified'] else None

        # Verify with threading
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {
                executor.submit(verify_and_enrich, sub): sub
                for sub in subdomains
            }

            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    verified.append(result)

        # Sort by subdomain name
        verified.sort(key=lambda x: x['subdomain'])

        return verified

    def search_subdomain_takeover(self, subdomains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for potential subdomain takeover vulnerabilities

        Args:
            subdomains: List of verified subdomains

        Returns:
            List of potentially vulnerable subdomains
        """
        vulnerable_services = {
            'github.io': 'There isn\'t a GitHub Pages site here',
            'herokuapp.com': 'No such app',
            'wordpress.com': 'Do you want to register',
            'tumblr.com': 'Whatever you were looking for doesn\'t currently exist',
            'shopify.com': 'Sorry, this shop is currently unavailable',
            'desk.com': 'Please try again or try Desk.com free for 14 days',
            'campaignmonitor.com': 'Double check the URL',
            'statuspage.io': 'You are being',
            'uservoice.com': 'This UserVoice subdomain is currently available'
        }

        vulnerable = []

        for subdomain in subdomains:
            if not subdomain.get('cname'):
                continue

            cname = subdomain['cname'].lower()

            # Check if CNAME points to vulnerable service
            for service, error_message in vulnerable_services.items():
                if service in cname:
                    # Try to fetch the page
                    try:
                        resp = requests.get(f"http://{subdomain['subdomain']}",
                                          timeout=10,
                                          allow_redirects=True)

                        if error_message.lower() in resp.text.lower():
                            vulnerable.append({
                                'subdomain': subdomain['subdomain'],
                                'cname': cname,
                                'service': service,
                                'confidence': 'high'
                            })
                    except Exception:
                        pass

        return vulnerable

    def export_subdomains(self, subdomains: List[Dict[str, Any]],
                         filename: str,
                         format: str = 'json') -> None:
        """
        Export subdomain results

        Args:
            subdomains: Subdomain data
            filename: Output filename
            format: Export format (json, txt, csv)
        """
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(subdomains, f, indent=2)

        elif format == 'txt':
            with open(filename, 'w') as f:
                for sub in subdomains:
                    f.write(f"{sub['subdomain']}\n")

        elif format == 'csv':
            with open(filename, 'w') as f:
                f.write("Subdomain,IP Addresses,CNAME,HTTP Status,HTTPS Status\n")
                for sub in subdomains:
                    ips = ';'.join(sub.get('ip_addresses', []))
                    f.write(f"{sub['subdomain']},{ips},{sub.get('cname', '')},"
                           f"{sub.get('http_status', '')},{sub.get('https_status', '')}\n")

        self.logger.info(f"Subdomains exported to {filename}")


def main():
    """Example usage"""
    enumerator = SubdomainEnumerator()

    # Enumerate subdomains
    subdomains = enumerator.enumerate("example.com", methods=['crtsh', 'brute'])

    print(f"Found {len(subdomains)} subdomains:")
    for sub in subdomains[:10]:  # Show first 10
        print(f"  {sub['subdomain']} -> {sub.get('ip_addresses', [])}")

    # Check for takeover vulnerabilities
    vulnerable = enumerator.search_subdomain_takeover(subdomains)
    if vulnerable:
        print(f"\nPotentially vulnerable subdomains: {len(vulnerable)}")
        for vuln in vulnerable:
            print(f"  {vuln['subdomain']} -> {vuln['service']}")

    # Export results
    enumerator.export_subdomains(subdomains, "subdomains.json", format='json')


if __name__ == "__main__":
    main()
