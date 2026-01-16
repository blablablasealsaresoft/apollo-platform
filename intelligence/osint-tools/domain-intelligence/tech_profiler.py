"""
Technology Profiler - Web Technology Detection
Detect CMS, frameworks, servers, and technology stack
"""

import requests
import re
import logging
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup
import json
from urllib.parse import urljoin, urlparse


class TechProfiler:
    """
    Web technology detection and profiling
    Identifies CMS, frameworks, JavaScript libraries, servers, and more
    """

    def __init__(self, builtwith_api_key: Optional[str] = None):
        """
        Initialize technology profiler

        Args:
            builtwith_api_key: BuiltWith API key (optional)
        """
        self.logger = logging.getLogger('TechProfiler')
        self.builtwith_key = builtwith_api_key

        # Technology signatures
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> Dict[str, Any]:
        """Load technology detection signatures"""
        return {
            'cms': {
                'WordPress': {
                    'headers': {'X-Powered-By': 'WordPress'},
                    'html': [
                        r'/wp-content/',
                        r'/wp-includes/',
                        r'<meta name="generator" content="WordPress'
                    ],
                    'cookies': ['wordpress_']
                },
                'Joomla': {
                    'html': [
                        r'/components/com_',
                        r'/templates/system/',
                        r'<meta name="generator" content="Joomla'
                    ],
                    'cookies': []
                },
                'Drupal': {
                    'headers': {'X-Generator': 'Drupal'},
                    'html': [
                        r'/sites/default/',
                        r'/misc/drupal.js',
                        r'<meta name="generator" content="Drupal'
                    ],
                    'cookies': ['SESS']
                },
                'Shopify': {
                    'headers': {'X-ShopId': '.*'},
                    'html': [r'cdn.shopify.com', r'Shopify.theme'],
                    'cookies': ['_shopify_']
                },
                'Magento': {
                    'html': [
                        r'/skin/frontend/',
                        r'/js/mage/',
                        r'Mage.Cookies'
                    ],
                    'cookies': ['frontend']
                },
                'Ghost': {
                    'html': [r'content="Ghost'],
                    'headers': {'X-Powered-By': 'Ghost'}
                }
            },
            'frameworks': {
                'Laravel': {
                    'cookies': ['laravel_session'],
                    'headers': {'X-Powered-By': 'PHP/.*'}
                },
                'Django': {
                    'cookies': ['csrftoken', 'sessionid'],
                    'headers': {'X-Powered-By': 'Django'}
                },
                'Ruby on Rails': {
                    'cookies': ['_session_id'],
                    'headers': {'X-Powered-By': 'Phusion Passenger'}
                },
                'ASP.NET': {
                    'headers': {'X-Powered-By': 'ASP.NET', 'X-AspNet-Version': '.*'},
                    'cookies': ['ASP.NET_SessionId']
                },
                'Express': {
                    'headers': {'X-Powered-By': 'Express'}
                },
                'Spring': {
                    'cookies': ['JSESSIONID']
                }
            },
            'javascript_libraries': {
                'jQuery': {
                    'html': [r'jquery[.-][\d.]+\.(?:min\.)?js']
                },
                'React': {
                    'html': [r'react[.-][\d.]+\.(?:min\.)?js', r'__REACT']
                },
                'Angular': {
                    'html': [r'angular[.-][\d.]+\.(?:min\.)?js', r'ng-app']
                },
                'Vue.js': {
                    'html': [r'vue[.-][\d.]+\.(?:min\.)?js', r'["\']__vue']
                },
                'Bootstrap': {
                    'html': [r'bootstrap[.-][\d.]+\.(?:min\.)?css']
                }
            },
            'servers': {
                'Apache': {
                    'headers': {'Server': 'Apache'}
                },
                'Nginx': {
                    'headers': {'Server': 'nginx'}
                },
                'IIS': {
                    'headers': {'Server': 'Microsoft-IIS'}
                },
                'Cloudflare': {
                    'headers': {'Server': 'cloudflare'}
                }
            },
            'analytics': {
                'Google Analytics': {
                    'html': [r'google-analytics\.com/analytics\.js', r'ga\(']
                },
                'Google Tag Manager': {
                    'html': [r'googletagmanager\.com/gtm\.js']
                },
                'Facebook Pixel': {
                    'html': [r'connect\.facebook\.net/.*fbq']
                },
                'Hotjar': {
                    'html': [r'static\.hotjar\.com']
                }
            },
            'cdn': {
                'Cloudflare': {
                    'headers': {'Server': 'cloudflare', 'CF-RAY': '.*'}
                },
                'Fastly': {
                    'headers': {'X-Served-By': 'cache-.*'}
                },
                'Akamai': {
                    'headers': {'X-Akamai-': '.*'}
                }
            }
        }

    def profile(self, domain: str, use_api: bool = True) -> Dict[str, Any]:
        """
        Profile technology stack of domain

        Args:
            domain: Target domain
            use_api: Use BuiltWith API if available

        Returns:
            Technology profile
        """
        self.logger.info(f"Profiling technology for {domain}")

        results = {
            'domain': domain,
            'url': f"https://{domain}",
            'technologies': [],
            'cms': None,
            'frameworks': [],
            'javascript_libraries': [],
            'servers': [],
            'analytics': [],
            'cdn': [],
            'metadata': {}
        }

        # Try HTTPS first, fallback to HTTP
        for protocol in ['https', 'http']:
            url = f"{protocol}://{domain}"
            try:
                response = requests.get(
                    url,
                    timeout=15,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (TechProfiler)'}
                )

                if response.status_code == 200:
                    results['url'] = url
                    results['metadata'] = self._extract_metadata(response)

                    # Detect technologies
                    detected = self._detect_technologies(response)
                    results.update(detected)

                    break

            except Exception as e:
                self.logger.debug(f"Failed to fetch {url}: {e}")
                continue

        # Use BuiltWith API if available
        if use_api and self.builtwith_key:
            try:
                builtwith_data = self._query_builtwith(domain)
                results['builtwith'] = builtwith_data
            except Exception as e:
                self.logger.error(f"BuiltWith API query failed: {e}")

        # Compile technology list
        results['technologies'] = self._compile_technology_list(results)

        return results

    def _detect_technologies(self, response: requests.Response) -> Dict[str, Any]:
        """
        Detect technologies from HTTP response

        Args:
            response: HTTP response object

        Returns:
            Detected technologies
        """
        detected = {
            'cms': None,
            'frameworks': [],
            'javascript_libraries': [],
            'servers': [],
            'analytics': [],
            'cdn': []
        }

        html = response.text
        headers = response.headers
        cookies = response.cookies

        # Check each category
        for category, technologies in self.signatures.items():
            for tech_name, patterns in technologies.items():

                match = False

                # Check headers
                if 'headers' in patterns:
                    for header, pattern in patterns['headers'].items():
                        if header in headers:
                            if re.search(pattern, headers[header], re.IGNORECASE):
                                match = True
                                break

                # Check HTML
                if 'html' in patterns:
                    for pattern in patterns['html']:
                        if re.search(pattern, html, re.IGNORECASE):
                            match = True
                            break

                # Check cookies
                if 'cookies' in patterns:
                    for cookie_pattern in patterns['cookies']:
                        for cookie in cookies:
                            if cookie_pattern in cookie:
                                match = True
                                break

                # Add to detected list
                if match:
                    if category == 'cms' and not detected['cms']:
                        detected['cms'] = tech_name
                    elif category != 'cms':
                        if tech_name not in detected[category]:
                            detected[category].append(tech_name)

        # Server detection from headers
        if 'Server' in headers:
            server = headers['Server']
            if server not in detected['servers']:
                detected['servers'].append(server)

        return detected

    def _extract_metadata(self, response: requests.Response) -> Dict[str, Any]:
        """
        Extract metadata from HTML

        Args:
            response: HTTP response

        Returns:
            Page metadata
        """
        metadata = {
            'title': None,
            'description': None,
            'keywords': None,
            'generator': None,
            'author': None,
            'robots': None
        }

        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Title
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.text.strip()

            # Meta tags
            meta_tags = {
                'description': soup.find('meta', attrs={'name': 'description'}),
                'keywords': soup.find('meta', attrs={'name': 'keywords'}),
                'generator': soup.find('meta', attrs={'name': 'generator'}),
                'author': soup.find('meta', attrs={'name': 'author'}),
                'robots': soup.find('meta', attrs={'name': 'robots'})
            }

            for key, tag in meta_tags.items():
                if tag and tag.get('content'):
                    metadata[key] = tag.get('content')

        except Exception as e:
            self.logger.debug(f"Failed to extract metadata: {e}")

        return metadata

    def _query_builtwith(self, domain: str) -> Dict[str, Any]:
        """
        Query BuiltWith API

        Args:
            domain: Target domain

        Returns:
            BuiltWith data
        """
        if not self.builtwith_key:
            return {}

        try:
            url = f"https://api.builtwith.com/v20/api.json"
            params = {
                'KEY': self.builtwith_key,
                'LOOKUP': domain
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            raise Exception(f"BuiltWith API query failed: {e}")

        return {}

    def _compile_technology_list(self, results: Dict[str, Any]) -> List[str]:
        """Compile flat list of all detected technologies"""
        technologies = []

        if results.get('cms'):
            technologies.append(results['cms'])

        for category in ['frameworks', 'javascript_libraries', 'servers', 'analytics', 'cdn']:
            technologies.extend(results.get(category, []))

        return list(set(technologies))

    def detect_cms(self, domain: str) -> Optional[str]:
        """
        Detect CMS only (quick check)

        Args:
            domain: Target domain

        Returns:
            CMS name or None
        """
        for protocol in ['https', 'http']:
            url = f"{protocol}://{domain}"
            try:
                response = requests.get(url, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    detected = self._detect_technologies(response)
                    return detected.get('cms')
            except Exception:
                continue

        return None

    def scan_security_headers(self, domain: str) -> Dict[str, Any]:
        """
        Scan security headers

        Args:
            domain: Target domain

        Returns:
            Security headers analysis
        """
        security_headers = {
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False
        }

        results = {
            'domain': domain,
            'headers': {},
            'security_score': 0,
            'missing_headers': [],
            'recommendations': []
        }

        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)

            # Check each security header
            for header in security_headers:
                if header in response.headers:
                    security_headers[header] = True
                    results['headers'][header] = response.headers[header]
                else:
                    results['missing_headers'].append(header)
                    results['recommendations'].append(f"Add {header} header")

            # Calculate score
            results['security_score'] = (
                sum(security_headers.values()) / len(security_headers) * 100
            )

        except Exception as e:
            results['error'] = str(e)

        return results

    def detect_waf(self, domain: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall

        Args:
            domain: Target domain

        Returns:
            WAF detection results
        """
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai'],
            'AWS WAF': ['awselb', 'x-amzn'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Sucuri': ['x-sucuri'],
            'Wordfence': ['wordfence'],
            'ModSecurity': ['mod_security', 'modsecurity']
        }

        results = {
            'domain': domain,
            'waf_detected': False,
            'waf_name': None,
            'confidence': 'low'
        }

        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)

            # Check headers and cookies
            all_headers = ' '.join([
                f"{k}:{v}" for k, v in response.headers.items()
            ]).lower()

            all_cookies = ' '.join([
                f"{k}:{v}" for k, v in response.cookies.items()
            ]).lower()

            combined = all_headers + ' ' + all_cookies

            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in combined:
                        results['waf_detected'] = True
                        results['waf_name'] = waf_name
                        results['confidence'] = 'high'
                        break

                if results['waf_detected']:
                    break

        except Exception as e:
            results['error'] = str(e)

        return results

    def fingerprint_server(self, domain: str) -> Dict[str, Any]:
        """
        Server fingerprinting

        Args:
            domain: Target domain

        Returns:
            Server fingerprint
        """
        results = {
            'domain': domain,
            'server': None,
            'powered_by': None,
            'platform': None,
            'programming_language': None
        }

        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)

            # Server header
            if 'Server' in response.headers:
                results['server'] = response.headers['Server']

            # X-Powered-By
            if 'X-Powered-By' in response.headers:
                results['powered_by'] = response.headers['X-Powered-By']

                # Detect language from X-Powered-By
                powered_by = response.headers['X-Powered-By'].lower()
                if 'php' in powered_by:
                    results['programming_language'] = 'PHP'
                elif 'asp.net' in powered_by:
                    results['programming_language'] = 'ASP.NET'
                elif 'express' in powered_by:
                    results['programming_language'] = 'Node.js'

        except Exception as e:
            results['error'] = str(e)

        return results


def main():
    """Example usage"""
    profiler = TechProfiler()

    # Profile technology
    results = profiler.profile("example.com", use_api=False)

    print(f"Domain: {results['domain']}")
    print(f"CMS: {results['cms']}")
    print(f"Frameworks: {results['frameworks']}")
    print(f"JavaScript Libraries: {results['javascript_libraries']}")
    print(f"Servers: {results['servers']}")
    print(f"CDN: {results['cdn']}")

    # Check security headers
    security = profiler.scan_security_headers("example.com")
    print(f"\nSecurity Score: {security['security_score']:.0f}%")
    print(f"Missing Headers: {security['missing_headers']}")

    # Detect WAF
    waf = profiler.detect_waf("example.com")
    if waf['waf_detected']:
        print(f"\nWAF Detected: {waf['waf_name']} ({waf['confidence']} confidence)")


if __name__ == "__main__":
    main()
