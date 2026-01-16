"""
Technology Detection Module
Detect web technologies, frameworks, CMS, servers, and CDN
"""

import asyncio
import aiohttp
import re
import logging
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
import json
from pathlib import Path
from bs4 import BeautifulSoup
import hashlib


@dataclass
class Technology:
    """Container for detected technology"""
    name: str
    category: str
    version: Optional[str] = None
    confidence: int = 100
    detection_method: Optional[str] = None


class TechnologyDetector:
    """
    Advanced technology stack detection system
    """

    # Technology fingerprints database
    TECH_SIGNATURES = {
        # Web Frameworks
        'React': {
            'category': 'JavaScript Framework',
            'patterns': [
                r'react',
                r'data-reactroot',
                r'data-reactid',
                r'__REACT_DEVTOOLS_',
            ],
            'headers': {},
            'meta': ['react'],
            'scripts': ['react.js', 'react.min.js', 'react-dom.js']
        },
        'Angular': {
            'category': 'JavaScript Framework',
            'patterns': [
                r'ng-app',
                r'ng-controller',
                r'ng-version',
                r'angular',
            ],
            'headers': {},
            'meta': ['ng-version'],
            'scripts': ['angular.js', 'angular.min.js']
        },
        'Vue.js': {
            'category': 'JavaScript Framework',
            'patterns': [
                r'v-if',
                r'v-for',
                r'v-model',
                r'__vue__',
            ],
            'headers': {},
            'meta': [],
            'scripts': ['vue.js', 'vue.min.js']
        },
        'jQuery': {
            'category': 'JavaScript Library',
            'patterns': [r'jquery'],
            'headers': {},
            'meta': [],
            'scripts': ['jquery.js', 'jquery.min.js']
        },

        # CMS Detection
        'WordPress': {
            'category': 'CMS',
            'patterns': [
                r'wp-content',
                r'wp-includes',
                r'wordpress',
            ],
            'headers': {'X-Powered-By': 'WordPress'},
            'meta': ['generator'],
            'paths': ['/wp-admin', '/wp-login.php', '/wp-content']
        },
        'Joomla': {
            'category': 'CMS',
            'patterns': [
                r'joomla',
                r'/components/com_',
                r'/templates/',
            ],
            'headers': {},
            'meta': ['generator'],
            'paths': ['/administrator']
        },
        'Drupal': {
            'category': 'CMS',
            'patterns': [
                r'drupal',
                r'sites/default/files',
            ],
            'headers': {'X-Drupal-Cache': ''},
            'meta': ['generator'],
            'paths': ['/user/login']
        },
        'Magento': {
            'category': 'E-Commerce',
            'patterns': [
                r'magento',
                r'mage/',
            ],
            'headers': {},
            'meta': [],
            'paths': ['/admin', '/magento']
        },
        'Shopify': {
            'category': 'E-Commerce',
            'patterns': [
                r'shopify',
                r'cdn.shopify.com',
            ],
            'headers': {'X-Shopify-Stage': ''},
            'meta': [],
            'scripts': []
        },

        # Web Servers
        'nginx': {
            'category': 'Web Server',
            'patterns': [],
            'headers': {'Server': 'nginx'},
            'meta': [],
            'scripts': []
        },
        'Apache': {
            'category': 'Web Server',
            'patterns': [],
            'headers': {'Server': 'Apache'},
            'meta': [],
            'scripts': []
        },
        'IIS': {
            'category': 'Web Server',
            'patterns': [],
            'headers': {'Server': 'Microsoft-IIS'},
            'meta': [],
            'scripts': []
        },

        # Backend Frameworks
        'Django': {
            'category': 'Web Framework',
            'patterns': [r'csrfmiddlewaretoken'],
            'headers': {},
            'meta': [],
            'cookies': ['csrftoken', 'sessionid']
        },
        'Flask': {
            'category': 'Web Framework',
            'patterns': [],
            'headers': {'Server': 'Werkzeug'},
            'meta': [],
            'cookies': ['session']
        },
        'Express': {
            'category': 'Web Framework',
            'patterns': [],
            'headers': {'X-Powered-By': 'Express'},
            'meta': [],
            'scripts': []
        },
        'Laravel': {
            'category': 'Web Framework',
            'patterns': [r'laravel'],
            'headers': {},
            'meta': [],
            'cookies': ['laravel_session']
        },
        'Ruby on Rails': {
            'category': 'Web Framework',
            'patterns': [r'rails'],
            'headers': {},
            'meta': ['csrf-param', 'csrf-token'],
            'cookies': ['_session_id']
        },

        # CDN Detection
        'Cloudflare': {
            'category': 'CDN',
            'patterns': [],
            'headers': {
                'Server': 'cloudflare',
                'CF-RAY': ''
            },
            'meta': [],
            'scripts': []
        },
        'Akamai': {
            'category': 'CDN',
            'patterns': [],
            'headers': {'X-Akamai-Transformed': ''},
            'meta': [],
            'scripts': []
        },
        'Fastly': {
            'category': 'CDN',
            'patterns': [],
            'headers': {'X-Fastly-Request-ID': ''},
            'meta': [],
            'scripts': []
        },

        # Analytics & Tracking
        'Google Analytics': {
            'category': 'Analytics',
            'patterns': [r'google-analytics.com', r'ga.js', r'analytics.js'],
            'headers': {},
            'meta': [],
            'scripts': ['analytics.js', 'ga.js']
        },
        'Google Tag Manager': {
            'category': 'Tag Manager',
            'patterns': [r'googletagmanager.com'],
            'headers': {},
            'meta': [],
            'scripts': ['gtm.js']
        },

        # Programming Languages
        'PHP': {
            'category': 'Programming Language',
            'patterns': [],
            'headers': {'X-Powered-By': 'PHP'},
            'meta': [],
            'file_extensions': ['.php']
        },
        'ASP.NET': {
            'category': 'Programming Language',
            'patterns': [r'__VIEWSTATE', r'__EVENTVALIDATION'],
            'headers': {'X-AspNet-Version': '', 'X-Powered-By': 'ASP.NET'},
            'meta': [],
            'file_extensions': ['.aspx']
        },
    }

    def __init__(self, config: Dict):
        """Initialize technology detector"""
        self.config = config.get('tech', {})
        self.timeout = config.get('timeout', 30)
        self.logger = logging.getLogger('TechDetector')

        # User agent for HTTP requests
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    async def detect(
        self,
        domain: str,
        open_ports: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Detect technologies used by a domain

        Args:
            domain: Target domain
            open_ports: List of open ports (optional, for targeted scanning)

        Returns:
            List of detected technologies
        """
        self.logger.info(f"Starting technology detection for {domain}")

        detected_technologies: Dict[str, Technology] = {}

        # Determine URLs to scan
        urls = self._build_urls(domain, open_ports)

        # Scan each URL
        for url in urls:
            try:
                techs = await self._analyze_url(url)
                for tech in techs:
                    if tech.name not in detected_technologies:
                        detected_technologies[tech.name] = tech
                    elif tech.confidence > detected_technologies[tech.name].confidence:
                        detected_technologies[tech.name] = tech
            except Exception as e:
                self.logger.error(f"Failed to analyze {url}: {e}")

        # Deep scan if enabled
        if self.config.get('deep_scan', False):
            additional_techs = await self._deep_scan(domain, detected_technologies)
            for tech in additional_techs:
                if tech.name not in detected_technologies:
                    detected_technologies[tech.name] = tech

        # Convert to list of dicts
        results = []
        for tech in detected_technologies.values():
            results.append({
                'name': tech.name,
                'category': tech.category,
                'version': tech.version,
                'confidence': tech.confidence,
                'detection_method': tech.detection_method
            })

        self.logger.info(f"Detected {len(results)} technologies")
        return sorted(results, key=lambda x: x['name'])

    def _build_urls(self, domain: str, open_ports: Optional[List[Dict]] = None) -> List[str]:
        """Build list of URLs to scan based on domain and open ports"""
        urls = []

        # Add HTTPS by default
        urls.append(f"https://{domain}")

        # Add HTTP
        urls.append(f"http://{domain}")

        # Add URLs based on open ports
        if open_ports:
            for port_info in open_ports:
                port = port_info.get('port')
                host = port_info.get('host', domain)

                if port in [80]:
                    urls.append(f"http://{host}")
                elif port in [443]:
                    urls.append(f"https://{host}")
                elif port in [8080, 8000, 8888]:
                    urls.append(f"http://{host}:{port}")
                elif port in [8443]:
                    urls.append(f"https://{host}:{port}")

        return list(set(urls))  # Remove duplicates

    async def _analyze_url(self, url: str) -> List[Technology]:
        """Analyze a single URL for technologies"""
        detected = []

        try:
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': self.user_agent}

                async with session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    ssl=False
                ) as response:
                    # Get response data
                    html_content = await response.text()
                    response_headers = response.headers
                    cookies = response.cookies

                    # Check headers
                    header_techs = self._check_headers(response_headers)
                    detected.extend(header_techs)

                    # Check HTML content
                    content_techs = self._check_html_content(html_content)
                    detected.extend(content_techs)

                    # Check meta tags
                    meta_techs = self._check_meta_tags(html_content)
                    detected.extend(meta_techs)

                    # Check scripts
                    script_techs = self._check_scripts(html_content)
                    detected.extend(script_techs)

                    # Check cookies
                    cookie_techs = self._check_cookies(cookies)
                    detected.extend(cookie_techs)

        except aiohttp.ClientError as e:
            self.logger.debug(f"Connection error for {url}: {e}")
        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout connecting to {url}")
        except Exception as e:
            self.logger.error(f"Error analyzing {url}: {e}")

        return detected

    def _check_headers(self, headers: Dict) -> List[Technology]:
        """Check HTTP headers for technology signatures"""
        detected = []

        for tech_name, tech_data in self.TECH_SIGNATURES.items():
            for header_name, header_value in tech_data.get('headers', {}).items():
                if header_name in headers:
                    actual_value = headers[header_name]

                    # Check if it matches
                    if not header_value or header_value in actual_value:
                        version = self._extract_version(actual_value)

                        detected.append(Technology(
                            name=tech_name,
                            category=tech_data['category'],
                            version=version,
                            confidence=95,
                            detection_method='HTTP Headers'
                        ))

        return detected

    def _check_html_content(self, html: str) -> List[Technology]:
        """Check HTML content for technology patterns"""
        detected = []

        for tech_name, tech_data in self.TECH_SIGNATURES.items():
            for pattern in tech_data.get('patterns', []):
                if re.search(pattern, html, re.IGNORECASE):
                    detected.append(Technology(
                        name=tech_name,
                        category=tech_data['category'],
                        confidence=80,
                        detection_method='HTML Pattern'
                    ))
                    break  # One match is enough

        return detected

    def _check_meta_tags(self, html: str) -> List[Technology]:
        """Check meta tags for technology information"""
        detected = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            meta_tags = soup.find_all('meta')

            for tech_name, tech_data in self.TECH_SIGNATURES.items():
                for meta_name in tech_data.get('meta', []):
                    for tag in meta_tags:
                        if tag.get('name') == meta_name or tag.get('property') == meta_name:
                            content = tag.get('content', '')
                            version = self._extract_version(content)

                            detected.append(Technology(
                                name=tech_name,
                                category=tech_data['category'],
                                version=version,
                                confidence=90,
                                detection_method='Meta Tag'
                            ))
                            break

        except Exception as e:
            self.logger.debug(f"Error parsing meta tags: {e}")

        return detected

    def _check_scripts(self, html: str) -> List[Technology]:
        """Check script tags for technology signatures"""
        detected = []

        try:
            soup = BeautifulSoup(html, 'html.parser')
            scripts = soup.find_all('script', src=True)

            for tech_name, tech_data in self.TECH_SIGNATURES.items():
                for script_file in tech_data.get('scripts', []):
                    for script_tag in scripts:
                        src = script_tag.get('src', '')
                        if script_file in src:
                            version = self._extract_version(src)

                            detected.append(Technology(
                                name=tech_name,
                                category=tech_data['category'],
                                version=version,
                                confidence=85,
                                detection_method='Script Include'
                            ))
                            break

        except Exception as e:
            self.logger.debug(f"Error parsing scripts: {e}")

        return detected

    def _check_cookies(self, cookies) -> List[Technology]:
        """Check cookies for technology signatures"""
        detected = []

        cookie_names = [cookie.key for cookie in cookies.values()]

        for tech_name, tech_data in self.TECH_SIGNATURES.items():
            for cookie_name in tech_data.get('cookies', []):
                if cookie_name in cookie_names:
                    detected.append(Technology(
                        name=tech_name,
                        category=tech_data['category'],
                        confidence=75,
                        detection_method='Cookie'
                    ))
                    break

        return detected

    async def _deep_scan(
        self,
        domain: str,
        current_techs: Dict[str, Technology]
    ) -> List[Technology]:
        """Perform deep scan for additional technologies"""
        detected = []

        # Check common paths for specific technologies
        if 'WordPress' in [t.name for t in current_techs.values()]:
            wp_version = await self._detect_wordpress_version(domain)
            if wp_version:
                wp_tech = current_techs.get('WordPress')
                if wp_tech:
                    wp_tech.version = wp_version

        # Add more deep scan techniques here

        return detected

    async def _detect_wordpress_version(self, domain: str) -> Optional[str]:
        """Detect WordPress version from readme or feed"""
        version_urls = [
            f"https://{domain}/readme.html",
            f"http://{domain}/readme.html",
            f"https://{domain}/feed/",
            f"http://{domain}/feed/"
        ]

        for url in version_urls:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            version_match = re.search(r'Version ([\d.]+)', content)
                            if version_match:
                                return version_match.group(1)
            except:
                continue

        return None

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text"""
        # Common version patterns
        patterns = [
            r'([\d]+\.[\d]+\.[\d]+)',  # X.Y.Z
            r'([\d]+\.[\d]+)',  # X.Y
            r'v([\d]+\.[\d]+\.[\d]+)',  # vX.Y.Z
            r'/([\d]+\.[\d]+\.[\d]+)/',  # /X.Y.Z/
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)

        return None


async def main():
    """Test technology detector"""
    config = {
        'tech': {
            'deep_scan': True,
            'wappalyzer': True,
            'header_analysis': True
        },
        'timeout': 30
    }

    detector = TechnologyDetector(config)
    results = await detector.detect('example.com')

    print(f"\nDetected {len(results)} technologies:")
    for result in results:
        tech_info = f"{result['name']} [{result['category']}]"
        if result.get('version'):
            tech_info += f" v{result['version']}"
        print(f"  {tech_info} (Confidence: {result['confidence']}%)")


if __name__ == '__main__':
    asyncio.run(main())
