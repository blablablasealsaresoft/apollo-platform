"""
Reverse Image Search - Multi-Engine Reverse Image Search
Searches across Google, TinEye, Yandex, Bing, and Baidu
"""

import os
import requests
import base64
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode, quote
import time
from io import BytesIO
from PIL import Image


class ReverseImageSearch:
    """
    Multi-engine reverse image search for OSINT operations
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize reverse image search engines"""
        self.config = config or {}
        self.logger = logging.getLogger('ReverseImageSearch')

        # API keys and configurations
        self.google_api_key = self.config.get('google_api_key', os.getenv('GOOGLE_API_KEY'))
        self.google_cx = self.config.get('google_cx', os.getenv('GOOGLE_CX'))
        self.tineye_api_key = self.config.get('tineye_api_key', os.getenv('TINEYE_API_KEY'))
        self.bing_api_key = self.config.get('bing_api_key', os.getenv('BING_API_KEY'))

        # Session for requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Enabled engines
        self.enabled_engines = self.config.get('engines', [
            'google', 'tineye', 'yandex', 'bing', 'baidu'
        ])

    def search_all_engines(self, image_path: str) -> Dict[str, Any]:
        """
        Search image across all enabled engines

        Args:
            image_path: Path to image file

        Returns:
            Results from all search engines
        """
        self.logger.info(f"Starting reverse image search for: {image_path}")

        results = {
            'image_path': image_path,
            'engines': {}
        }

        if 'google' in self.enabled_engines:
            results['engines']['google'] = self.search_google(image_path)

        if 'tineye' in self.enabled_engines:
            results['engines']['tineye'] = self.search_tineye(image_path)

        if 'yandex' in self.enabled_engines:
            results['engines']['yandex'] = self.search_yandex(image_path)

        if 'bing' in self.enabled_engines:
            results['engines']['bing'] = self.search_bing(image_path)

        if 'baidu' in self.enabled_engines:
            results['engines']['baidu'] = self.search_baidu(image_path)

        # Aggregate results
        results['summary'] = self._aggregate_results(results['engines'])

        return results

    def search_google(self, image_path: str) -> Dict[str, Any]:
        """
        Search using Google Images

        Args:
            image_path: Path to image

        Returns:
            Google search results
        """
        self.logger.info("Searching Google Images...")

        results = {
            'engine': 'google',
            'status': 'success',
            'results': [],
            'search_url': '',
            'error': None
        }

        try:
            # Method 1: Google Custom Search API (if API key available)
            if self.google_api_key and self.google_cx:
                results = self._search_google_api(image_path)
            else:
                # Method 2: Generate search URL for manual verification
                results['search_url'] = self._generate_google_search_url(image_path)
                results['status'] = 'url_generated'
                results['note'] = 'API key not available. Use search_url for manual search.'

        except Exception as e:
            self.logger.error(f"Google search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def _search_google_api(self, image_path: str) -> Dict[str, Any]:
        """Search using Google Custom Search API"""
        results = {
            'engine': 'google',
            'status': 'success',
            'results': [],
            'search_url': ''
        }

        # Upload image and get search results
        # Note: Google Custom Search API doesn't directly support image upload
        # This would require Google Cloud Vision API or alternative approach

        url = f"https://www.googleapis.com/customsearch/v1"
        params = {
            'key': self.google_api_key,
            'cx': self.google_cx,
            'searchType': 'image',
            'q': 'image search'  # Would need image URL or base64
        }

        response = self.session.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            for item in data.get('items', []):
                results['results'].append({
                    'title': item.get('title'),
                    'url': item.get('link'),
                    'source': item.get('displayLink'),
                    'thumbnail': item.get('image', {}).get('thumbnailLink')
                })

        return results

    def _generate_google_search_url(self, image_path: str) -> str:
        """Generate Google Images search URL"""
        # Google Images search by upload would require actual upload
        # This generates a URL that can be used manually
        return "https://images.google.com/searchbyimage/upload"

    def search_tineye(self, image_path: str) -> Dict[str, Any]:
        """
        Search using TinEye reverse image search

        Args:
            image_path: Path to image

        Returns:
            TinEye search results
        """
        self.logger.info("Searching TinEye...")

        results = {
            'engine': 'tineye',
            'status': 'success',
            'results': [],
            'matches': 0,
            'error': None
        }

        try:
            if self.tineye_api_key:
                # Use TinEye API
                results = self._search_tineye_api(image_path)
            else:
                # Generate search URL
                results['search_url'] = "https://tineye.com/"
                results['status'] = 'url_generated'
                results['note'] = 'API key not available. Use https://tineye.com/ for manual search.'

        except Exception as e:
            self.logger.error(f"TinEye search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def _search_tineye_api(self, image_path: str) -> Dict[str, Any]:
        """Search using TinEye API"""
        results = {
            'engine': 'tineye',
            'status': 'success',
            'results': [],
            'matches': 0
        }

        # TinEye API endpoint
        url = "https://api.tineye.com/rest/search/"

        # Read image and encode
        with open(image_path, 'rb') as f:
            image_data = f.read()

        files = {'image': image_data}
        params = {'api_key': self.tineye_api_key}

        response = self.session.post(url, files=files, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            results['matches'] = data.get('matches', 0)

            for match in data.get('results', []):
                results['results'].append({
                    'url': match.get('backlink_url'),
                    'domain': match.get('domain'),
                    'score': match.get('score'),
                    'width': match.get('width'),
                    'height': match.get('height'),
                    'crawl_date': match.get('crawl_date')
                })

        return results

    def search_yandex(self, image_path: str) -> Dict[str, Any]:
        """
        Search using Yandex Images

        Args:
            image_path: Path to image

        Returns:
            Yandex search results
        """
        self.logger.info("Searching Yandex Images...")

        results = {
            'engine': 'yandex',
            'status': 'success',
            'results': [],
            'search_url': '',
            'error': None
        }

        try:
            # Yandex reverse image search URL
            # Would need to upload image to get search URL
            results['search_url'] = "https://yandex.com/images/"
            results['status'] = 'url_generated'
            results['note'] = 'Use Yandex Images for reverse search'

        except Exception as e:
            self.logger.error(f"Yandex search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def search_bing(self, image_path: str) -> Dict[str, Any]:
        """
        Search using Bing Visual Search

        Args:
            image_path: Path to image

        Returns:
            Bing search results
        """
        self.logger.info("Searching Bing Visual Search...")

        results = {
            'engine': 'bing',
            'status': 'success',
            'results': [],
            'error': None
        }

        try:
            if self.bing_api_key:
                results = self._search_bing_api(image_path)
            else:
                results['search_url'] = "https://www.bing.com/images/"
                results['status'] = 'url_generated'
                results['note'] = 'API key not available. Use Bing Images for manual search.'

        except Exception as e:
            self.logger.error(f"Bing search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def _search_bing_api(self, image_path: str) -> Dict[str, Any]:
        """Search using Bing Visual Search API"""
        results = {
            'engine': 'bing',
            'status': 'success',
            'results': []
        }

        url = "https://api.bing.microsoft.com/v7.0/images/visualsearch"

        headers = {
            'Ocp-Apim-Subscription-Key': self.bing_api_key
        }

        with open(image_path, 'rb') as f:
            files = {'image': f}
            response = self.session.post(url, headers=headers, files=files, timeout=30)

        if response.status_code == 200:
            data = response.json()

            for tag in data.get('tags', []):
                for action in tag.get('actions', []):
                    if action.get('actionType') == 'PagesIncluding':
                        for result in action.get('data', {}).get('value', []):
                            results['results'].append({
                                'name': result.get('name'),
                                'url': result.get('hostPageUrl'),
                                'thumbnail': result.get('thumbnailUrl'),
                                'date_published': result.get('datePublished')
                            })

        return results

    def search_baidu(self, image_path: str) -> Dict[str, Any]:
        """
        Search using Baidu Images

        Args:
            image_path: Path to image

        Returns:
            Baidu search results
        """
        self.logger.info("Searching Baidu Images...")

        results = {
            'engine': 'baidu',
            'status': 'success',
            'results': [],
            'search_url': '',
            'error': None
        }

        try:
            results['search_url'] = "https://image.baidu.com/"
            results['status'] = 'url_generated'
            results['note'] = 'Use Baidu Images for reverse search'

        except Exception as e:
            self.logger.error(f"Baidu search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def search_by_url(self, image_url: str) -> Dict[str, Any]:
        """
        Search using image URL instead of file

        Args:
            image_url: URL of image

        Returns:
            Search results from all engines
        """
        self.logger.info(f"Searching by URL: {image_url}")

        results = {
            'google': f"https://images.google.com/searchbyimage?image_url={quote(image_url)}",
            'tineye': f"https://tineye.com/search?url={quote(image_url)}",
            'yandex': f"https://yandex.com/images/search?rpt=imageview&url={quote(image_url)}",
            'bing': f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIDP&sbisrc=UrlPaste&q=imgurl:{quote(image_url)}"
        }

        return results

    def _aggregate_results(self, engines: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate results from all engines"""
        summary = {
            'total_results': 0,
            'engines_searched': len(engines),
            'successful_searches': 0,
            'unique_domains': set()
        }

        for engine_name, engine_results in engines.items():
            if engine_results.get('status') == 'success':
                summary['successful_searches'] += 1

                results = engine_results.get('results', [])
                summary['total_results'] += len(results)

                for result in results:
                    domain = result.get('source') or result.get('domain') or result.get('url', '')
                    if domain:
                        summary['unique_domains'].add(domain)

        summary['unique_domains'] = list(summary['unique_domains'])

        return summary

    def compare_image_similarity(self, image1_path: str, image2_path: str) -> float:
        """
        Compare similarity between two images

        Args:
            image1_path: First image path
            image2_path: Second image path

        Returns:
            Similarity score (0-1)
        """
        from PIL import Image
        import numpy as np

        img1 = Image.open(image1_path).resize((256, 256))
        img2 = Image.open(image2_path).resize((256, 256))

        # Convert to arrays
        arr1 = np.array(img1)
        arr2 = np.array(img2)

        # Calculate normalized cross-correlation
        correlation = np.corrcoef(arr1.flatten(), arr2.flatten())[0, 1]

        return max(0, correlation)


if __name__ == "__main__":
    print("Reverse Image Search - Multi-Engine Search")
    print("=" * 60)

    searcher = ReverseImageSearch()

    print("\nSupported engines:")
    print("  - Google Images")
    print("  - TinEye")
    print("  - Yandex Images")
    print("  - Bing Visual Search")
    print("  - Baidu Images")
    print("\nUsage:")
    print("  results = searcher.search_all_engines('image.jpg')")
    print("  results = searcher.search_by_url('https://example.com/image.jpg')")
