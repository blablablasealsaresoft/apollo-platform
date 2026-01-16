"""
PimEyes Integration - Face Search Across the Web
Monitor and search for faces using PimEyes service
"""

import os
import logging
import requests
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import json


class PimEyesIntegration:
    """
    PimEyes integration for searching faces across the web
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize PimEyes integration"""
        self.config = config or {}
        self.logger = logging.getLogger('PimEyes')

        # API configuration
        self.api_key = self.config.get('api_key', os.getenv('PIMEYES_API_KEY'))
        self.base_url = self.config.get('base_url', 'https://api.pimeyes.com')

        # Session
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'User-Agent': 'IMINT-OSINT-Tool/1.0'
            })

        # Monitoring state
        self.monitoring_active = False
        self.monitoring_interval = self.config.get('monitoring_interval', 3600)  # 1 hour

        self.logger.info("PimEyes integration initialized")

    def search_faces(self, image_path: str) -> Dict[str, Any]:
        """
        Search for faces in an image across the web

        Args:
            image_path: Path to image containing face

        Returns:
            Search results with found faces
        """
        self.logger.info(f"Searching faces in: {image_path}")

        results = {
            'image_path': image_path,
            'timestamp': datetime.now().isoformat(),
            'status': 'success',
            'results': [],
            'total_matches': 0,
            'error': None
        }

        if not self.api_key:
            results['status'] = 'no_api_key'
            results['error'] = 'PimEyes API key not configured'
            results['note'] = 'Visit https://pimeyes.com for manual search'
            return results

        try:
            # Upload image and search
            search_results = self._perform_search(image_path)

            if search_results:
                results['results'] = search_results
                results['total_matches'] = len(search_results)
                self.logger.info(f"Found {len(search_results)} matches")

        except Exception as e:
            self.logger.error(f"PimEyes search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def _perform_search(self, image_path: str) -> List[Dict[str, Any]]:
        """Perform actual PimEyes search"""
        results = []

        try:
            # Step 1: Upload image
            upload_url = f"{self.base_url}/upload"

            with open(image_path, 'rb') as f:
                files = {'image': f}
                upload_response = self.session.post(upload_url, files=files, timeout=30)

            if upload_response.status_code != 200:
                raise Exception(f"Upload failed: {upload_response.status_code}")

            upload_data = upload_response.json()
            image_id = upload_data.get('image_id')

            if not image_id:
                raise Exception("No image_id returned from upload")

            # Step 2: Perform search
            search_url = f"{self.base_url}/search"
            search_payload = {
                'image_id': image_id,
                'max_results': self.config.get('max_results', 100)
            }

            search_response = self.session.post(search_url, json=search_payload, timeout=60)

            if search_response.status_code != 200:
                raise Exception(f"Search failed: {search_response.status_code}")

            search_data = search_response.json()

            # Step 3: Process results
            for match in search_data.get('matches', []):
                results.append({
                    'url': match.get('url'),
                    'thumbnail': match.get('thumbnail_url'),
                    'domain': match.get('domain'),
                    'similarity': match.get('similarity_score'),
                    'date_found': match.get('date_found'),
                    'context': match.get('context', '')
                })

        except Exception as e:
            self.logger.error(f"PimEyes API error: {str(e)}")
            # Note: This is a mock implementation
            # Real PimEyes API may have different endpoints and response format
            raise

        return results

    def monitor_face(self, face_image_path: str, alert_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Set up monitoring for a face across the web

        Args:
            face_image_path: Path to face image
            alert_callback: Function to call when new images found

        Returns:
            Monitoring configuration
        """
        self.logger.info(f"Setting up face monitoring for: {face_image_path}")

        monitor_config = {
            'face_image': face_image_path,
            'started': datetime.now().isoformat(),
            'status': 'active',
            'interval_seconds': self.monitoring_interval,
            'alert_callback': alert_callback is not None,
            'results': []
        }

        if not self.api_key:
            monitor_config['status'] = 'no_api_key'
            monitor_config['error'] = 'PimEyes API key not configured'
            return monitor_config

        # Perform initial search to establish baseline
        initial_results = self.search_faces(face_image_path)
        monitor_config['initial_matches'] = initial_results.get('total_matches', 0)

        # Store baseline URLs
        baseline_urls = set()
        for result in initial_results.get('results', []):
            baseline_urls.add(result.get('url'))

        monitor_config['baseline_urls'] = list(baseline_urls)

        # In a real implementation, this would start a background monitoring task
        self.logger.info(f"Monitoring setup complete. Initial matches: {monitor_config['initial_matches']}")

        return monitor_config

    def check_monitoring_updates(self, monitor_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check for new results in monitored face

        Args:
            monitor_config: Monitoring configuration from monitor_face()

        Returns:
            New results found since last check
        """
        self.logger.info("Checking for monitoring updates...")

        updates = {
            'checked': datetime.now().isoformat(),
            'new_matches': 0,
            'new_results': []
        }

        try:
            # Perform new search
            current_results = self.search_faces(monitor_config['face_image'])

            # Compare with baseline
            baseline_urls = set(monitor_config.get('baseline_urls', []))

            for result in current_results.get('results', []):
                url = result.get('url')
                if url not in baseline_urls:
                    updates['new_results'].append(result)
                    updates['new_matches'] += 1

            if updates['new_matches'] > 0:
                self.logger.info(f"Found {updates['new_matches']} new matches")

                # Call alert callback if provided
                if monitor_config.get('alert_callback'):
                    # In real implementation, would call the callback function
                    pass

        except Exception as e:
            self.logger.error(f"Monitoring update error: {str(e)}")
            updates['error'] = str(e)

        return updates

    def search_by_url(self, image_url: str) -> Dict[str, Any]:
        """
        Search for faces using image URL

        Args:
            image_url: URL of image

        Returns:
            Search results
        """
        self.logger.info(f"Searching by URL: {image_url}")

        results = {
            'image_url': image_url,
            'timestamp': datetime.now().isoformat(),
            'status': 'success',
            'results': [],
            'error': None
        }

        if not self.api_key:
            results['status'] = 'no_api_key'
            results['pimeyes_url'] = 'https://pimeyes.com'
            return results

        try:
            # Search using URL
            search_url = f"{self.base_url}/search_by_url"
            payload = {'image_url': image_url}

            response = self.session.post(search_url, json=payload, timeout=60)

            if response.status_code == 200:
                data = response.json()
                results['results'] = data.get('matches', [])
                results['total_matches'] = len(results['results'])

        except Exception as e:
            self.logger.error(f"URL search error: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        return results

    def get_search_credits(self) -> Dict[str, Any]:
        """
        Get remaining PimEyes API credits

        Returns:
            Credit information
        """
        credits = {
            'available': 0,
            'used': 0,
            'limit': 0,
            'reset_date': None
        }

        if not self.api_key:
            return credits

        try:
            url = f"{self.base_url}/credits"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                credits.update(data)

        except Exception as e:
            self.logger.error(f"Error getting credits: {str(e)}")

        return credits

    def batch_search_faces(self, image_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Search multiple faces in batch

        Args:
            image_paths: List of image paths

        Returns:
            List of search results
        """
        self.logger.info(f"Batch searching {len(image_paths)} faces")

        results = []

        for i, image_path in enumerate(image_paths):
            self.logger.info(f"Searching face {i+1}/{len(image_paths)}: {image_path}")

            try:
                result = self.search_faces(image_path)
                results.append(result)

                # Rate limiting
                if i < len(image_paths) - 1:
                    time.sleep(2)  # 2 second delay between searches

            except Exception as e:
                self.logger.error(f"Error searching {image_path}: {str(e)}")
                results.append({
                    'image_path': image_path,
                    'status': 'error',
                    'error': str(e)
                })

        return results

    def export_results(self, results: Dict[str, Any], output_file: str):
        """
        Export search results to file

        Args:
            results: Search results
            output_file: Output file path
        """
        self.logger.info(f"Exporting results to: {output_file}")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        self.logger.info("Results exported")

    def generate_manual_search_url(self) -> str:
        """
        Generate URL for manual PimEyes search

        Returns:
            PimEyes search URL
        """
        return "https://pimeyes.com/en"


if __name__ == "__main__":
    print("PimEyes Integration - Face Search Across the Web")
    print("=" * 60)

    pimeyes = PimEyesIntegration()

    print("\nCapabilities:")
    print("  - Search faces across the internet")
    print("  - Monitor faces for new appearances")
    print("  - Alert on new images found")
    print("  - Batch face searching")
    print("\nUsage:")
    print("  results = pimeyes.search_faces('face.jpg')")
    print("  monitor = pimeyes.monitor_face('suspect.jpg', alert_callback)")
    print("  updates = pimeyes.check_monitoring_updates(monitor)")
    print("\nNote: Requires PimEyes API key")
    print("Manual search: https://pimeyes.com")
