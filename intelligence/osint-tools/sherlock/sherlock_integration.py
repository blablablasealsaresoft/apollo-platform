"""
Sherlock OSINT Integration - Username Search Across 400+ Platforms

This module provides comprehensive username search capabilities across social media
platforms, forums, gaming sites, and other online services.

Author: Apollo Intelligence Platform
License: MIT
"""

import json
import time
import logging
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import concurrent.futures
from dataclasses import dataclass, asdict
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels for username matches"""
    CONFIRMED = 0.95
    HIGH = 0.85
    MEDIUM = 0.70
    LOW = 0.50
    UNKNOWN = 0.0


@dataclass
class SherlockResult:
    """Result from a Sherlock username search"""
    username: str
    platform: str
    url: str
    exists: bool
    confidence: float
    response_time: float
    http_status: int
    error_message: Optional[str] = None
    timestamp: str = None
    additional_data: Optional[Dict] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        """Convert result to dictionary"""
        return asdict(self)


@dataclass
class BatchSearchResult:
    """Results from a batch username search"""
    username: str
    total_platforms: int
    found_platforms: int
    results: List[SherlockResult]
    search_duration: float
    timestamp: str

    def to_dict(self) -> Dict:
        """Convert batch result to dictionary"""
        return {
            'username': self.username,
            'total_platforms': self.total_platforms,
            'found_platforms': self.found_platforms,
            'results': [r.to_dict() for r in self.results],
            'search_duration': self.search_duration,
            'timestamp': self.timestamp
        }


class SherlockOSINT:
    """
    Main Sherlock OSINT integration class for username searches
    """

    def __init__(self,
                 config_path: Optional[str] = None,
                 timeout: int = 10,
                 max_workers: int = 50,
                 enable_cache: bool = True,
                 elasticsearch_client=None,
                 redis_client=None,
                 neo4j_client=None):
        """
        Initialize Sherlock OSINT engine

        Args:
            config_path: Path to platforms configuration file
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent workers
            enable_cache: Enable Redis caching
            elasticsearch_client: Elasticsearch client for storage
            redis_client: Redis client for caching
            neo4j_client: Neo4j client for relationship mapping
        """
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_cache = enable_cache

        # External integrations
        self.es_client = elasticsearch_client
        self.redis_client = redis_client
        self.neo4j_client = neo4j_client

        # Load platform configurations
        if config_path is None:
            config_path = Path(__file__).parent / "platforms_config.json"

        self.platforms = self._load_platforms(config_path)

        # Setup HTTP session with retry logic
        self.session = self._create_session()

        # Statistics
        self.stats = {
            'total_searches': 0,
            'total_platforms_checked': 0,
            'total_matches_found': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }

        self.logger.info(f"Sherlock OSINT initialized with {len(self.platforms)} platforms")

    def _load_platforms(self, config_path: Path) -> Dict:
        """Load platform configurations from JSON file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.logger.info(f"Loaded {len(data)} platform configurations")
                return data
        except FileNotFoundError:
            self.logger.warning(f"Platform config not found at {config_path}, using minimal set")
            return self._get_default_platforms()
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse platform config: {e}")
            return self._get_default_platforms()

    def _get_default_platforms(self) -> Dict:
        """Return default platform configurations"""
        return {
            "GitHub": {
                "url": "https://github.com/{}",
                "errorType": "status_code",
                "errorCode": 404,
                "category": "development"
            },
            "Twitter": {
                "url": "https://twitter.com/{}",
                "errorType": "status_code",
                "errorCode": 404,
                "category": "social"
            },
            "Instagram": {
                "url": "https://instagram.com/{}",
                "errorType": "status_code",
                "errorCode": 404,
                "category": "social"
            }
        }

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic and headers"""
        session = requests.Session()

        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"]
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Default headers to mimic browser
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        return session

    def _get_cache_key(self, username: str, platform: str) -> str:
        """Generate cache key for username-platform combination"""
        key_string = f"sherlock:{username}:{platform}"
        return hashlib.md5(key_string.encode()).hexdigest()

    def _check_cache(self, username: str, platform: str) -> Optional[SherlockResult]:
        """Check Redis cache for existing result"""
        if not self.enable_cache or not self.redis_client:
            return None

        try:
            cache_key = self._get_cache_key(username, platform)
            cached_data = self.redis_client.get(cache_key)

            if cached_data:
                self.stats['cache_hits'] += 1
                result_dict = json.loads(cached_data)
                return SherlockResult(**result_dict)

            self.stats['cache_misses'] += 1
            return None
        except Exception as e:
            self.logger.error(f"Cache check error: {e}")
            return None

    def _save_to_cache(self, result: SherlockResult, ttl: int = 86400):
        """Save result to Redis cache"""
        if not self.enable_cache or not self.redis_client:
            return

        try:
            cache_key = self._get_cache_key(result.username, result.platform)
            self.redis_client.setex(
                cache_key,
                ttl,
                json.dumps(result.to_dict())
            )
        except Exception as e:
            self.logger.error(f"Cache save error: {e}")

    def _check_platform(self,
                       username: str,
                       platform_name: str,
                       platform_config: Dict) -> SherlockResult:
        """
        Check if username exists on a specific platform

        Args:
            username: Username to search
            platform_name: Name of the platform
            platform_config: Platform configuration dictionary

        Returns:
            SherlockResult object
        """
        # Check cache first
        cached_result = self._check_cache(username, platform_name)
        if cached_result:
            return cached_result

        start_time = time.time()
        url = platform_config['url'].format(username)

        try:
            # Make request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )

            response_time = time.time() - start_time

            # Determine if username exists based on error type
            exists = self._determine_existence(response, platform_config)

            # Calculate confidence score
            confidence = self._calculate_confidence(
                response,
                platform_config,
                exists
            )

            result = SherlockResult(
                username=username,
                platform=platform_name,
                url=url,
                exists=exists,
                confidence=confidence,
                response_time=response_time,
                http_status=response.status_code,
                additional_data={
                    'category': platform_config.get('category', 'unknown'),
                    'final_url': response.url
                }
            )

        except requests.exceptions.Timeout:
            result = SherlockResult(
                username=username,
                platform=platform_name,
                url=url,
                exists=False,
                confidence=ConfidenceLevel.UNKNOWN.value,
                response_time=self.timeout,
                http_status=0,
                error_message="Request timeout"
            )

        except requests.exceptions.RequestException as e:
            result = SherlockResult(
                username=username,
                platform=platform_name,
                url=url,
                exists=False,
                confidence=ConfidenceLevel.UNKNOWN.value,
                response_time=time.time() - start_time,
                http_status=0,
                error_message=str(e)
            )

        # Save to cache
        self._save_to_cache(result)

        return result

    def _determine_existence(self,
                           response: requests.Response,
                           config: Dict) -> bool:
        """Determine if username exists based on platform configuration"""
        error_type = config.get('errorType', 'status_code')

        if error_type == 'status_code':
            error_code = config.get('errorCode', 404)
            return response.status_code != error_code

        elif error_type == 'message':
            error_msg = config.get('errorMsg', '')
            return error_msg not in response.text

        elif error_type == 'response_url':
            # Check if redirected to error page
            error_url = config.get('errorUrl', '')
            return error_url not in response.url

        # Default to status code check
        return response.status_code == 200

    def _calculate_confidence(self,
                             response: requests.Response,
                             config: Dict,
                             exists: bool) -> float:
        """Calculate confidence score for the result"""
        if not exists:
            return ConfidenceLevel.UNKNOWN.value

        confidence = ConfidenceLevel.MEDIUM.value

        # Increase confidence for 200 status
        if response.status_code == 200:
            confidence = ConfidenceLevel.HIGH.value

        # Increase confidence if platform has reliable detection
        if config.get('reliable', False):
            confidence = min(confidence + 0.1, 1.0)

        # Decrease confidence for redirects
        if len(response.history) > 0:
            confidence = max(confidence - 0.1, 0.5)

        return round(confidence, 2)

    def search_username(self,
                       username: str,
                       platforms: Optional[List[str]] = None,
                       categories: Optional[List[str]] = None,
                       min_confidence: float = 0.0) -> BatchSearchResult:
        """
        Search for username across platforms

        Args:
            username: Username to search
            platforms: Specific platforms to search (None = all)
            categories: Platform categories to search
            min_confidence: Minimum confidence threshold

        Returns:
            BatchSearchResult object
        """
        start_time = time.time()
        self.stats['total_searches'] += 1

        # Filter platforms
        platforms_to_check = self._filter_platforms(platforms, categories)

        self.logger.info(f"Searching username '{username}' across {len(platforms_to_check)} platforms")

        # Concurrent platform checking
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_platform = {
                executor.submit(
                    self._check_platform,
                    username,
                    platform_name,
                    platform_config
                ): platform_name
                for platform_name, platform_config in platforms_to_check.items()
            }

            for future in concurrent.futures.as_completed(future_to_platform):
                try:
                    result = future.result()

                    # Filter by confidence threshold
                    if result.confidence >= min_confidence:
                        results.append(result)

                        if result.exists:
                            self.stats['total_matches_found'] += 1

                    self.stats['total_platforms_checked'] += 1

                except Exception as e:
                    platform_name = future_to_platform[future]
                    self.logger.error(f"Error checking {platform_name}: {e}")

        # Sort results by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)

        # Count found platforms
        found_platforms = sum(1 for r in results if r.exists)

        search_duration = time.time() - start_time

        batch_result = BatchSearchResult(
            username=username,
            total_platforms=len(platforms_to_check),
            found_platforms=found_platforms,
            results=results,
            search_duration=search_duration,
            timestamp=datetime.utcnow().isoformat()
        )

        # Store in Elasticsearch
        self._store_results(batch_result)

        # Create Neo4j relationships
        self._create_relationships(batch_result)

        self.logger.info(
            f"Search complete: {found_platforms}/{len(platforms_to_check)} platforms found "
            f"in {search_duration:.2f}s"
        )

        return batch_result

    def _filter_platforms(self,
                         platforms: Optional[List[str]] = None,
                         categories: Optional[List[str]] = None) -> Dict:
        """Filter platforms by name or category"""
        if platforms:
            return {
                name: config
                for name, config in self.platforms.items()
                if name in platforms
            }

        if categories:
            return {
                name: config
                for name, config in self.platforms.items()
                if config.get('category', '') in categories
            }

        return self.platforms

    def batch_search(self,
                    usernames: List[str],
                    platforms: Optional[List[str]] = None,
                    categories: Optional[List[str]] = None) -> List[BatchSearchResult]:
        """
        Search multiple usernames

        Args:
            usernames: List of usernames to search
            platforms: Specific platforms to search
            categories: Platform categories to search

        Returns:
            List of BatchSearchResult objects
        """
        results = []

        for username in usernames:
            self.logger.info(f"Processing username {len(results) + 1}/{len(usernames)}: {username}")
            result = self.search_username(username, platforms, categories)
            results.append(result)

            # Brief pause between searches to be respectful
            time.sleep(1)

        return results

    def _store_results(self, batch_result: BatchSearchResult):
        """Store results in Elasticsearch"""
        if not self.es_client:
            return

        try:
            # Store batch result
            doc_id = hashlib.md5(
                f"{batch_result.username}:{batch_result.timestamp}".encode()
            ).hexdigest()

            self.es_client.index(
                index='sherlock-searches',
                id=doc_id,
                document=batch_result.to_dict()
            )

            # Store individual platform results
            for result in batch_result.results:
                if result.exists:
                    result_id = hashlib.md5(
                        f"{result.username}:{result.platform}".encode()
                    ).hexdigest()

                    self.es_client.index(
                        index='sherlock-results',
                        id=result_id,
                        document=result.to_dict()
                    )

            self.logger.debug(f"Stored results in Elasticsearch for {batch_result.username}")

        except Exception as e:
            self.logger.error(f"Elasticsearch storage error: {e}")

    def _create_relationships(self, batch_result: BatchSearchResult):
        """Create relationships in Neo4j graph database"""
        if not self.neo4j_client:
            return

        try:
            # Create username node
            self.neo4j_client.run(
                """
                MERGE (u:Username {name: $username})
                SET u.last_searched = $timestamp,
                    u.platforms_found = $found_count
                """,
                username=batch_result.username,
                timestamp=batch_result.timestamp,
                found_count=batch_result.found_platforms
            )

            # Create platform relationships
            for result in batch_result.results:
                if result.exists:
                    self.neo4j_client.run(
                        """
                        MATCH (u:Username {name: $username})
                        MERGE (p:Platform {name: $platform})
                        MERGE (u)-[r:HAS_ACCOUNT_ON]->(p)
                        SET r.url = $url,
                            r.confidence = $confidence,
                            r.discovered = $timestamp
                        """,
                        username=batch_result.username,
                        platform=result.platform,
                        url=result.url,
                        confidence=result.confidence,
                        timestamp=result.timestamp
                    )

            self.logger.debug(f"Created Neo4j relationships for {batch_result.username}")

        except Exception as e:
            self.logger.error(f"Neo4j relationship creation error: {e}")

    def export_results(self,
                      batch_result: BatchSearchResult,
                      format: str = 'json',
                      output_path: Optional[str] = None) -> str:
        """
        Export search results to file

        Args:
            batch_result: Batch search result to export
            format: Output format (json, csv, markdown)
            output_path: Output file path

        Returns:
            Path to exported file
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"sherlock_{batch_result.username}_{timestamp}.{format}"

        if format == 'json':
            return self._export_json(batch_result, output_path)
        elif format == 'csv':
            return self._export_csv(batch_result, output_path)
        elif format == 'markdown':
            return self._export_markdown(batch_result, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self, batch_result: BatchSearchResult, output_path: str) -> str:
        """Export results to JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(batch_result.to_dict(), f, indent=2, ensure_ascii=False)

        self.logger.info(f"Exported results to {output_path}")
        return output_path

    def _export_csv(self, batch_result: BatchSearchResult, output_path: str) -> str:
        """Export results to CSV"""
        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Username', 'Platform', 'URL', 'Exists', 'Confidence',
                'Response Time', 'HTTP Status', 'Category', 'Timestamp'
            ])

            # Data rows
            for result in batch_result.results:
                writer.writerow([
                    result.username,
                    result.platform,
                    result.url,
                    result.exists,
                    result.confidence,
                    f"{result.response_time:.2f}s",
                    result.http_status,
                    result.additional_data.get('category', '') if result.additional_data else '',
                    result.timestamp
                ])

        self.logger.info(f"Exported results to {output_path}")
        return output_path

    def _export_markdown(self, batch_result: BatchSearchResult, output_path: str) -> str:
        """Export results to Markdown"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# Sherlock OSINT Report: {batch_result.username}\n\n")
            f.write(f"**Search Date:** {batch_result.timestamp}\n\n")
            f.write(f"**Platforms Checked:** {batch_result.total_platforms}\n\n")
            f.write(f"**Platforms Found:** {batch_result.found_platforms}\n\n")
            f.write(f"**Search Duration:** {batch_result.search_duration:.2f}s\n\n")

            f.write("## Found Accounts\n\n")

            found_results = [r for r in batch_result.results if r.exists]

            if found_results:
                f.write("| Platform | URL | Confidence | Category |\n")
                f.write("|----------|-----|------------|----------|\n")

                for result in found_results:
                    category = result.additional_data.get('category', 'unknown') if result.additional_data else 'unknown'
                    f.write(f"| {result.platform} | {result.url} | {result.confidence:.0%} | {category} |\n")
            else:
                f.write("No accounts found.\n")

            f.write("\n## Statistics\n\n")
            f.write(f"- Average response time: {sum(r.response_time for r in batch_result.results) / len(batch_result.results):.2f}s\n")
            f.write(f"- Success rate: {batch_result.found_platforms / batch_result.total_platforms:.1%}\n")

        self.logger.info(f"Exported results to {output_path}")
        return output_path

    def get_statistics(self) -> Dict:
        """Get search statistics"""
        return {
            **self.stats,
            'platforms_available': len(self.platforms),
            'cache_hit_rate': (
                self.stats['cache_hits'] /
                (self.stats['cache_hits'] + self.stats['cache_misses'])
                if (self.stats['cache_hits'] + self.stats['cache_misses']) > 0
                else 0
            )
        }

    def close(self):
        """Close HTTP session and cleanup resources"""
        self.session.close()
        self.logger.info("Sherlock OSINT session closed")


def main():
    """Example usage"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize Sherlock OSINT
    sherlock = SherlockOSINT()

    # Search for a username
    results = sherlock.search_username("ruja_ignatova")

    print(f"\nSearch Results for '{results.username}':")
    print(f"Platforms checked: {results.total_platforms}")
    print(f"Platforms found: {results.found_platforms}")
    print(f"Search duration: {results.search_duration:.2f}s\n")

    print("Found on platforms:")
    for result in results.results:
        if result.exists:
            print(f"  - {result.platform}: {result.url} (confidence: {result.confidence:.0%})")

    # Export results
    sherlock.export_results(results, format='json')
    sherlock.export_results(results, format='markdown')

    # Get statistics
    stats = sherlock.get_statistics()
    print(f"\nStatistics: {stats}")

    # Cleanup
    sherlock.close()


if __name__ == "__main__":
    main()
