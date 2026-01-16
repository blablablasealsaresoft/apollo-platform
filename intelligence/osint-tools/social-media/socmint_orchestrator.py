#!/usr/bin/env python3
"""
SOCMINT Orchestrator - Main Social Media Intelligence Engine
Coordinates multi-platform intelligence collection and profile aggregation
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

from twitter_intel import TwitterIntel
from facebook_intel import FacebookIntel
from instagram_intel import InstagramIntel
from linkedin_intel import LinkedInIntel
from tiktok_intel import TikTokIntel
from reddit_intel import RedditIntel
from telegram_intel import TelegramIntel
from discord_intel import DiscordIntel
from platform_aggregator import PlatformAggregator


@dataclass
class TargetProfile:
    """Unified target profile across platforms"""
    username: str
    platforms: Dict[str, Dict[str, Any]]
    unified_data: Dict[str, Any]
    relationships: Dict[str, List[str]]
    timeline: List[Dict[str, Any]]
    risk_score: float
    collection_timestamp: str
    metadata: Dict[str, Any]


class SOCMINT:
    """
    Main SOCMINT Intelligence Engine
    Orchestrates multi-platform social media intelligence collection
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SOCMINT orchestrator"""
        self.config = config or {}
        self.logger = self._setup_logging()

        # Initialize platform collectors
        self.platforms = {
            'twitter': TwitterIntel(config.get('twitter', {})),
            'facebook': FacebookIntel(config.get('facebook', {})),
            'instagram': InstagramIntel(config.get('instagram', {})),
            'linkedin': LinkedInIntel(config.get('linkedin', {})),
            'tiktok': TikTokIntel(config.get('tiktok', {})),
            'reddit': RedditIntel(config.get('reddit', {})),
            'telegram': TelegramIntel(config.get('telegram', {})),
            'discord': DiscordIntel(config.get('discord', {}))
        }

        # Initialize aggregator
        self.aggregator = PlatformAggregator()

        # Collection statistics
        self.stats = {
            'profiles_collected': 0,
            'posts_collected': 0,
            'relationships_mapped': 0,
            'platforms_queried': 0
        }

        self.logger.info("SOCMINT Orchestrator initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('SOCMINT')
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def build_profile(self,
                     username: str,
                     platforms: Optional[List[str]] = None,
                     deep_scan: bool = False) -> TargetProfile:
        """
        Build comprehensive profile across multiple platforms

        Args:
            username: Target username
            platforms: List of platforms to query (None = all)
            deep_scan: Enable deep scanning with relationship mapping

        Returns:
            TargetProfile object with unified intelligence
        """
        self.logger.info(f"Building profile for: {username}")

        if platforms is None:
            platforms = list(self.platforms.keys())

        # Collect data from all platforms in parallel
        platform_data = self._collect_parallel(username, platforms, deep_scan)

        # Aggregate and unify data
        unified_data = self.aggregator.unify_profile(platform_data)
        relationships = self.aggregator.map_relationships(platform_data)
        timeline = self.aggregator.build_timeline(platform_data)

        # Calculate risk score
        risk_score = self._calculate_risk_score(platform_data, unified_data)

        # Build target profile
        profile = TargetProfile(
            username=username,
            platforms=platform_data,
            unified_data=unified_data,
            relationships=relationships,
            timeline=timeline,
            risk_score=risk_score,
            collection_timestamp=datetime.utcnow().isoformat(),
            metadata={
                'deep_scan': deep_scan,
                'platforms_queried': len(platforms),
                'total_posts': sum(len(p.get('posts', [])) for p in platform_data.values())
            }
        )

        # Update statistics
        self.stats['profiles_collected'] += 1
        self.stats['posts_collected'] += profile.metadata['total_posts']
        self.stats['platforms_queried'] += len(platforms)

        self.logger.info(f"Profile build complete: {username}")
        return profile

    def _collect_parallel(self,
                         username: str,
                         platforms: List[str],
                         deep_scan: bool) -> Dict[str, Dict[str, Any]]:
        """Collect data from multiple platforms in parallel"""
        results = {}

        with ThreadPoolExecutor(max_workers=len(platforms)) as executor:
            # Submit collection tasks
            future_to_platform = {
                executor.submit(
                    self._collect_platform_data,
                    platform,
                    username,
                    deep_scan
                ): platform
                for platform in platforms
            }

            # Collect results as they complete
            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    data = future.result(timeout=30)
                    if data:
                        results[platform] = data
                        self.logger.info(f"Collected data from {platform}")
                except Exception as e:
                    self.logger.error(f"Error collecting from {platform}: {e}")
                    results[platform] = {'error': str(e)}

        return results

    def _collect_platform_data(self,
                              platform: str,
                              username: str,
                              deep_scan: bool) -> Optional[Dict[str, Any]]:
        """Collect data from a single platform"""
        try:
            collector = self.platforms.get(platform)
            if not collector:
                return None

            # Collect profile data
            data = collector.collect_profile(username, deep_scan=deep_scan)
            return data

        except Exception as e:
            self.logger.error(f"Platform collection error ({platform}): {e}")
            return None

    def track_hashtag(self, hashtag: str, platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Track hashtag across multiple platforms

        Args:
            hashtag: Hashtag to track (without #)
            platforms: List of platforms to query

        Returns:
            Dictionary of hashtag intelligence
        """
        self.logger.info(f"Tracking hashtag: #{hashtag}")

        if platforms is None:
            platforms = ['twitter', 'instagram', 'tiktok']

        results = {}

        for platform_name in platforms:
            collector = self.platforms.get(platform_name)
            if collector and hasattr(collector, 'track_hashtag'):
                try:
                    data = collector.track_hashtag(hashtag)
                    results[platform_name] = data
                except Exception as e:
                    self.logger.error(f"Hashtag tracking error ({platform_name}): {e}")

        return results

    def monitor_location(self,
                        latitude: float,
                        longitude: float,
                        radius_km: float = 1.0,
                        platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Monitor social media activity at specific location

        Args:
            latitude: Location latitude
            longitude: Location longitude
            radius_km: Search radius in kilometers
            platforms: List of platforms to query

        Returns:
            Dictionary of location-based intelligence
        """
        self.logger.info(f"Monitoring location: {latitude}, {longitude}")

        if platforms is None:
            platforms = ['twitter', 'instagram', 'facebook']

        results = {}

        for platform_name in platforms:
            collector = self.platforms.get(platform_name)
            if collector and hasattr(collector, 'search_location'):
                try:
                    data = collector.search_location(latitude, longitude, radius_km)
                    results[platform_name] = data
                except Exception as e:
                    self.logger.error(f"Location monitoring error ({platform_name}): {e}")

        return results

    def find_connections(self, username1: str, username2: str) -> Dict[str, Any]:
        """
        Find connections between two users across platforms

        Args:
            username1: First username
            username2: Second username

        Returns:
            Connection analysis results
        """
        self.logger.info(f"Finding connections: {username1} <-> {username2}")

        # Build profiles for both users
        profile1 = self.build_profile(username1, deep_scan=True)
        profile2 = self.build_profile(username2, deep_scan=True)

        # Analyze connections
        connections = self.aggregator.find_connections(
            profile1.platforms,
            profile2.platforms
        )

        return connections

    def search_username(self, username: str) -> Dict[str, Any]:
        """
        Search for username across all platforms

        Args:
            username: Username to search

        Returns:
            Platform availability results
        """
        self.logger.info(f"Searching username: {username}")

        results = {}

        with ThreadPoolExecutor(max_workers=len(self.platforms)) as executor:
            future_to_platform = {
                executor.submit(
                    self._check_username_exists,
                    platform_name,
                    username
                ): platform_name
                for platform_name in self.platforms.keys()
            }

            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    exists = future.result(timeout=10)
                    results[platform] = {
                        'exists': exists,
                        'url': self._get_profile_url(platform, username) if exists else None
                    }
                except Exception as e:
                    results[platform] = {'error': str(e)}

        return results

    def _check_username_exists(self, platform: str, username: str) -> bool:
        """Check if username exists on platform"""
        collector = self.platforms.get(platform)
        if collector and hasattr(collector, 'check_exists'):
            return collector.check_exists(username)
        return False

    def _get_profile_url(self, platform: str, username: str) -> str:
        """Get profile URL for platform"""
        urls = {
            'twitter': f"https://twitter.com/{username}",
            'facebook': f"https://facebook.com/{username}",
            'instagram': f"https://instagram.com/{username}",
            'linkedin': f"https://linkedin.com/in/{username}",
            'tiktok': f"https://tiktok.com/@{username}",
            'reddit': f"https://reddit.com/user/{username}",
            'telegram': f"https://t.me/{username}",
        }
        return urls.get(platform, '')

    def _calculate_risk_score(self,
                             platform_data: Dict[str, Dict[str, Any]],
                             unified_data: Dict[str, Any]) -> float:
        """
        Calculate risk score based on collected intelligence

        Returns:
            Risk score from 0.0 (low) to 1.0 (high)
        """
        score = 0.0
        factors = []

        # Multiple platform presence
        active_platforms = len([p for p in platform_data.values() if p.get('profile')])
        if active_platforms > 5:
            factors.append(0.1)

        # High follower count (potential influence)
        total_followers = unified_data.get('total_followers', 0)
        if total_followers > 10000:
            factors.append(0.15)
        elif total_followers > 1000:
            factors.append(0.08)

        # High posting frequency
        total_posts = unified_data.get('total_posts', 0)
        if total_posts > 1000:
            factors.append(0.1)

        # Location sharing
        if unified_data.get('locations'):
            factors.append(0.15)

        # Multiple identities
        unique_names = len(set(unified_data.get('names', [])))
        if unique_names > 2:
            factors.append(0.2)

        # Calculate final score
        score = min(sum(factors), 1.0)

        return round(score, 3)

    def export_profile(self, profile: TargetProfile, format: str = 'json') -> str:
        """
        Export profile data in specified format

        Args:
            profile: TargetProfile object
            format: Export format (json, html, csv)

        Returns:
            Exported data as string
        """
        if format == 'json':
            return json.dumps(asdict(profile), indent=2, default=str)
        elif format == 'html':
            return self._export_html(profile)
        elif format == 'csv':
            return self._export_csv(profile)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_html(self, profile: TargetProfile) -> str:
        """Export profile as HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SOCMINT Report - {profile.username}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .platform {{ background: #ecf0f1; padding: 10px; margin: 10px 0; }}
                .risk-score {{ font-size: 24px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SOCMINT Intelligence Report</h1>
                <h2>Target: {profile.username}</h2>
                <p>Generated: {profile.collection_timestamp}</p>
            </div>

            <div class="section">
                <h3>Risk Score: <span class="risk-score">{profile.risk_score}</span></h3>
            </div>

            <div class="section">
                <h3>Platforms ({len(profile.platforms)})</h3>
                {''.join(f'<div class="platform">{p}</div>' for p in profile.platforms.keys())}
            </div>

            <div class="section">
                <h3>Timeline Events: {len(profile.timeline)}</h3>
            </div>

            <div class="section">
                <h3>Relationships</h3>
                <pre>{json.dumps(profile.relationships, indent=2)}</pre>
            </div>
        </body>
        </html>
        """
        return html

    def _export_csv(self, profile: TargetProfile) -> str:
        """Export profile as CSV"""
        lines = [
            "Field,Value",
            f"Username,{profile.username}",
            f"Risk Score,{profile.risk_score}",
            f"Platforms,{len(profile.platforms)}",
            f"Timeline Events,{len(profile.timeline)}",
            f"Collection Time,{profile.collection_timestamp}"
        ]
        return '\n'.join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return self.stats.copy()


if __name__ == '__main__':
    # Example usage
    socmint = SOCMINT()

    # Build comprehensive profile
    profile = socmint.build_profile(
        username="target_user",
        platforms=["twitter", "instagram", "linkedin"],
        deep_scan=True
    )

    print(f"Profile collected for: {profile.username}")
    print(f"Risk Score: {profile.risk_score}")
    print(f"Platforms: {len(profile.platforms)}")
    print(f"Timeline Events: {len(profile.timeline)}")

    # Export results
    json_export = socmint.export_profile(profile, format='json')
    print("\nExported profile data")

    # Get statistics
    stats = socmint.get_statistics()
    print(f"\nCollection Statistics: {stats}")
