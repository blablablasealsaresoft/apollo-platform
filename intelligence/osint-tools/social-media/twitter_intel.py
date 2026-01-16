#!/usr/bin/env python3
"""
Twitter/X Intelligence Collection
Profile scraping, tweet analysis, network mapping, and sentiment analysis
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import hashlib


@dataclass
class Tweet:
    """Tweet data structure"""
    id: str
    text: str
    author: str
    timestamp: str
    likes: int
    retweets: int
    replies: int
    hashtags: List[str]
    mentions: List[str]
    urls: List[str]
    location: Optional[Dict[str, Any]]
    sentiment: Optional[str]


class TwitterIntel:
    """
    Twitter/X Intelligence Collector
    Collects profiles, tweets, relationships, and performs analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Twitter intelligence collector"""
        self.config = config or {}
        self.logger = logging.getLogger('TwitterIntel')

        # API configuration (placeholder - would use actual Twitter API)
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        self.bearer_token = config.get('bearer_token')

        # Collection limits
        self.max_tweets = config.get('max_tweets', 200)
        self.max_followers = config.get('max_followers', 1000)

        self.logger.info("Twitter Intelligence initialized")

    def collect_profile(self, username: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Collect comprehensive Twitter profile data

        Args:
            username: Twitter username (without @)
            deep_scan: Enable deep scanning with network analysis

        Returns:
            Dictionary containing profile intelligence
        """
        self.logger.info(f"Collecting Twitter profile: @{username}")

        profile_data = {
            'platform': 'twitter',
            'username': username,
            'profile': self._get_profile_info(username),
            'tweets': self._collect_tweets(username),
            'metrics': {},
            'network': {},
            'activity_patterns': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        if deep_scan:
            profile_data['network'] = self._analyze_network(username)
            profile_data['activity_patterns'] = self._analyze_activity_patterns(
                profile_data['tweets']
            )

        # Calculate metrics
        profile_data['metrics'] = self._calculate_metrics(profile_data)

        return profile_data

    def _get_profile_info(self, username: str) -> Dict[str, Any]:
        """Get Twitter profile information"""
        # Simulate API call - in production, use Twitter API v2
        profile = {
            'username': username,
            'display_name': f"User {username}",
            'user_id': hashlib.md5(username.encode()).hexdigest()[:16],
            'bio': f"Twitter user {username}",
            'location': "Unknown",
            'url': None,
            'joined_date': "2020-01-01",
            'verified': False,
            'protected': False,
            'followers_count': 0,
            'following_count': 0,
            'tweet_count': 0,
            'listed_count': 0,
            'profile_image_url': f"https://twitter.com/{username}/photo.jpg",
            'banner_image_url': None
        }

        return profile

    def _collect_tweets(self, username: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Collect recent tweets from user"""
        if limit is None:
            limit = self.max_tweets

        self.logger.info(f"Collecting up to {limit} tweets from @{username}")

        # Simulate tweet collection - in production, use Twitter API
        tweets = []

        for i in range(min(limit, 10)):  # Demo: 10 tweets
            tweet = {
                'id': hashlib.md5(f"{username}{i}".encode()).hexdigest(),
                'text': f"Sample tweet {i} from @{username}",
                'created_at': (datetime.utcnow() - timedelta(days=i)).isoformat(),
                'likes': i * 10,
                'retweets': i * 5,
                'replies': i * 2,
                'hashtags': self._extract_hashtags(f"Sample #tweet {i}"),
                'mentions': self._extract_mentions(f"Sample tweet {i}"),
                'urls': [],
                'location': None,
                'sentiment': self._analyze_sentiment(f"Sample tweet {i}"),
                'is_retweet': False,
                'is_reply': False,
                'lang': 'en'
            }
            tweets.append(tweet)

        return tweets

    def _extract_hashtags(self, text: str) -> List[str]:
        """Extract hashtags from tweet text"""
        return re.findall(r'#(\w+)', text)

    def _extract_mentions(self, text: str) -> List[str]:
        """Extract mentions from tweet text"""
        return re.findall(r'@(\w+)', text)

    def _analyze_sentiment(self, text: str) -> str:
        """
        Analyze tweet sentiment

        Returns:
            Sentiment: positive, negative, or neutral
        """
        # Simple keyword-based sentiment (in production, use NLP model)
        positive_words = ['good', 'great', 'awesome', 'love', 'excellent', 'happy']
        negative_words = ['bad', 'hate', 'terrible', 'awful', 'sad', 'angry']

        text_lower = text.lower()

        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)

        if positive_count > negative_count:
            return 'positive'
        elif negative_count > positive_count:
            return 'negative'
        else:
            return 'neutral'

    def _analyze_network(self, username: str) -> Dict[str, Any]:
        """Analyze follower/following network"""
        self.logger.info(f"Analyzing network for @{username}")

        network = {
            'followers': self._get_followers(username, limit=100),
            'following': self._get_following(username, limit=100),
            'mutual_connections': [],
            'influential_followers': [],
            'network_metrics': {}
        }

        # Calculate mutual connections
        followers_set = set(f['username'] for f in network['followers'])
        following_set = set(f['username'] for f in network['following'])
        network['mutual_connections'] = list(followers_set & following_set)

        # Identify influential followers (high follower count)
        network['influential_followers'] = sorted(
            network['followers'],
            key=lambda x: x.get('followers_count', 0),
            reverse=True
        )[:10]

        # Network metrics
        network['network_metrics'] = {
            'follower_count': len(network['followers']),
            'following_count': len(network['following']),
            'mutual_count': len(network['mutual_connections']),
            'follower_following_ratio': (
                len(network['followers']) / max(len(network['following']), 1)
            )
        }

        return network

    def _get_followers(self, username: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get user followers"""
        # Simulate API call
        followers = []
        for i in range(min(limit, 10)):
            followers.append({
                'username': f"follower_{i}",
                'display_name': f"Follower {i}",
                'followers_count': i * 100,
                'verified': False
            })
        return followers

    def _get_following(self, username: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get users that the target is following"""
        # Simulate API call
        following = []
        for i in range(min(limit, 10)):
            following.append({
                'username': f"following_{i}",
                'display_name': f"Following {i}",
                'followers_count': i * 150,
                'verified': False
            })
        return following

    def _analyze_activity_patterns(self, tweets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze posting patterns and activity"""
        if not tweets:
            return {}

        patterns = {
            'posting_hours': {},
            'posting_days': {},
            'hashtag_frequency': {},
            'mention_frequency': {},
            'avg_engagement': {},
            'content_analysis': {}
        }

        # Analyze posting times
        for tweet in tweets:
            timestamp = datetime.fromisoformat(tweet['created_at'].replace('Z', '+00:00'))
            hour = timestamp.hour
            day = timestamp.strftime('%A')

            patterns['posting_hours'][hour] = patterns['posting_hours'].get(hour, 0) + 1
            patterns['posting_days'][day] = patterns['posting_days'].get(day, 0) + 1

        # Hashtag frequency
        for tweet in tweets:
            for hashtag in tweet.get('hashtags', []):
                patterns['hashtag_frequency'][hashtag] = (
                    patterns['hashtag_frequency'].get(hashtag, 0) + 1
                )

        # Calculate average engagement
        if tweets:
            patterns['avg_engagement'] = {
                'avg_likes': sum(t['likes'] for t in tweets) / len(tweets),
                'avg_retweets': sum(t['retweets'] for t in tweets) / len(tweets),
                'avg_replies': sum(t['replies'] for t in tweets) / len(tweets)
            }

        # Sentiment distribution
        sentiments = [t.get('sentiment', 'neutral') for t in tweets]
        patterns['content_analysis'] = {
            'positive_tweets': sentiments.count('positive'),
            'negative_tweets': sentiments.count('negative'),
            'neutral_tweets': sentiments.count('neutral'),
            'sentiment_ratio': sentiments.count('positive') / max(sentiments.count('negative'), 1)
        }

        return patterns

    def _calculate_metrics(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate profile metrics"""
        profile = profile_data.get('profile', {})
        tweets = profile_data.get('tweets', [])

        metrics = {
            'total_tweets': len(tweets),
            'total_followers': profile.get('followers_count', 0),
            'total_following': profile.get('following_count', 0),
            'engagement_rate': 0.0,
            'influence_score': 0.0,
            'activity_score': 0.0
        }

        # Calculate engagement rate
        if tweets and metrics['total_followers'] > 0:
            total_engagement = sum(
                t['likes'] + t['retweets'] + t['replies']
                for t in tweets
            )
            metrics['engagement_rate'] = (
                total_engagement / (len(tweets) * metrics['total_followers'])
            )

        # Calculate influence score (0-100)
        follower_score = min(metrics['total_followers'] / 10000, 1.0) * 40
        engagement_score = min(metrics['engagement_rate'] * 100, 1.0) * 30
        verified_score = 30 if profile.get('verified') else 0
        metrics['influence_score'] = follower_score + engagement_score + verified_score

        # Calculate activity score
        if tweets:
            recent_tweets = [
                t for t in tweets
                if (datetime.utcnow() - datetime.fromisoformat(t['created_at'].replace('Z', '+00:00'))).days <= 7
            ]
            metrics['activity_score'] = min(len(recent_tweets) / 7, 1.0) * 100

        return metrics

    def track_hashtag(self, hashtag: str, limit: int = 100) -> Dict[str, Any]:
        """
        Track hashtag usage and trends

        Args:
            hashtag: Hashtag to track (without #)
            limit: Maximum tweets to collect

        Returns:
            Hashtag intelligence data
        """
        self.logger.info(f"Tracking hashtag: #{hashtag}")

        # Simulate hashtag search
        results = {
            'hashtag': hashtag,
            'tweet_count': 0,
            'tweets': [],
            'top_users': [],
            'geographic_distribution': {},
            'sentiment_distribution': {},
            'trending_score': 0.0,
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Collect tweets with hashtag
        for i in range(min(limit, 20)):
            tweet = {
                'id': hashlib.md5(f"{hashtag}{i}".encode()).hexdigest(),
                'text': f"Tweet about #{hashtag}",
                'author': f"user_{i}",
                'created_at': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'likes': i * 5,
                'retweets': i * 3,
                'sentiment': self._analyze_sentiment(f"Tweet about {hashtag}")
            }
            results['tweets'].append(tweet)

        results['tweet_count'] = len(results['tweets'])

        return results

    def search_location(self,
                       latitude: float,
                       longitude: float,
                       radius_km: float = 1.0) -> Dict[str, Any]:
        """
        Search tweets from specific location

        Args:
            latitude: Location latitude
            longitude: Location longitude
            radius_km: Search radius in kilometers

        Returns:
            Location-based tweet intelligence
        """
        self.logger.info(f"Searching tweets near {latitude}, {longitude}")

        results = {
            'location': {
                'latitude': latitude,
                'longitude': longitude,
                'radius_km': radius_km
            },
            'tweets': [],
            'users': [],
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Simulate location-based search
        for i in range(10):
            tweet = {
                'id': hashlib.md5(f"{latitude}{longitude}{i}".encode()).hexdigest(),
                'text': f"Tweet from location {i}",
                'author': f"user_{i}",
                'location': {
                    'latitude': latitude + (i * 0.001),
                    'longitude': longitude + (i * 0.001),
                    'place_name': f"Place {i}"
                },
                'created_at': (datetime.utcnow() - timedelta(hours=i)).isoformat()
            }
            results['tweets'].append(tweet)

        return results

    def check_exists(self, username: str) -> bool:
        """Check if Twitter profile exists"""
        # Simulate profile check
        # In production, make HEAD request to profile URL
        return True

    def export_data(self, data: Dict[str, Any], format: str = 'json') -> str:
        """Export collected data"""
        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")


if __name__ == '__main__':
    # Example usage
    twitter = TwitterIntel()

    # Collect profile
    profile = twitter.collect_profile("target_user", deep_scan=True)
    print(f"Collected profile: {profile['username']}")
    print(f"Tweets: {len(profile['tweets'])}")
    print(f"Influence Score: {profile['metrics']['influence_score']:.2f}")

    # Track hashtag
    hashtag_data = twitter.track_hashtag("cybersecurity")
    print(f"\nHashtag #{hashtag_data['hashtag']}: {hashtag_data['tweet_count']} tweets")
