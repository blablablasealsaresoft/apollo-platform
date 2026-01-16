#!/usr/bin/env python3
"""
Instagram Intelligence Collection
Profile extraction, post/story collection, follower analysis, and image analysis
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import hashlib


@dataclass
class InstagramPost:
    """Instagram post data structure"""
    id: str
    shortcode: str
    type: str  # photo, video, carousel
    caption: str
    timestamp: str
    likes: int
    comments: int
    media_url: str
    thumbnail_url: str
    hashtags: List[str]
    mentions: List[str]
    location: Optional[Dict[str, Any]]


class InstagramIntel:
    """
    Instagram Intelligence Collector
    Collects profiles, posts, stories, followers, and performs image analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Instagram intelligence collector"""
        self.config = config or {}
        self.logger = logging.getLogger('InstagramIntel')

        # API configuration
        self.access_token = config.get('access_token')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')

        # Collection limits
        self.max_posts = config.get('max_posts', 100)
        self.max_followers = config.get('max_followers', 500)

        self.logger.info("Instagram Intelligence initialized")

    def collect_profile(self, username: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Collect comprehensive Instagram profile data

        Args:
            username: Instagram username
            deep_scan: Enable deep scanning with media analysis

        Returns:
            Dictionary containing profile intelligence
        """
        self.logger.info(f"Collecting Instagram profile: @{username}")

        profile_data = {
            'platform': 'instagram',
            'username': username,
            'profile': self._get_profile_info(username),
            'posts': self._collect_posts(username),
            'stories': [],
            'highlights': [],
            'reels': [],
            'igtv': [],
            'tagged_posts': [],
            'followers': [],
            'following': [],
            'metrics': {},
            'content_analysis': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        if deep_scan:
            profile_data['followers'] = self._get_followers(username, limit=100)
            profile_data['following'] = self._get_following(username, limit=100)
            profile_data['tagged_posts'] = self._get_tagged_posts(username)
            profile_data['content_analysis'] = self._analyze_content(profile_data['posts'])

        # Calculate metrics
        profile_data['metrics'] = self._calculate_metrics(profile_data)

        return profile_data

    def _get_profile_info(self, username: str) -> Dict[str, Any]:
        """Get Instagram profile information"""
        # Simulate Instagram API call
        profile = {
            'user_id': hashlib.md5(username.encode()).hexdigest()[:16],
            'username': username,
            'full_name': f"User {username}",
            'biography': f"Instagram user {username}",
            'external_url': None,
            'profile_picture_url': f"https://instagram.com/{username}/profile.jpg",
            'is_private': False,
            'is_verified': False,
            'is_business': False,
            'business_category': None,
            'followers_count': 0,
            'following_count': 0,
            'media_count': 0,
            'email': None,
            'phone': None,
            'location': None,
            'created_at': None  # Not available via API
        }

        return profile

    def _collect_posts(self, username: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Collect Instagram posts"""
        if limit is None:
            limit = self.max_posts

        self.logger.info(f"Collecting up to {limit} posts from @{username}")

        posts = []

        for i in range(min(limit, 12)):
            post = {
                'id': hashlib.md5(f"{username}_post_{i}".encode()).hexdigest(),
                'shortcode': f"ABC{i}XYZ",
                'type': ['photo', 'video', 'carousel'][i % 3],
                'caption': f"Sample Instagram post {i} #instagram #post",
                'timestamp': (datetime.utcnow() - timedelta(days=i*3)).isoformat(),
                'likes_count': i * 100,
                'comments_count': i * 10,
                'media_url': f"https://instagram.com/p/{i}/media.jpg",
                'thumbnail_url': f"https://instagram.com/p/{i}/thumb.jpg",
                'hashtags': self._extract_hashtags(f"Sample post {i} #instagram #post"),
                'mentions': [],
                'location': None,
                'is_video': (i % 3 == 1),
                'video_view_count': i * 500 if (i % 3 == 1) else 0,
                'accessibility_caption': f"Photo description {i}"
            }
            posts.append(post)

        return posts

    def _extract_hashtags(self, text: str) -> List[str]:
        """Extract hashtags from caption"""
        import re
        return re.findall(r'#(\w+)', text)

    def _get_followers(self, username: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get user followers"""
        self.logger.info(f"Collecting followers of @{username}")

        followers = []

        for i in range(min(limit, 20)):
            follower = {
                'user_id': hashlib.md5(f"follower_{i}".encode()).hexdigest()[:16],
                'username': f"follower_{i}",
                'full_name': f"Follower {i}",
                'profile_picture': f"https://instagram.com/follower_{i}/picture.jpg",
                'is_verified': False,
                'is_private': (i % 3 == 0)
            }
            followers.append(follower)

        return followers

    def _get_following(self, username: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get users that target is following"""
        self.logger.info(f"Collecting following of @{username}")

        following = []

        for i in range(min(limit, 20)):
            user = {
                'user_id': hashlib.md5(f"following_{i}".encode()).hexdigest()[:16],
                'username': f"following_{i}",
                'full_name': f"Following {i}",
                'profile_picture': f"https://instagram.com/following_{i}/picture.jpg",
                'is_verified': (i % 5 == 0),
                'is_private': False
            }
            following.append(user)

        return following

    def _get_tagged_posts(self, username: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get posts where user is tagged"""
        self.logger.info(f"Collecting tagged posts of @{username}")

        tagged = []

        for i in range(min(limit, 10)):
            post = {
                'id': hashlib.md5(f"{username}_tagged_{i}".encode()).hexdigest(),
                'shortcode': f"TAG{i}XYZ",
                'owner': f"tagger_{i}",
                'caption': f"Post tagging @{username}",
                'timestamp': (datetime.utcnow() - timedelta(days=i*5)).isoformat(),
                'media_url': f"https://instagram.com/p/tagged_{i}/media.jpg"
            }
            tagged.append(post)

        return tagged

    def _analyze_content(self, posts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze post content and patterns"""
        if not posts:
            return {}

        analysis = {
            'hashtag_frequency': {},
            'posting_times': {},
            'media_types': {'photo': 0, 'video': 0, 'carousel': 0},
            'engagement_patterns': {},
            'content_themes': [],
            'color_analysis': {},
            'face_detection': {}
        }

        # Analyze hashtags
        for post in posts:
            for hashtag in post.get('hashtags', []):
                analysis['hashtag_frequency'][hashtag] = (
                    analysis['hashtag_frequency'].get(hashtag, 0) + 1
                )

        # Analyze posting times
        for post in posts:
            timestamp = datetime.fromisoformat(post['timestamp'].replace('Z', '+00:00'))
            hour = timestamp.hour
            analysis['posting_times'][hour] = analysis['posting_times'].get(hour, 0) + 1

        # Count media types
        for post in posts:
            media_type = post.get('type', 'photo')
            analysis['media_types'][media_type] = analysis['media_types'].get(media_type, 0) + 1

        # Engagement patterns
        if posts:
            total_likes = sum(p['likes_count'] for p in posts)
            total_comments = sum(p['comments_count'] for p in posts)
            analysis['engagement_patterns'] = {
                'avg_likes': total_likes / len(posts),
                'avg_comments': total_comments / len(posts),
                'engagement_rate': (total_likes + total_comments) / len(posts),
                'like_to_comment_ratio': total_likes / max(total_comments, 1)
            }

        return analysis

    def _calculate_metrics(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate profile metrics"""
        profile = profile_data.get('profile', {})
        posts = profile_data.get('posts', [])

        metrics = {
            'total_posts': len(posts),
            'total_followers': profile.get('followers_count', 0),
            'total_following': profile.get('following_count', 0),
            'follower_following_ratio': 0.0,
            'engagement_rate': 0.0,
            'avg_likes': 0.0,
            'avg_comments': 0.0,
            'influence_score': 0.0
        }

        # Calculate ratios
        if profile.get('following_count', 0) > 0:
            metrics['follower_following_ratio'] = (
                profile.get('followers_count', 0) / profile['following_count']
            )

        # Calculate engagement
        if posts and metrics['total_followers'] > 0:
            total_engagement = sum(
                p['likes_count'] + p['comments_count']
                for p in posts
            )
            metrics['avg_likes'] = sum(p['likes_count'] for p in posts) / len(posts)
            metrics['avg_comments'] = sum(p['comments_count'] for p in posts) / len(posts)
            metrics['engagement_rate'] = (
                total_engagement / (len(posts) * metrics['total_followers']) * 100
            )

        # Calculate influence score (0-100)
        follower_score = min(metrics['total_followers'] / 10000, 1.0) * 40
        engagement_score = min(metrics['engagement_rate'], 1.0) * 30
        verified_score = 30 if profile.get('is_verified') else 0
        metrics['influence_score'] = follower_score + engagement_score + verified_score

        return metrics

    def track_hashtag(self, hashtag: str, limit: int = 100) -> Dict[str, Any]:
        """
        Track hashtag usage on Instagram

        Args:
            hashtag: Hashtag to track (without #)
            limit: Maximum posts to collect

        Returns:
            Hashtag intelligence data
        """
        self.logger.info(f"Tracking hashtag: #{hashtag}")

        results = {
            'hashtag': hashtag,
            'post_count': 0,
            'posts': [],
            'top_posts': [],
            'recent_posts': [],
            'users': [],
            'related_hashtags': [],
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Simulate hashtag search
        for i in range(min(limit, 20)):
            post = {
                'id': hashlib.md5(f"{hashtag}_post_{i}".encode()).hexdigest(),
                'username': f"user_{i}",
                'caption': f"Post about #{hashtag}",
                'likes_count': i * 50,
                'comments_count': i * 5,
                'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'media_url': f"https://instagram.com/p/{hashtag}_{i}/media.jpg"
            }
            results['posts'].append(post)

        results['post_count'] = len(results['posts'])

        # Top posts (sorted by engagement)
        results['top_posts'] = sorted(
            results['posts'],
            key=lambda x: x['likes_count'] + x['comments_count'],
            reverse=True
        )[:9]

        return results

    def search_location(self,
                       latitude: float,
                       longitude: float,
                       radius_km: float = 1.0) -> Dict[str, Any]:
        """
        Search Instagram posts from specific location

        Args:
            latitude: Location latitude
            longitude: Location longitude
            radius_km: Search radius in kilometers

        Returns:
            Location-based intelligence
        """
        self.logger.info(f"Searching Instagram posts near {latitude}, {longitude}")

        results = {
            'location': {
                'latitude': latitude,
                'longitude': longitude,
                'radius_km': radius_km
            },
            'posts': [],
            'locations': [],
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Simulate location search
        for i in range(10):
            post = {
                'id': hashlib.md5(f"loc_{latitude}_{longitude}_{i}".encode()).hexdigest(),
                'username': f"user_{i}",
                'caption': f"Post from location {i}",
                'location': {
                    'id': f"loc_{i}",
                    'name': f"Location {i}",
                    'latitude': latitude + (i * 0.001),
                    'longitude': longitude + (i * 0.001)
                },
                'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'media_url': f"https://instagram.com/p/loc_{i}/media.jpg"
            }
            results['posts'].append(post)

        return results

    def analyze_story(self, username: str) -> Dict[str, Any]:
        """
        Analyze Instagram stories (24-hour content)

        Args:
            username: Instagram username

        Returns:
            Story analysis data
        """
        self.logger.info(f"Analyzing stories from @{username}")

        stories = {
            'username': username,
            'stories': [],
            'total_views': 0,
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Simulate story collection (stories expire after 24h)
        for i in range(5):
            story = {
                'id': hashlib.md5(f"{username}_story_{i}".encode()).hexdigest(),
                'type': 'photo' if i % 2 == 0 else 'video',
                'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(hours=24-i)).isoformat(),
                'view_count': (5-i) * 100,
                'media_url': f"https://instagram.com/stories/{username}/{i}/media.jpg",
                'has_audio': (i % 2 == 1),
                'stickers': []
            }
            stories['stories'].append(story)

        stories['total_views'] = sum(s['view_count'] for s in stories['stories'])

        return stories

    def check_exists(self, username: str) -> bool:
        """Check if Instagram profile exists"""
        # Simulate profile check
        return True

    def export_data(self, data: Dict[str, Any], format: str = 'json') -> str:
        """Export collected data"""
        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")


if __name__ == '__main__':
    # Example usage
    instagram = InstagramIntel()

    # Collect profile
    profile = instagram.collect_profile("target_user", deep_scan=True)
    print(f"Collected profile: @{profile['username']}")
    print(f"Posts: {len(profile['posts'])}")
    print(f"Followers: {len(profile['followers'])}")
    print(f"Influence Score: {profile['metrics']['influence_score']:.2f}")

    # Track hashtag
    hashtag_data = instagram.track_hashtag("travel")
    print(f"\nHashtag #{hashtag_data['hashtag']}: {hashtag_data['post_count']} posts")
