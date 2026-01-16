#!/usr/bin/env python3
"""
Platform Aggregator - Cross-Platform Intelligence Unification
Unifies data from multiple social media platforms into coherent profiles
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict
import hashlib


class PlatformAggregator:
    """
    Cross-Platform Intelligence Aggregator
    Unifies and correlates data from multiple social media platforms
    """

    def __init__(self):
        """Initialize platform aggregator"""
        self.logger = logging.getLogger('PlatformAggregator')
        self.logger.info("Platform Aggregator initialized")

    def unify_profile(self, platform_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Unify profile data from multiple platforms

        Args:
            platform_data: Dictionary of platform data keyed by platform name

        Returns:
            Unified profile dictionary
        """
        self.logger.info(f"Unifying profile across {len(platform_data)} platforms")

        unified = {
            'names': [],
            'usernames': {},
            'locations': [],
            'bios': [],
            'profile_pictures': [],
            'emails': [],
            'phones': [],
            'websites': [],
            'total_followers': 0,
            'total_following': 0,
            'total_posts': 0,
            'platforms_present': [],
            'account_ages': {},
            'verified_platforms': [],
            'metadata': {}
        }

        for platform, data in platform_data.items():
            if 'error' in data:
                continue

            profile = data.get('profile', {})
            unified['platforms_present'].append(platform)

            # Extract names
            self._extract_names(profile, platform, unified)

            # Extract usernames
            unified['usernames'][platform] = self._extract_username(profile, platform)

            # Extract locations
            location = self._extract_location(profile, platform)
            if location:
                unified['locations'].append({
                    'platform': platform,
                    'location': location
                })

            # Extract bios/descriptions
            bio = self._extract_bio(profile, platform)
            if bio:
                unified['bios'].append({
                    'platform': platform,
                    'bio': bio
                })

            # Extract profile pictures
            profile_pic = self._extract_profile_picture(profile, platform)
            if profile_pic:
                unified['profile_pictures'].append({
                    'platform': platform,
                    'url': profile_pic
                })

            # Extract contact information
            email = profile.get('email')
            if email:
                unified['emails'].append(email)

            phone = profile.get('phone')
            if phone:
                unified['phones'].append(phone)

            # Extract website/URLs
            website = self._extract_website(profile, platform)
            if website:
                unified['websites'].append({
                    'platform': platform,
                    'url': website
                })

            # Aggregate metrics
            unified['total_followers'] += self._extract_followers(profile, platform)
            unified['total_following'] += self._extract_following(profile, platform)
            unified['total_posts'] += self._extract_post_count(data, platform)

            # Track verification status
            if self._is_verified(profile, platform):
                unified['verified_platforms'].append(platform)

            # Track account age
            created = self._extract_created_date(profile, platform)
            if created:
                unified['account_ages'][platform] = created

        # Deduplicate lists
        unified['names'] = list(set(unified['names']))
        unified['emails'] = list(set(unified['emails']))
        unified['phones'] = list(set(unified['phones']))

        # Add metadata
        unified['metadata'] = {
            'platform_count': len(unified['platforms_present']),
            'has_verification': len(unified['verified_platforms']) > 0,
            'cross_platform_consistency': self._calculate_consistency(unified)
        }

        return unified

    def _extract_names(self, profile: Dict[str, Any], platform: str, unified: Dict[str, Any]):
        """Extract names from profile"""
        if platform in ['twitter', 'instagram', 'tiktok']:
            if 'display_name' in profile:
                unified['names'].append(profile['display_name'])
            if 'full_name' in profile:
                unified['names'].append(profile['full_name'])
            if 'name' in profile:
                unified['names'].append(profile['name'])
        elif platform == 'facebook':
            if 'name' in profile:
                unified['names'].append(profile['name'])
        elif platform == 'linkedin':
            first = profile.get('first_name', '')
            last = profile.get('last_name', '')
            if first or last:
                unified['names'].append(f"{first} {last}".strip())
        elif platform == 'discord':
            if 'global_name' in profile:
                unified['names'].append(profile['global_name'])

    def _extract_username(self, profile: Dict[str, Any], platform: str) -> str:
        """Extract username from profile"""
        return profile.get('username', profile.get('public_identifier', ''))

    def _extract_location(self, profile: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract location from profile"""
        location = profile.get('location')
        if isinstance(location, dict):
            # Complex location object
            parts = []
            if 'city' in location:
                parts.append(location['city'])
            if 'state' in location:
                parts.append(location['state'])
            if 'country' in location:
                parts.append(location['country'])
            return ', '.join(parts) if parts else None
        return location

    def _extract_bio(self, profile: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract bio/description from profile"""
        return (profile.get('bio') or
                profile.get('biography') or
                profile.get('description') or
                profile.get('summary'))

    def _extract_profile_picture(self, profile: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract profile picture URL"""
        return (profile.get('profile_picture_url') or
                profile.get('avatar_url') or
                profile.get('icon_img') or
                profile.get('photo_url'))

    def _extract_website(self, profile: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract website URL"""
        return (profile.get('url') or
                profile.get('website') or
                profile.get('external_url'))

    def _extract_followers(self, profile: Dict[str, Any], platform: str) -> int:
        """Extract follower count"""
        return (profile.get('followers_count') or
                profile.get('follower_count') or
                profile.get('connections_count') or
                0)

    def _extract_following(self, profile: Dict[str, Any], platform: str) -> int:
        """Extract following count"""
        return (profile.get('following_count') or
                profile.get('friends_count') or
                0)

    def _extract_post_count(self, data: Dict[str, Any], platform: str) -> int:
        """Extract post/content count"""
        posts = data.get('posts', [])
        tweets = data.get('tweets', [])
        videos = data.get('videos', [])
        return len(posts) + len(tweets) + len(videos)

    def _is_verified(self, profile: Dict[str, Any], platform: str) -> bool:
        """Check if account is verified"""
        return profile.get('verified', False) or profile.get('is_verified', False)

    def _extract_created_date(self, profile: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract account creation date"""
        return (profile.get('created_time') or
                profile.get('created_utc') or
                profile.get('created_at') or
                profile.get('joined_date'))

    def _calculate_consistency(self, unified: Dict[str, Any]) -> float:
        """
        Calculate cross-platform consistency score

        Returns:
            Consistency score from 0.0 to 1.0
        """
        score = 0.0
        checks = 0

        # Check name consistency
        if len(unified['names']) > 0:
            checks += 1
            if len(unified['names']) <= 2:  # Same name across platforms
                score += 0.25

        # Check location consistency
        unique_locations = len(set(loc['location'] for loc in unified['locations']))
        if unified['locations']:
            checks += 1
            if unique_locations <= 2:
                score += 0.25

        # Check bio similarity
        if len(unified['bios']) > 1:
            checks += 1
            # Simple check: do bios share common words?
            all_words = set()
            for bio_obj in unified['bios']:
                words = set(bio_obj['bio'].lower().split())
                if all_words:
                    overlap = len(all_words & words) / max(len(all_words), len(words))
                    if overlap > 0.3:
                        score += 0.25
                        break
                all_words.update(words)

        # Check profile picture consistency (would use image comparison in production)
        if len(unified['profile_pictures']) > 1:
            checks += 1
            # Placeholder - in production, use perceptual hashing
            score += 0.25

        return score / max(checks, 1) if checks > 0 else 0.0

    def map_relationships(self, platform_data: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Map relationships across platforms

        Args:
            platform_data: Dictionary of platform data

        Returns:
            Dictionary of relationship types and connections
        """
        self.logger.info("Mapping cross-platform relationships")

        relationships = {
            'followers': [],
            'following': [],
            'friends': [],
            'connections': [],
            'mutual_across_platforms': []
        }

        # Collect all relationships
        all_usernames = defaultdict(list)

        for platform, data in platform_data.items():
            if 'error' in data:
                continue

            # Collect followers
            followers = data.get('followers', [])
            for follower in followers:
                username = self._get_connection_username(follower, platform)
                if username:
                    all_usernames[username].append(platform)
                    relationships['followers'].append({
                        'username': username,
                        'platform': platform
                    })

            # Collect following
            following = data.get('following', [])
            for follow in following:
                username = self._get_connection_username(follow, platform)
                if username:
                    all_usernames[username].append(platform)
                    relationships['following'].append({
                        'username': username,
                        'platform': platform
                    })

            # Collect friends (Facebook)
            friends = data.get('friends', [])
            for friend in friends:
                username = self._get_connection_username(friend, platform)
                if username:
                    all_usernames[username].append(platform)
                    relationships['friends'].append({
                        'username': username,
                        'platform': platform
                    })

            # Collect connections (LinkedIn)
            connections = data.get('connections', [])
            for conn in connections:
                username = self._get_connection_username(conn, platform)
                if username:
                    all_usernames[username].append(platform)
                    relationships['connections'].append({
                        'username': username,
                        'platform': platform
                    })

        # Find mutual connections across platforms
        for username, platforms in all_usernames.items():
            if len(platforms) > 1:
                relationships['mutual_across_platforms'].append({
                    'username': username,
                    'platforms': list(set(platforms))
                })

        return relationships

    def _get_connection_username(self, connection: Dict[str, Any], platform: str) -> Optional[str]:
        """Extract username from connection object"""
        return (connection.get('username') or
                connection.get('name') or
                connection.get('public_identifier'))

    def build_timeline(self, platform_data: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build unified activity timeline across platforms

        Args:
            platform_data: Dictionary of platform data

        Returns:
            Sorted list of timeline events
        """
        self.logger.info("Building unified timeline")

        timeline = []

        for platform, data in platform_data.items():
            if 'error' in data:
                continue

            # Add posts to timeline
            posts = data.get('posts', [])
            for post in posts:
                event = {
                    'platform': platform,
                    'type': 'post',
                    'timestamp': self._extract_timestamp(post),
                    'content': self._extract_post_content(post),
                    'engagement': self._extract_engagement(post),
                    'data': post
                }
                timeline.append(event)

            # Add tweets to timeline
            tweets = data.get('tweets', [])
            for tweet in tweets:
                event = {
                    'platform': platform,
                    'type': 'tweet',
                    'timestamp': self._extract_timestamp(tweet),
                    'content': tweet.get('text', ''),
                    'engagement': self._extract_engagement(tweet),
                    'data': tweet
                }
                timeline.append(event)

            # Add videos to timeline
            videos = data.get('videos', [])
            for video in videos:
                event = {
                    'platform': platform,
                    'type': 'video',
                    'timestamp': self._extract_timestamp(video),
                    'content': video.get('description', ''),
                    'engagement': self._extract_engagement(video),
                    'data': video
                }
                timeline.append(event)

            # Add comments to timeline
            comments = data.get('comments', [])
            for comment in comments[:20]:  # Limit comments
                event = {
                    'platform': platform,
                    'type': 'comment',
                    'timestamp': self._extract_timestamp(comment),
                    'content': comment.get('body', comment.get('text', '')),
                    'engagement': self._extract_engagement(comment),
                    'data': comment
                }
                timeline.append(event)

        # Sort timeline by timestamp (most recent first)
        timeline.sort(key=lambda x: x['timestamp'], reverse=True)

        return timeline

    def _extract_timestamp(self, item: Dict[str, Any]) -> str:
        """Extract timestamp from item"""
        return (item.get('timestamp') or
                item.get('created_at') or
                item.get('created_time') or
                item.get('created_utc') or
                item.get('date') or
                datetime.utcnow().isoformat())

    def _extract_post_content(self, post: Dict[str, Any]) -> str:
        """Extract content from post"""
        return (post.get('text') or
                post.get('message') or
                post.get('caption') or
                post.get('title') or
                '')

    def _extract_engagement(self, item: Dict[str, Any]) -> Dict[str, int]:
        """Extract engagement metrics from item"""
        return {
            'likes': (item.get('likes') or
                     item.get('likes_count') or
                     item.get('like_count') or
                     item.get('score') or
                     0),
            'comments': (item.get('comments') or
                        item.get('comments_count') or
                        item.get('comment_count') or
                        item.get('num_comments') or
                        0),
            'shares': (item.get('shares') or
                      item.get('shares_count') or
                      item.get('share_count') or
                      item.get('retweets') or
                      item.get('forwards') or
                      0)
        }

    def find_connections(self,
                        profile1_data: Dict[str, Dict[str, Any]],
                        profile2_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Find connections between two users across platforms

        Args:
            profile1_data: First user's platform data
            profile2_data: Second user's platform data

        Returns:
            Connection analysis
        """
        self.logger.info("Finding connections between two users")

        connections = {
            'shared_platforms': [],
            'mutual_followers': [],
            'mutual_following': [],
            'interaction_evidence': [],
            'common_locations': [],
            'connection_score': 0.0
        }

        # Find shared platforms
        platforms1 = set(profile1_data.keys())
        platforms2 = set(profile2_data.keys())
        connections['shared_platforms'] = list(platforms1 & platforms2)

        # Analyze each shared platform
        for platform in connections['shared_platforms']:
            data1 = profile1_data[platform]
            data2 = profile2_data[platform]

            if 'error' in data1 or 'error' in data2:
                continue

            # Check if they follow each other
            username1 = data1.get('profile', {}).get('username')
            username2 = data2.get('profile', {}).get('username')

            # Check mutual followers
            followers1 = set(
                self._get_connection_username(f, platform)
                for f in data1.get('followers', [])
            )
            followers2 = set(
                self._get_connection_username(f, platform)
                for f in data2.get('followers', [])
            )
            mutual = followers1 & followers2
            if mutual:
                connections['mutual_followers'].extend([
                    {'username': u, 'platform': platform}
                    for u in mutual
                ])

            # Check locations
            loc1 = data1.get('profile', {}).get('location')
            loc2 = data2.get('profile', {}).get('location')
            if loc1 and loc2 and loc1 == loc2:
                connections['common_locations'].append({
                    'location': loc1,
                    'platform': platform
                })

        # Calculate connection score (0-100)
        score = 0.0
        score += len(connections['shared_platforms']) * 10
        score += len(connections['mutual_followers']) * 5
        score += len(connections['common_locations']) * 15
        connections['connection_score'] = min(score, 100)

        return connections

    def analyze_cross_platform_patterns(self, platform_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze behavioral patterns across platforms

        Args:
            platform_data: Dictionary of platform data

        Returns:
            Pattern analysis
        """
        self.logger.info("Analyzing cross-platform patterns")

        analysis = {
            'posting_consistency': {},
            'content_themes': [],
            'hashtag_usage': {},
            'time_patterns': {},
            'engagement_patterns': {}
        }

        # Aggregate all hashtags
        all_hashtags = defaultdict(int)

        # Analyze each platform
        for platform, data in platform_data.items():
            if 'error' in data:
                continue

            posts = data.get('posts', []) + data.get('tweets', [])

            # Collect hashtags
            for post in posts:
                hashtags = post.get('hashtags', [])
                for tag in hashtags:
                    all_hashtags[tag] += 1

        # Top hashtags across platforms
        analysis['hashtag_usage'] = dict(
            sorted(all_hashtags.items(), key=lambda x: x[1], reverse=True)[:20]
        )

        return analysis

    def export_unified_report(self, unified_data: Dict[str, Any], format: str = 'json') -> str:
        """
        Export unified intelligence report

        Args:
            unified_data: Unified profile data
            format: Export format

        Returns:
            Formatted report
        """
        if format == 'json':
            return json.dumps(unified_data, indent=2, default=str)
        elif format == 'text':
            return self._format_text_report(unified_data)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _format_text_report(self, data: Dict[str, Any]) -> str:
        """Format unified data as text report"""
        lines = [
            "=" * 60,
            "UNIFIED CROSS-PLATFORM INTELLIGENCE REPORT",
            "=" * 60,
            f"\nNames: {', '.join(data.get('names', []))}",
            f"Platforms: {', '.join(data.get('platforms_present', []))}",
            f"Total Followers: {data.get('total_followers', 0):,}",
            f"Total Posts: {data.get('total_posts', 0):,}",
            f"Verified: {data.get('verified_platforms', [])}",
            "=" * 60
        ]
        return '\n'.join(lines)


if __name__ == '__main__':
    # Example usage
    aggregator = PlatformAggregator()

    # Simulate platform data
    platform_data = {
        'twitter': {
            'profile': {
                'username': 'johndoe',
                'display_name': 'John Doe',
                'followers_count': 1000,
                'verified': True
            },
            'posts': []
        },
        'instagram': {
            'profile': {
                'username': 'johndoe',
                'full_name': 'John Doe',
                'followers_count': 2000
            },
            'posts': []
        }
    }

    # Unify profile
    unified = aggregator.unify_profile(platform_data)
    print(f"Unified profile created")
    print(f"Platforms: {unified['platforms_present']}")
    print(f"Total followers: {unified['total_followers']}")
