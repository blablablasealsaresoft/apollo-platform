#!/usr/bin/env python3
"""
Reddit Intelligence Collection
User history extraction, subreddit tracking, comment analysis, and post pattern analysis
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import hashlib


@dataclass
class RedditPost:
    """Reddit post data structure"""
    id: str
    title: str
    text: str
    author: str
    subreddit: str
    timestamp: str
    score: int
    upvote_ratio: float
    comments: int
    awards: List[str]
    url: str


class RedditIntel:
    """
    Reddit Intelligence Collector
    Collects user activity, subreddit data, and performs behavioral analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Reddit intelligence collector"""
        self.config = config or {}
        self.logger = logging.getLogger('RedditIntel')

        # API configuration
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.user_agent = config.get('user_agent', 'SOCMINT/1.0')

        # Collection limits
        self.max_posts = config.get('max_posts', 100)
        self.max_comments = config.get('max_comments', 500)

        self.logger.info("Reddit Intelligence initialized")

    def collect_profile(self, username: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Collect comprehensive Reddit user data

        Args:
            username: Reddit username (without u/)
            deep_scan: Enable deep scanning with behavioral analysis

        Returns:
            Dictionary containing user intelligence
        """
        self.logger.info(f"Collecting Reddit profile: u/{username}")

        profile_data = {
            'platform': 'reddit',
            'username': username,
            'profile': self._get_profile_info(username),
            'posts': self._collect_posts(username),
            'comments': self._collect_comments(username),
            'subreddits': self._get_active_subreddits(username),
            'metrics': {},
            'behavioral_analysis': {},
            'content_analysis': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        if deep_scan:
            profile_data['behavioral_analysis'] = self._analyze_behavior(profile_data)
            profile_data['content_analysis'] = self._analyze_content(profile_data)

        # Calculate metrics
        profile_data['metrics'] = self._calculate_metrics(profile_data)

        return profile_data

    def _get_profile_info(self, username: str) -> Dict[str, Any]:
        """Get Reddit user profile information"""
        # Simulate Reddit API call
        profile = {
            'id': hashlib.md5(username.encode()).hexdigest()[:10],
            'username': username,
            'created_utc': (datetime.utcnow() - timedelta(days=730)).isoformat(),
            'link_karma': 0,
            'comment_karma': 0,
            'total_karma': 0,
            'is_gold': False,
            'is_mod': False,
            'has_verified_email': True,
            'icon_img': f"https://reddit.com/user/{username}/icon.png",
            'subreddit': {  # User's profile subreddit
                'display_name': f"u_{username}",
                'subscribers': 0
            }
        }

        return profile

    def _collect_posts(self, username: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Collect user's Reddit posts"""
        if limit is None:
            limit = self.max_posts

        self.logger.info(f"Collecting up to {limit} posts from u/{username}")

        posts = []

        for i in range(min(limit, 20)):
            post = {
                'id': hashlib.md5(f"{username}_post_{i}".encode()).hexdigest()[:8],
                'title': f"Sample Reddit post title {i}",
                'selftext': f"Post content {i}",
                'subreddit': f"subreddit_{i % 5}",
                'author': username,
                'created_utc': (datetime.utcnow() - timedelta(days=i*5)).isoformat(),
                'score': i * 100,
                'upvote_ratio': 0.85 + (i % 10) * 0.01,
                'num_comments': i * 10,
                'awards': [],
                'permalink': f"/r/subreddit_{i % 5}/comments/{i}/post_title/",
                'url': f"https://reddit.com/r/subreddit_{i % 5}/comments/{i}/",
                'is_self': True,
                'link_flair_text': None,
                'over_18': False,
                'spoiler': False,
                'locked': False,
                'stickied': False
            }
            posts.append(post)

        return posts

    def _collect_comments(self, username: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Collect user's Reddit comments"""
        if limit is None:
            limit = self.max_comments

        self.logger.info(f"Collecting up to {limit} comments from u/{username}")

        comments = []

        for i in range(min(limit, 50)):
            comment = {
                'id': hashlib.md5(f"{username}_comment_{i}".encode()).hexdigest()[:8],
                'body': f"Sample comment text {i}",
                'subreddit': f"subreddit_{i % 5}",
                'author': username,
                'created_utc': (datetime.utcnow() - timedelta(hours=i*6)).isoformat(),
                'score': i * 5,
                'controversiality': 0,
                'awards': [],
                'permalink': f"/r/subreddit_{i % 5}/comments/post/comment/{i}/",
                'parent_id': f"t3_{hashlib.md5(f'parent{i}'.encode()).hexdigest()[:8]}",
                'link_id': f"t3_{hashlib.md5(f'link{i}'.encode()).hexdigest()[:8]}"
            }
            comments.append(comment)

        return comments

    def _get_active_subreddits(self, username: str) -> List[Dict[str, Any]]:
        """Get subreddits where user is active"""
        self.logger.info(f"Analyzing active subreddits for u/{username}")

        # Count activity per subreddit
        subreddit_activity = {}

        # This would be derived from actual posts/comments
        subreddits = [
            {
                'name': f"subreddit_{i}",
                'display_name': f"Subreddit {i}",
                'post_count': 10 - i,
                'comment_count': 50 - (i*5),
                'total_karma': (60 - (i*6)) * 10,
                'subscribers': (100 - i) * 1000,
                'is_moderator': (i == 0)
            }
            for i in range(5)
        ]

        return subreddits

    def _analyze_behavior(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user behavioral patterns"""
        self.logger.info("Analyzing behavioral patterns")

        posts = profile_data.get('posts', [])
        comments = profile_data.get('comments', [])

        behavior = {
            'posting_times': {},
            'activity_days': {},
            'posting_frequency': {},
            'engagement_patterns': {},
            'subreddit_focus': {},
            'content_preferences': {}
        }

        # Analyze posting times
        for post in posts:
            timestamp = datetime.fromisoformat(post['created_utc'].replace('Z', '+00:00'))
            hour = timestamp.hour
            day = timestamp.strftime('%A')

            behavior['posting_times'][hour] = behavior['posting_times'].get(hour, 0) + 1
            behavior['activity_days'][day] = behavior['activity_days'].get(day, 0) + 1

        # Calculate posting frequency
        if posts:
            date_range = (
                datetime.utcnow() -
                datetime.fromisoformat(posts[-1]['created_utc'].replace('Z', '+00:00'))
            ).days
            if date_range > 0:
                behavior['posting_frequency'] = {
                    'posts_per_day': len(posts) / date_range,
                    'comments_per_day': len(comments) / date_range
                }

        # Engagement patterns
        if posts:
            behavior['engagement_patterns'] = {
                'avg_post_score': sum(p['score'] for p in posts) / len(posts),
                'avg_comments_per_post': sum(p['num_comments'] for p in posts) / len(posts),
                'controversial_ratio': sum(
                    1 for p in posts if p.get('upvote_ratio', 1.0) < 0.6
                ) / len(posts)
            }

        return behavior

    def _analyze_content(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content patterns"""
        posts = profile_data.get('posts', [])
        comments = profile_data.get('comments', [])

        analysis = {
            'word_frequency': {},
            'sentiment_distribution': {},
            'topic_categories': {},
            'language_style': {},
            'toxicity_indicators': {}
        }

        # Simple sentiment analysis
        positive_count = 0
        negative_count = 0
        neutral_count = 0

        for post in posts:
            text = (post.get('title', '') + ' ' + post.get('selftext', '')).lower()
            if any(word in text for word in ['good', 'great', 'awesome', 'love']):
                positive_count += 1
            elif any(word in text for word in ['bad', 'hate', 'terrible', 'awful']):
                negative_count += 1
            else:
                neutral_count += 1

        total = len(posts) if posts else 1
        analysis['sentiment_distribution'] = {
            'positive': positive_count / total,
            'negative': negative_count / total,
            'neutral': neutral_count / total
        }

        return analysis

    def _calculate_metrics(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate user metrics"""
        profile = profile_data.get('profile', {})
        posts = profile_data.get('posts', [])
        comments = profile_data.get('comments', [])

        metrics = {
            'total_posts': len(posts),
            'total_comments': len(comments),
            'link_karma': profile.get('link_karma', 0),
            'comment_karma': profile.get('comment_karma', 0),
            'total_karma': profile.get('total_karma', 0),
            'account_age_days': 0,
            'avg_post_score': 0.0,
            'avg_comment_score': 0.0,
            'activity_score': 0.0
        }

        # Calculate account age
        created = datetime.fromisoformat(profile['created_utc'].replace('Z', '+00:00'))
        metrics['account_age_days'] = (datetime.utcnow() - created).days

        # Calculate averages
        if posts:
            metrics['avg_post_score'] = sum(p['score'] for p in posts) / len(posts)
        if comments:
            metrics['avg_comment_score'] = sum(c['score'] for c in comments) / len(comments)

        # Calculate activity score (0-100)
        karma_score = min(metrics['total_karma'] / 10000, 1.0) * 40
        post_score = min(metrics['total_posts'] / 100, 1.0) * 30
        comment_score = min(metrics['total_comments'] / 500, 1.0) * 30
        metrics['activity_score'] = karma_score + post_score + comment_score

        return metrics

    def track_subreddit(self, subreddit: str, limit: int = 100) -> Dict[str, Any]:
        """
        Track subreddit activity and posts

        Args:
            subreddit: Subreddit name (without r/)
            limit: Maximum posts to collect

        Returns:
            Subreddit intelligence data
        """
        self.logger.info(f"Tracking subreddit: r/{subreddit}")

        results = {
            'subreddit': subreddit,
            'info': self._get_subreddit_info(subreddit),
            'hot_posts': [],
            'new_posts': [],
            'top_posts': [],
            'moderators': [],
            'metrics': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Collect posts
        for i in range(min(limit, 25)):
            post = {
                'id': hashlib.md5(f"{subreddit}_post_{i}".encode()).hexdigest()[:8],
                'title': f"Post {i} in r/{subreddit}",
                'author': f"user_{i}",
                'score': (25-i) * 100,
                'num_comments': (25-i) * 10,
                'created_utc': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'url': f"https://reddit.com/r/{subreddit}/comments/{i}/"
            }
            results['hot_posts'].append(post)

        # Calculate metrics
        results['metrics'] = {
            'total_posts_collected': len(results['hot_posts']),
            'avg_score': sum(p['score'] for p in results['hot_posts']) / len(results['hot_posts']),
            'avg_comments': sum(p['num_comments'] for p in results['hot_posts']) / len(results['hot_posts'])
        }

        return results

    def _get_subreddit_info(self, subreddit: str) -> Dict[str, Any]:
        """Get subreddit information"""
        info = {
            'display_name': subreddit,
            'title': f"The {subreddit} Community",
            'description': f"Community for discussing {subreddit}",
            'subscribers': 100000,
            'active_users': 5000,
            'created_utc': (datetime.utcnow() - timedelta(days=1825)).isoformat(),
            'public_description': f"Welcome to r/{subreddit}",
            'over18': False,
            'icon_img': f"https://reddit.com/r/{subreddit}/icon.png",
            'community_icon': None
        }
        return info

    def search_posts(self, query: str, subreddit: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search Reddit posts

        Args:
            query: Search query
            subreddit: Optional subreddit to search within

        Returns:
            List of matching posts
        """
        self.logger.info(f"Searching posts: {query}")

        results = []

        for i in range(20):
            post = {
                'id': hashlib.md5(f"{query}_result_{i}".encode()).hexdigest()[:8],
                'title': f"{query} - Result {i}",
                'subreddit': subreddit or f"subreddit_{i % 5}",
                'author': f"user_{i}",
                'score': (20-i) * 50,
                'created_utc': (datetime.utcnow() - timedelta(days=i)).isoformat(),
                'url': f"https://reddit.com/r/subreddit/comments/{i}/"
            }
            results.append(post)

        return results

    def check_exists(self, username: str) -> bool:
        """Check if Reddit user exists"""
        # Simulate user check
        return True

    def export_data(self, data: Dict[str, Any], format: str = 'json') -> str:
        """Export collected data"""
        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")


if __name__ == '__main__':
    # Example usage
    reddit = RedditIntel()

    # Collect profile
    profile = reddit.collect_profile("target_user", deep_scan=True)
    print(f"Collected profile: u/{profile['username']}")
    print(f"Posts: {len(profile['posts'])}")
    print(f"Comments: {len(profile['comments'])}")
    print(f"Karma: {profile['metrics']['total_karma']}")
    print(f"Activity Score: {profile['metrics']['activity_score']:.2f}")

    # Track subreddit
    subreddit_data = reddit.track_subreddit("cybersecurity")
    print(f"\nSubreddit r/{subreddit_data['subreddit']}")
    print(f"Subscribers: {subreddit_data['info']['subscribers']:,}")
