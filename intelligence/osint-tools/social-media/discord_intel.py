#!/usr/bin/env python3
"""
Discord Intelligence Collection
Server discovery, message scraping, user tracking, and relationship mapping
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import hashlib


@dataclass
class DiscordMessage:
    """Discord message data structure"""
    id: str
    content: str
    author: str
    timestamp: str
    channel_id: str
    guild_id: str
    attachments: List[str]
    reactions: Dict[str, int]


class DiscordIntel:
    """
    Discord Intelligence Collector
    Collects server data, messages, user activity, and relationships
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Discord intelligence collector"""
        self.config = config or {}
        self.logger = logging.getLogger('DiscordIntel')

        # Bot/User token configuration
        self.bot_token = config.get('bot_token')
        self.user_token = config.get('user_token')

        # Collection limits
        self.max_messages = config.get('max_messages', 1000)

        self.logger.info("Discord Intelligence initialized")

    def collect_profile(self, identifier: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Collect Discord user profile data

        Args:
            identifier: User ID or username#discriminator
            deep_scan: Enable deep scanning

        Returns:
            Dictionary containing user intelligence
        """
        self.logger.info(f"Collecting Discord profile: {identifier}")

        profile_data = {
            'platform': 'discord',
            'identifier': identifier,
            'profile': self._get_user_info(identifier),
            'mutual_guilds': [],
            'mutual_friends': [],
            'activity': [],
            'messages': [],
            'metrics': {},
            'relationship_map': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        if deep_scan:
            profile_data['mutual_guilds'] = self._get_mutual_guilds(identifier)
            profile_data['activity'] = self._get_user_activity(identifier)
            profile_data['relationship_map'] = self._map_relationships(identifier)

        # Calculate metrics
        profile_data['metrics'] = self._calculate_metrics(profile_data)

        return profile_data

    def _get_user_info(self, identifier: str) -> Dict[str, Any]:
        """Get Discord user information"""
        # Simulate Discord API call
        user_info = {
            'id': hashlib.md5(identifier.encode()).hexdigest()[:18],
            'username': identifier.split('#')[0] if '#' in identifier else identifier,
            'discriminator': identifier.split('#')[1] if '#' in identifier else '0001',
            'global_name': f"User {identifier}",
            'avatar': hashlib.md5(f"{identifier}_avatar".encode()).hexdigest(),
            'avatar_url': f"https://cdn.discordapp.com/avatars/{identifier}/avatar.png",
            'banner': None,
            'banner_color': '#5865F2',
            'accent_color': 5793266,
            'bot': False,
            'system': False,
            'verified': True,
            'email': None,  # Privacy protected
            'flags': 0,
            'premium_type': 0,  # 0: None, 1: Nitro Classic, 2: Nitro
            'public_flags': 0,
            'created_at': (datetime.utcnow() - timedelta(days=730)).isoformat()
        }

        return user_info

    def _get_mutual_guilds(self, identifier: str) -> List[Dict[str, Any]]:
        """Get mutual Discord servers"""
        guilds = []

        for i in range(5):
            guild = {
                'id': hashlib.md5(f"guild_{i}".encode()).hexdigest()[:18],
                'name': f"Server {i}",
                'icon': hashlib.md5(f"icon_{i}".encode()).hexdigest(),
                'owner': False,
                'permissions': '2147483647',
                'features': ['COMMUNITY', 'NEWS']
            }
            guilds.append(guild)

        return guilds

    def _get_user_activity(self, identifier: str) -> List[Dict[str, Any]]:
        """Get recent user activity"""
        activity = []

        for i in range(10):
            event = {
                'type': 'message',
                'guild_id': hashlib.md5(f"guild_{i % 3}".encode()).hexdigest()[:18],
                'channel_id': hashlib.md5(f"channel_{i}".encode()).hexdigest()[:18],
                'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'action': 'sent_message'
            }
            activity.append(event)

        return activity

    def _map_relationships(self, identifier: str) -> Dict[str, Any]:
        """Map user relationships"""
        relationships = {
            'friends': [],
            'blocked': [],
            'incoming_requests': [],
            'outgoing_requests': []
        }

        # Simulate friend list
        for i in range(10):
            friend = {
                'id': hashlib.md5(f"friend_{i}".encode()).hexdigest()[:18],
                'username': f"Friend{i}",
                'discriminator': f"{1000+i}",
                'type': 1  # 1: Friend
            }
            relationships['friends'].append(friend)

        return relationships

    def scrape_server(self, guild_id: str) -> Dict[str, Any]:
        """
        Scrape Discord server/guild information

        Args:
            guild_id: Guild/Server ID

        Returns:
            Server intelligence data
        """
        self.logger.info(f"Scraping Discord server: {guild_id}")

        server_data = {
            'guild_id': guild_id,
            'info': self._get_guild_info(guild_id),
            'channels': self._get_guild_channels(guild_id),
            'members': self._get_guild_members(guild_id),
            'roles': self._get_guild_roles(guild_id),
            'emojis': [],
            'messages': [],
            'metrics': {},
            'activity_analysis': {},
            'collection_timestamp': datetime.utcnow().isoformat()
        }

        # Collect messages from channels
        for channel in server_data['channels']:
            if channel['type'] == 0:  # Text channel
                messages = self._collect_messages(channel['id'], limit=100)
                server_data['messages'].extend(messages)

        # Analyze activity
        server_data['activity_analysis'] = self._analyze_server_activity(server_data)

        # Calculate metrics
        server_data['metrics'] = self._calculate_server_metrics(server_data)

        return server_data

    def _get_guild_info(self, guild_id: str) -> Dict[str, Any]:
        """Get guild/server information"""
        info = {
            'id': guild_id,
            'name': f"Server {guild_id}",
            'icon': hashlib.md5(f"{guild_id}_icon".encode()).hexdigest(),
            'icon_url': f"https://cdn.discordapp.com/icons/{guild_id}/icon.png",
            'splash': None,
            'discovery_splash': None,
            'owner_id': hashlib.md5('owner'.encode()).hexdigest()[:18],
            'region': 'us-west',
            'afk_channel_id': None,
            'afk_timeout': 300,
            'verification_level': 2,
            'default_message_notifications': 0,
            'explicit_content_filter': 2,
            'features': ['COMMUNITY', 'NEWS', 'DISCOVERABLE'],
            'mfa_level': 1,
            'premium_tier': 2,
            'premium_subscription_count': 14,
            'description': f"Discord server {guild_id}",
            'banner': None,
            'vanity_url_code': None,
            'member_count': 1000,
            'presence_count': 100,
            'max_members': 500000
        }

        return info

    def _get_guild_channels(self, guild_id: str) -> List[Dict[str, Any]]:
        """Get guild channels"""
        channels = []

        # Text channels
        for i in range(5):
            channel = {
                'id': hashlib.md5(f"{guild_id}_channel_{i}".encode()).hexdigest()[:18],
                'type': 0,  # 0: Text, 2: Voice, 4: Category
                'name': f"channel-{i}",
                'position': i,
                'topic': f"Channel {i} topic",
                'nsfw': False,
                'parent_id': None,
                'permission_overwrites': []
            }
            channels.append(channel)

        # Voice channels
        for i in range(3):
            channel = {
                'id': hashlib.md5(f"{guild_id}_voice_{i}".encode()).hexdigest()[:18],
                'type': 2,
                'name': f"Voice {i}",
                'position': i + 5,
                'bitrate': 64000,
                'user_limit': 0,
                'parent_id': None
            }
            channels.append(channel)

        return channels

    def _get_guild_members(self, guild_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get guild members"""
        members = []

        for i in range(min(limit, 20)):
            member = {
                'user': {
                    'id': hashlib.md5(f"member_{i}".encode()).hexdigest()[:18],
                    'username': f"Member{i}",
                    'discriminator': f"{1000+i}",
                    'avatar': hashlib.md5(f"avatar_{i}".encode()).hexdigest(),
                    'bot': False
                },
                'nick': f"Nickname{i}" if i % 3 == 0 else None,
                'roles': [hashlib.md5(f"role_{i % 3}".encode()).hexdigest()[:18]],
                'joined_at': (datetime.utcnow() - timedelta(days=i*10)).isoformat(),
                'premium_since': None,
                'deaf': False,
                'mute': False,
                'pending': False,
                'permissions': '2147483647'
            }
            members.append(member)

        return members

    def _get_guild_roles(self, guild_id: str) -> List[Dict[str, Any]]:
        """Get guild roles"""
        roles = [
            {
                'id': hashlib.md5(f"{guild_id}_role_admin".encode()).hexdigest()[:18],
                'name': 'Admin',
                'color': 15158332,
                'hoist': True,
                'position': 3,
                'permissions': '8',
                'managed': False,
                'mentionable': False
            },
            {
                'id': hashlib.md5(f"{guild_id}_role_mod".encode()).hexdigest()[:18],
                'name': 'Moderator',
                'color': 3447003,
                'hoist': True,
                'position': 2,
                'permissions': '1543892055',
                'managed': False,
                'mentionable': True
            },
            {
                'id': hashlib.md5(f"{guild_id}_role_member".encode()).hexdigest()[:18],
                'name': 'Member',
                'color': 0,
                'hoist': False,
                'position': 1,
                'permissions': '104324161',
                'managed': False,
                'mentionable': False
            }
        ]

        return roles

    def _collect_messages(self, channel_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Collect messages from channel"""
        self.logger.info(f"Collecting messages from channel: {channel_id}")

        messages = []

        for i in range(min(limit, 50)):
            message = {
                'id': hashlib.md5(f"{channel_id}_msg_{i}".encode()).hexdigest()[:18],
                'channel_id': channel_id,
                'author': {
                    'id': hashlib.md5(f"user_{i % 10}".encode()).hexdigest()[:18],
                    'username': f"User{i % 10}",
                    'discriminator': f"{1000 + (i % 10)}"
                },
                'content': f"Message content {i}",
                'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                'edited_timestamp': None,
                'tts': False,
                'mention_everyone': False,
                'mentions': [],
                'mention_roles': [],
                'attachments': [],
                'embeds': [],
                'reactions': [],
                'pinned': False,
                'type': 0  # 0: Default message
            }
            messages.append(message)

        return messages

    def _analyze_server_activity(self, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze server activity patterns"""
        messages = server_data.get('messages', [])

        analysis = {
            'message_frequency': {},
            'active_users': {},
            'peak_hours': {},
            'channel_activity': {},
            'user_engagement': {}
        }

        # Analyze message frequency
        if messages:
            date_range = (
                datetime.utcnow() -
                datetime.fromisoformat(messages[-1]['timestamp'].replace('Z', '+00:00'))
            ).days
            if date_range > 0:
                analysis['message_frequency'] = {
                    'messages_per_day': len(messages) / date_range,
                    'total_days': date_range
                }

        # Count active users
        user_message_count = {}
        for message in messages:
            user_id = message['author']['id']
            user_message_count[user_id] = user_message_count.get(user_id, 0) + 1

        analysis['active_users'] = sorted(
            user_message_count.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Analyze posting times
        for message in messages:
            timestamp = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
            hour = timestamp.hour
            analysis['peak_hours'][hour] = analysis['peak_hours'].get(hour, 0) + 1

        return analysis

    def _calculate_server_metrics(self, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate server metrics"""
        info = server_data.get('info', {})
        members = server_data.get('members', [])
        messages = server_data.get('messages', [])

        metrics = {
            'total_members': len(members),
            'online_members': info.get('presence_count', 0),
            'total_channels': len(server_data.get('channels', [])),
            'total_messages_collected': len(messages),
            'activity_score': 0.0,
            'engagement_rate': 0.0
        }

        # Calculate activity score (0-100)
        member_score = min(metrics['total_members'] / 10000, 1.0) * 40
        message_score = min(metrics['total_messages_collected'] / 1000, 1.0) * 30
        online_ratio = metrics['online_members'] / max(metrics['total_members'], 1)
        online_score = online_ratio * 30
        metrics['activity_score'] = member_score + message_score + online_score

        # Calculate engagement rate
        if metrics['total_members'] > 0 and messages:
            active_users = len(set(m['author']['id'] for m in messages))
            metrics['engagement_rate'] = (active_users / metrics['total_members']) * 100

        return metrics

    def _calculate_metrics(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate user metrics"""
        metrics = {
            'mutual_guilds': len(profile_data.get('mutual_guilds', [])),
            'friends': len(profile_data.get('relationship_map', {}).get('friends', [])),
            'recent_activity': len(profile_data.get('activity', [])),
            'activity_score': 0.0
        }

        # Calculate activity score
        guild_score = min(metrics['mutual_guilds'] / 10, 1.0) * 40
        friend_score = min(metrics['friends'] / 50, 1.0) * 30
        activity_score = min(metrics['recent_activity'] / 100, 1.0) * 30
        metrics['activity_score'] = guild_score + friend_score + activity_score

        return metrics

    def search_servers(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Search for Discord servers

        Args:
            keyword: Search keyword

        Returns:
            List of matching servers
        """
        self.logger.info(f"Searching servers: {keyword}")

        results = []

        for i in range(10):
            server = {
                'id': hashlib.md5(f"{keyword}_server_{i}".encode()).hexdigest()[:18],
                'name': f"{keyword} Server {i}",
                'description': f"Server about {keyword}",
                'member_count': (10-i) * 1000,
                'online_count': (10-i) * 100,
                'icon_url': f"https://cdn.discordapp.com/icons/{i}/icon.png",
                'features': ['COMMUNITY', 'DISCOVERABLE']
            }
            results.append(server)

        return results

    def check_exists(self, identifier: str) -> bool:
        """Check if Discord user exists"""
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
    discord = DiscordIntel()

    # Scrape server
    server = discord.scrape_server("123456789")
    print(f"Server: {server['info']['name']}")
    print(f"Members: {server['metrics']['total_members']}")
    print(f"Messages collected: {server['metrics']['total_messages_collected']}")
    print(f"Activity Score: {server['metrics']['activity_score']:.2f}")

    # Collect user profile
    profile = discord.collect_profile("user#1234", deep_scan=True)
    print(f"\nUser: {profile['profile']['username']}")
    print(f"Mutual Servers: {profile['metrics']['mutual_guilds']}")
