#!/usr/bin/env python3
"""
SOCMINT - Social Media Intelligence Collection System
Comprehensive multi-platform intelligence framework
"""

from .socmint_orchestrator import SOCMINT, TargetProfile
from .twitter_intel import TwitterIntel
from .facebook_intel import FacebookIntel
from .instagram_intel import InstagramIntel
from .linkedin_intel import LinkedInIntel
from .tiktok_intel import TikTokIntel
from .reddit_intel import RedditIntel
from .telegram_intel import TelegramIntel
from .discord_intel import DiscordIntel
from .platform_aggregator import PlatformAggregator

__version__ = '1.0.0'
__author__ = 'Apollo Intelligence Division'
__all__ = [
    'SOCMINT',
    'TargetProfile',
    'TwitterIntel',
    'FacebookIntel',
    'InstagramIntel',
    'LinkedInIntel',
    'TikTokIntel',
    'RedditIntel',
    'TelegramIntel',
    'DiscordIntel',
    'PlatformAggregator'
]
