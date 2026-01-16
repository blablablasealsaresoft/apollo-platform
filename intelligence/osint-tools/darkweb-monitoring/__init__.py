"""
Dark Web Monitoring System
Comprehensive intelligence gathering from dark web sources

Enhanced by Agent 5 with:
- Tor SOCKS proxy integration with circuit rotation
- Ahmia.fi dark web search API
- HaveIBeenPwned breach checking
- Paste site monitoring (Pastebin, GitHub Gist)
- FastAPI endpoints for all services
- TimescaleDB storage for time-series data
"""

__version__ = "2.0.0"
__author__ = "Agent 5, Agent 7"
__description__ = "Dark Web Intelligence and Monitoring System"

# Core monitoring
from .darkweb_monitor import DarkWebMonitor, MonitoringConfig, DarkWebResult
from .onion_crawler import OnionCrawler, OnionPage, CrawlConfig
from .marketplace_tracker import MarketplaceTracker, MarketplaceListing, Marketplace
from .forum_scraper import ForumScraper, ForumThread, ForumPost, ForumUser
from .paste_monitor import PasteMonitor, PasteResult
from .telegram_darkweb import TelegramDarkWeb, TelegramMessage, TelegramChannel
from .tor_proxy import TorProxy
from .darkweb_alerts import DarkWebAlerts, Alert

# Enhanced modules (Agent 5)
from .tor_proxy_enhanced import TorProxyEnhanced, CircuitInfo, TorHealthStatus
from .ahmia_search import AhmiaSearch, DarkWebSearchResult, MonitoringAlert
from .breach_checker import BreachChecker, BreachCheckResult, BreachInfo, CredentialLeak
from .paste_monitor_enhanced import PasteMonitorEnhanced, PasteRecord, PasteSeverity, PasteType
from .timescale_storage import DarkWebStorage

# API router
from .api_endpoints import router as darkweb_router

__all__ = [
    # Main Monitor
    'DarkWebMonitor',
    'MonitoringConfig',
    'DarkWebResult',

    # Crawler
    'OnionCrawler',
    'OnionPage',
    'CrawlConfig',

    # Marketplace
    'MarketplaceTracker',
    'MarketplaceListing',
    'Marketplace',

    # Forums
    'ForumScraper',
    'ForumThread',
    'ForumPost',
    'ForumUser',

    # Paste Sites
    'PasteMonitor',
    'PasteResult',
    'PasteMonitorEnhanced',
    'PasteRecord',
    'PasteSeverity',
    'PasteType',

    # Telegram
    'TelegramDarkWeb',
    'TelegramMessage',
    'TelegramChannel',

    # Tor Proxy
    'TorProxy',
    'TorProxyEnhanced',
    'CircuitInfo',
    'TorHealthStatus',

    # Dark Web Search
    'AhmiaSearch',
    'DarkWebSearchResult',
    'MonitoringAlert',

    # Breach Checking
    'BreachChecker',
    'BreachCheckResult',
    'BreachInfo',
    'CredentialLeak',

    # Storage
    'DarkWebStorage',

    # Alerts
    'DarkWebAlerts',
    'Alert',

    # API Router
    'darkweb_router'
]
