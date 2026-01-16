"""
Real-time Blockchain Monitoring Module

Monitor cryptocurrency addresses and wallets in real-time:
- Watch list management
- Transaction alerts
- Threshold-based notifications
- Webhook integrations
"""

from .monitor import BlockchainMonitor
from .alerting import AlertManager

__all__ = ["BlockchainMonitor", "AlertManager"]
