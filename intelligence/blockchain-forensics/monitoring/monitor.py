"""
Blockchain Monitor

Real-time monitoring of cryptocurrency addresses
"""

import asyncio
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class WatchedAddress:
    """Address being monitored"""

    address: str
    blockchain: str
    added_at: datetime
    tags: List[str] = field(default_factory=list)
    alert_threshold_usd: float = 10000.0  # Alert on transactions > this amount
    last_checked: Optional[datetime] = None
    last_transaction: Optional[str] = None


@dataclass
class TransactionAlert:
    """Alert for a monitored transaction"""

    alert_id: str
    address: str
    blockchain: str
    txid: str
    amount: float
    amount_usd: float
    from_address: str
    to_address: str
    timestamp: datetime
    alert_type: str  # threshold, mixer, exchange, etc.
    severity: str  # low, medium, high, critical


class BlockchainMonitor:
    """
    Real-time blockchain monitoring system

    Features:
    - Watch list management
    - Continuous transaction monitoring
    - Threshold-based alerts
    - Pattern detection
    - Webhook notifications
    """

    def __init__(self, db_manager, api_manager, alert_manager, config):
        self.db = db_manager
        self.api = api_manager
        self.alerts = alert_manager
        self.config = config

        # Watch list
        self.watched_addresses: Dict[str, WatchedAddress] = {}

        # Monitoring state
        self.is_monitoring = False
        self.monitor_task: Optional[asyncio.Task] = None

        # Alert callbacks
        self.alert_callbacks: List[Callable] = []

        logger.info("Blockchain Monitor initialized")

    async def start_monitoring(self, interval_seconds: int = 60):
        """
        Start continuous monitoring

        Args:
            interval_seconds: How often to check for new transactions
        """
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return

        self.is_monitoring = True
        self.monitor_task = asyncio.create_task(
            self._monitoring_loop(interval_seconds)
        )

        logger.info(f"Started monitoring with {interval_seconds}s interval")

    async def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_monitoring = False

        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        logger.info("Stopped monitoring")

    async def add_address(
        self,
        address: str,
        blockchain: str = "btc",
        tags: Optional[List[str]] = None,
        alert_threshold_usd: float = 10000.0
    ):
        """
        Add an address to the watch list

        Args:
            address: Address to monitor
            blockchain: Blockchain type
            tags: Optional tags (e.g., "onecoin", "ruja", "suspect")
            alert_threshold_usd: Alert on transactions above this amount
        """
        if address in self.watched_addresses:
            logger.warning(f"Address {address} already being monitored")
            return

        watched = WatchedAddress(
            address=address,
            blockchain=blockchain,
            added_at=datetime.utcnow(),
            tags=tags or [],
            alert_threshold_usd=alert_threshold_usd,
        )

        self.watched_addresses[address] = watched

        # Store in database
        if self.db:
            await self.db.add_watched_address(watched)

        logger.info(
            f"Added {address} to watch list (threshold: ${alert_threshold_usd:,.2f})"
        )

    async def remove_address(self, address: str):
        """Remove an address from the watch list"""
        if address not in self.watched_addresses:
            logger.warning(f"Address {address} not in watch list")
            return

        del self.watched_addresses[address]

        if self.db:
            await self.db.remove_watched_address(address)

        logger.info(f"Removed {address} from watch list")

    async def get_watch_list(self) -> List[WatchedAddress]:
        """Get all watched addresses"""
        return list(self.watched_addresses.values())

    async def check_address(self, address: str) -> List[TransactionAlert]:
        """
        Check an address for new transactions

        Returns list of alerts
        """
        if address not in self.watched_addresses:
            return []

        watched = self.watched_addresses[address]
        alerts = []

        try:
            # Get recent transactions
            transactions = await self.api.get_address_transactions(
                address,
                watched.blockchain,
                limit=50
            )

            # Filter for new transactions
            new_transactions = []
            for tx in transactions:
                if watched.last_transaction:
                    if tx["txid"] == watched.last_transaction:
                        break  # Found the last known transaction
                new_transactions.append(tx)

            # Analyze new transactions
            for tx in new_transactions:
                # Check threshold
                if tx.get("amount_usd", 0) >= watched.alert_threshold_usd:
                    alert = TransactionAlert(
                        alert_id=f"{address}_{tx['txid']}",
                        address=address,
                        blockchain=watched.blockchain,
                        txid=tx["txid"],
                        amount=tx.get("amount", 0),
                        amount_usd=tx.get("amount_usd", 0),
                        from_address=tx["from_address"],
                        to_address=tx["to_address"],
                        timestamp=tx["timestamp"],
                        alert_type="threshold",
                        severity=self._calculate_severity(tx, watched),
                    )
                    alerts.append(alert)

                # Check for mixer usage
                if await self._is_mixer_transaction(tx):
                    alert = TransactionAlert(
                        alert_id=f"{address}_{tx['txid']}_mixer",
                        address=address,
                        blockchain=watched.blockchain,
                        txid=tx["txid"],
                        amount=tx.get("amount", 0),
                        amount_usd=tx.get("amount_usd", 0),
                        from_address=tx["from_address"],
                        to_address=tx["to_address"],
                        timestamp=tx["timestamp"],
                        alert_type="mixer",
                        severity="high",
                    )
                    alerts.append(alert)

                # Check for exchange deposit
                if await self._is_exchange_transaction(tx):
                    alert = TransactionAlert(
                        alert_id=f"{address}_{tx['txid']}_exchange",
                        address=address,
                        blockchain=watched.blockchain,
                        txid=tx["txid"],
                        amount=tx.get("amount", 0),
                        amount_usd=tx.get("amount_usd", 0),
                        from_address=tx["from_address"],
                        to_address=tx["to_address"],
                        timestamp=tx["timestamp"],
                        alert_type="exchange",
                        severity="medium",
                    )
                    alerts.append(alert)

            # Update last checked
            watched.last_checked = datetime.utcnow()
            if new_transactions:
                watched.last_transaction = new_transactions[0]["txid"]

            # Send alerts
            for alert in alerts:
                await self._send_alert(alert)

            return alerts

        except Exception as e:
            logger.error(f"Error checking address {address}: {e}")
            return []

    def register_alert_callback(self, callback: Callable):
        """
        Register a callback function to be called when alerts are triggered

        Callback signature: async def callback(alert: TransactionAlert)
        """
        self.alert_callbacks.append(callback)

    async def _monitoring_loop(self, interval_seconds: int):
        """Main monitoring loop"""
        logger.info("Starting monitoring loop")

        while self.is_monitoring:
            try:
                # Check all watched addresses
                tasks = [
                    self.check_address(addr)
                    for addr in self.watched_addresses.keys()
                ]

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    total_alerts = sum(
                        len(r) for r in results
                        if not isinstance(r, Exception)
                    )

                    if total_alerts > 0:
                        logger.info(f"Generated {total_alerts} alerts")

                # Wait before next check
                await asyncio.sleep(interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(interval_seconds)

        logger.info("Monitoring loop stopped")

    async def _send_alert(self, alert: TransactionAlert):
        """Send an alert through all configured channels"""
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

        # Send via alert manager
        if self.alerts:
            await self.alerts.send_alert(alert)

        # Store in database
        if self.db:
            await self.db.store_alert(alert)

        logger.info(
            f"Alert: {alert.alert_type} for {alert.address} - "
            f"${alert.amount_usd:,.2f} ({alert.severity})"
        )

    def _calculate_severity(
        self,
        transaction: Dict,
        watched: WatchedAddress
    ) -> str:
        """Calculate alert severity"""
        amount_usd = transaction.get("amount_usd", 0)

        if amount_usd >= watched.alert_threshold_usd * 10:
            return "critical"
        elif amount_usd >= watched.alert_threshold_usd * 5:
            return "high"
        elif amount_usd >= watched.alert_threshold_usd:
            return "medium"
        else:
            return "low"

    async def _is_mixer_transaction(self, transaction: Dict) -> bool:
        """Check if transaction involves a mixer"""
        from ..config import KNOWN_MIXERS

        mixer_addresses = set()
        for mixer_type, addresses in KNOWN_MIXERS.items():
            mixer_addresses.update(addresses)

        return (
            transaction["from_address"] in mixer_addresses or
            transaction["to_address"] in mixer_addresses
        )

    async def _is_exchange_transaction(self, transaction: Dict) -> bool:
        """Check if transaction involves an exchange"""
        from ..config import KNOWN_EXCHANGES

        exchange_addresses = set()
        for exchange_name, addresses in KNOWN_EXCHANGES.items():
            exchange_addresses.update(addresses)

        return (
            transaction["from_address"] in exchange_addresses or
            transaction["to_address"] in exchange_addresses
        )
