"""
Continuous Breach Monitoring System
Monitor for new breaches and send automated alerts
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Set, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from breach_search import BreachSearch, SearchResults
from hibp_integration import HaveIBeenPwnedIntegration


@dataclass
class MonitorTarget:
    """Target to monitor"""
    target_id: str
    target_type: str  # email, username, domain, phone
    target_value: str
    check_interval: int = 3600  # seconds
    last_check: Optional[datetime] = None
    last_breach_count: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_id': self.target_id,
            'target_type': self.target_type,
            'target_value': self.target_value,
            'check_interval': self.check_interval,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'last_breach_count': self.last_breach_count,
            'enabled': self.enabled,
            'metadata': self.metadata
        }


@dataclass
class BreachAlert:
    """Breach alert notification"""
    alert_id: str
    target_id: str
    target_value: str
    alert_type: str  # new_breach, password_exposed, paste_found
    timestamp: datetime
    severity: str  # low, medium, high, critical
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    notified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'target_id': self.target_id,
            'target_value': self.target_value,
            'alert_type': self.alert_type,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity,
            'message': self.message,
            'details': self.details,
            'notified': self.notified
        }


class BreachMonitor:
    """
    Continuous breach monitoring system
    Monitor targets and send alerts for new breaches
    """

    def __init__(
        self,
        breach_search: BreachSearch,
        storage_file: str = 'breach_monitor_data.json',
        notification_config: Optional[Dict] = None
    ):
        """
        Initialize breach monitor

        Args:
            breach_search: BreachSearch instance
            storage_file: File to store monitor data
            notification_config: Email/webhook configuration
        """
        self.breach_search = breach_search
        self.storage_file = storage_file
        self.notification_config = notification_config or {}
        self.logger = logging.getLogger(__name__)

        # Monitoring state
        self.targets: Dict[str, MonitorTarget] = {}
        self.alerts: List[BreachAlert] = []
        self.running = False

        # Notification callbacks
        self.notification_callbacks: List[Callable] = []

        # Load existing data
        self._load_data()

    def add_target(
        self,
        target_type: str,
        target_value: str,
        check_interval: int = 3600,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add target to monitor

        Args:
            target_type: Type of target (email, username, domain, phone)
            target_value: Target value to monitor
            check_interval: Check interval in seconds
            metadata: Optional metadata

        Returns:
            Target ID
        """
        # Generate target ID
        target_id = hashlib.md5(f"{target_type}:{target_value}".encode()).hexdigest()

        # Create target
        target = MonitorTarget(
            target_id=target_id,
            target_type=target_type,
            target_value=target_value,
            check_interval=check_interval,
            metadata=metadata or {}
        )

        self.targets[target_id] = target
        self._save_data()

        self.logger.info(f"Added monitoring target: {target_type}:{target_value}")

        return target_id

    def remove_target(self, target_id: str):
        """Remove target from monitoring"""
        if target_id in self.targets:
            del self.targets[target_id]
            self._save_data()
            self.logger.info(f"Removed monitoring target: {target_id}")

    def enable_target(self, target_id: str):
        """Enable monitoring for target"""
        if target_id in self.targets:
            self.targets[target_id].enabled = True
            self._save_data()

    def disable_target(self, target_id: str):
        """Disable monitoring for target"""
        if target_id in self.targets:
            self.targets[target_id].enabled = False
            self._save_data()

    def add_email_watchlist(self, emails: List[str], check_interval: int = 3600):
        """Add multiple emails to watchlist"""
        target_ids = []
        for email in emails:
            target_id = self.add_target('email', email, check_interval)
            target_ids.append(target_id)
        return target_ids

    def add_domain_watchlist(self, domains: List[str], check_interval: int = 3600):
        """Add multiple domains to watchlist"""
        target_ids = []
        for domain in domains:
            target_id = self.add_target('domain', domain, check_interval)
            target_ids.append(target_id)
        return target_ids

    def register_notification_callback(self, callback: Callable):
        """Register callback for notifications"""
        self.notification_callbacks.append(callback)

    async def start_monitoring(self):
        """Start continuous monitoring"""
        self.logger.info("Starting breach monitoring")
        self.running = True

        # Start monitoring tasks
        tasks = []
        for target_id in self.targets:
            task = asyncio.create_task(self._monitor_target(target_id))
            tasks.append(task)

        # Wait for all tasks
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
        finally:
            self.running = False

    def stop_monitoring(self):
        """Stop monitoring"""
        self.logger.info("Stopping breach monitoring")
        self.running = False

    async def _monitor_target(self, target_id: str):
        """Monitor a specific target"""
        while self.running:
            try:
                target = self.targets.get(target_id)
                if not target or not target.enabled:
                    await asyncio.sleep(60)
                    continue

                # Check if it's time to check this target
                now = datetime.now()
                if target.last_check:
                    time_since_check = (now - target.last_check).total_seconds()
                    if time_since_check < target.check_interval:
                        await asyncio.sleep(60)
                        continue

                # Perform check
                await self._check_target(target)

                # Update last check time
                target.last_check = now
                self._save_data()

            except Exception as e:
                self.logger.error(f"Error monitoring target {target_id}: {e}")

            await asyncio.sleep(60)  # Check every minute if target needs checking

    async def _check_target(self, target: MonitorTarget):
        """Check target for new breaches"""
        self.logger.info(f"Checking target: {target.target_type}:{target.target_value}")

        try:
            # Search for breaches
            if target.target_type == 'email':
                results = await self.breach_search.search_email(target.target_value, correlate=False)
            elif target.target_type == 'username':
                results = await self.breach_search.search_username(target.target_value, correlate=False)
            elif target.target_type == 'domain':
                results = await self.breach_search.search_domain(target.target_value)
            elif target.target_type == 'phone':
                results = await self.breach_search.search_phone(target.target_value, correlate=False)
            else:
                self.logger.warning(f"Unknown target type: {target.target_type}")
                return

            # Check for new breaches
            if results.total_records > target.last_breach_count:
                new_breaches = results.total_records - target.last_breach_count
                await self._create_alert(
                    target=target,
                    alert_type='new_breach',
                    severity='high',
                    message=f"{new_breaches} new breach(es) found for {target.target_value}",
                    details={
                        'new_breach_count': new_breaches,
                        'total_breaches': results.total_records,
                        'sources': results.sources
                    }
                )

                target.last_breach_count = results.total_records

            # Check for sensitive data
            for record in results.records:
                if record.password:
                    await self._create_alert(
                        target=target,
                        alert_type='password_exposed',
                        severity='critical',
                        message=f"Password exposed for {target.target_value}",
                        details={
                            'database': record.database,
                            'breach_date': record.breach_date.isoformat() if record.breach_date else None,
                            'password': record.password[:3] + '***'  # Partial password for notification
                        }
                    )

        except Exception as e:
            self.logger.error(f"Error checking target {target.target_id}: {e}")

    async def _create_alert(
        self,
        target: MonitorTarget,
        alert_type: str,
        severity: str,
        message: str,
        details: Dict[str, Any]
    ):
        """Create and send alert"""
        # Generate alert ID
        alert_id = hashlib.md5(
            f"{target.target_id}:{alert_type}:{datetime.now().isoformat()}".encode()
        ).hexdigest()

        # Create alert
        alert = BreachAlert(
            alert_id=alert_id,
            target_id=target.target_id,
            target_value=target.target_value,
            alert_type=alert_type,
            timestamp=datetime.now(),
            severity=severity,
            message=message,
            details=details
        )

        self.alerts.append(alert)
        self.logger.warning(f"Alert created: {message}")

        # Send notifications
        await self._send_notifications(alert)

        # Save data
        self._save_data()

    async def _send_notifications(self, alert: BreachAlert):
        """Send alert notifications"""
        # Call registered callbacks
        for callback in self.notification_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                self.logger.error(f"Notification callback failed: {e}")

        # Send email if configured
        if self.notification_config.get('email_enabled'):
            await self._send_email_notification(alert)

        # Send webhook if configured
        if self.notification_config.get('webhook_url'):
            await self._send_webhook_notification(alert)

        alert.notified = True

    async def _send_email_notification(self, alert: BreachAlert):
        """Send email notification"""
        try:
            email_config = self.notification_config

            msg = MIMEMultipart()
            msg['From'] = email_config.get('from_email')
            msg['To'] = email_config.get('to_email')
            msg['Subject'] = f"[{alert.severity.upper()}] Breach Alert: {alert.target_value}"

            # Create email body
            body = f"""
Breach Alert Notification
========================

Severity: {alert.severity.upper()}
Target: {alert.target_value}
Alert Type: {alert.alert_type}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Message:
{alert.message}

Details:
{json.dumps(alert.details, indent=2)}

---
Apollo Breach Monitoring System
            """

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(email_config.get('smtp_host'), email_config.get('smtp_port', 587)) as server:
                server.starttls()
                if email_config.get('smtp_username'):
                    server.login(email_config.get('smtp_username'), email_config.get('smtp_password'))
                server.send_message(msg)

            self.logger.info(f"Email notification sent for alert {alert.alert_id}")

        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")

    async def _send_webhook_notification(self, alert: BreachAlert):
        """Send webhook notification"""
        try:
            import aiohttp

            webhook_url = self.notification_config.get('webhook_url')

            payload = {
                'alert_id': alert.alert_id,
                'target': alert.target_value,
                'severity': alert.severity,
                'alert_type': alert.alert_type,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat(),
                'details': alert.details
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info(f"Webhook notification sent for alert {alert.alert_id}")
                    else:
                        self.logger.error(f"Webhook notification failed: {response.status}")

        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")

    def get_targets(self) -> List[Dict[str, Any]]:
        """Get all monitoring targets"""
        return [target.to_dict() for target in self.targets.values()]

    def get_alerts(
        self,
        target_id: Optional[str] = None,
        severity: Optional[str] = None,
        days: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get alerts with optional filtering

        Args:
            target_id: Filter by target ID
            severity: Filter by severity
            days: Filter by last N days

        Returns:
            List of alerts
        """
        alerts = self.alerts

        # Filter by target
        if target_id:
            alerts = [a for a in alerts if a.target_id == target_id]

        # Filter by severity
        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        # Filter by days
        if days:
            cutoff = datetime.now() - timedelta(days=days)
            alerts = [a for a in alerts if a.timestamp >= cutoff]

        return [alert.to_dict() for alert in alerts]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        total_targets = len(self.targets)
        enabled_targets = sum(1 for t in self.targets.values() if t.enabled)
        total_alerts = len(self.alerts)

        # Count alerts by severity
        severity_counts = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }

        for alert in self.alerts:
            severity_counts[alert.severity] += 1

        # Count alerts by type
        type_counts = {}
        for alert in self.alerts:
            type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1

        return {
            'total_targets': total_targets,
            'enabled_targets': enabled_targets,
            'disabled_targets': total_targets - enabled_targets,
            'total_alerts': total_alerts,
            'alerts_by_severity': severity_counts,
            'alerts_by_type': type_counts,
            'monitoring_active': self.running
        }

    def clear_old_alerts(self, days: int = 30):
        """Clear alerts older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        original_count = len(self.alerts)

        self.alerts = [a for a in self.alerts if a.timestamp >= cutoff]

        removed = original_count - len(self.alerts)
        self.logger.info(f"Cleared {removed} old alerts")

        self._save_data()

    def export_alerts(self, output_file: str, format: str = 'json'):
        """Export alerts to file"""
        alerts_data = [alert.to_dict() for alert in self.alerts]

        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(alerts_data, f, indent=2)
        elif format == 'csv':
            import csv
            if alerts_data:
                with open(output_file, 'w', newline='') as f:
                    fieldnames = alerts_data[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(alerts_data)

        self.logger.info(f"Exported {len(alerts_data)} alerts to {output_file}")

    def _load_data(self):
        """Load monitoring data from file"""
        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)

            # Load targets
            for target_data in data.get('targets', []):
                target = MonitorTarget(
                    target_id=target_data['target_id'],
                    target_type=target_data['target_type'],
                    target_value=target_data['target_value'],
                    check_interval=target_data['check_interval'],
                    last_check=datetime.fromisoformat(target_data['last_check'])
                        if target_data.get('last_check') else None,
                    last_breach_count=target_data['last_breach_count'],
                    enabled=target_data['enabled'],
                    metadata=target_data.get('metadata', {})
                )
                self.targets[target.target_id] = target

            # Load alerts
            for alert_data in data.get('alerts', []):
                alert = BreachAlert(
                    alert_id=alert_data['alert_id'],
                    target_id=alert_data['target_id'],
                    target_value=alert_data['target_value'],
                    alert_type=alert_data['alert_type'],
                    timestamp=datetime.fromisoformat(alert_data['timestamp']),
                    severity=alert_data['severity'],
                    message=alert_data['message'],
                    details=alert_data.get('details', {}),
                    notified=alert_data.get('notified', False)
                )
                self.alerts.append(alert)

            self.logger.info(f"Loaded {len(self.targets)} targets and {len(self.alerts)} alerts")

        except FileNotFoundError:
            self.logger.info("No existing monitoring data found")
        except Exception as e:
            self.logger.error(f"Error loading monitoring data: {e}")

    def _save_data(self):
        """Save monitoring data to file"""
        try:
            data = {
                'targets': [target.to_dict() for target in self.targets.values()],
                'alerts': [alert.to_dict() for alert in self.alerts]
            }

            with open(self.storage_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Error saving monitoring data: {e}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Initialize breach search
        breach_search = BreachSearch(config_file='breach_config.json')

        # Initialize monitor with email notifications
        notification_config = {
            'email_enabled': True,
            'from_email': 'alerts@example.com',
            'to_email': 'security@example.com',
            'smtp_host': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_username': 'your-email@gmail.com',
            'smtp_password': 'your-password'
        }

        monitor = BreachMonitor(
            breach_search=breach_search,
            notification_config=notification_config
        )

        # Add targets
        monitor.add_email_watchlist([
            'target@example.com',
            'admin@company.com'
        ], check_interval=3600)

        monitor.add_domain_watchlist([
            'company.com',
            'example.com'
        ], check_interval=7200)

        # Register custom callback
        async def custom_alert_handler(alert: BreachAlert):
            print(f"Custom Alert: {alert.message}")

        monitor.register_notification_callback(custom_alert_handler)

        # Start monitoring
        await monitor.start_monitoring()

    asyncio.run(main())
