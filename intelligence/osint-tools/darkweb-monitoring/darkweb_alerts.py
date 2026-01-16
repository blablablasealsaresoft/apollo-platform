#!/usr/bin/env python3
"""
Dark Web Alert System
Real-time alerting for dark web intelligence
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import logging
from pathlib import Path


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    timestamp: datetime
    alert_type: str
    severity: str  # low, medium, high, critical
    title: str
    message: str
    source: str
    url: Optional[str]
    entities: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class DarkWebAlerts:
    """Dark web alert system"""

    SEVERITY_COLORS = {
        'low': '#00FF00',
        'medium': '#FFA500',
        'high': '#FF0000',
        'critical': '#8B0000'
    }

    SEVERITY_EMOJIS = {
        'low': '🟢',
        'medium': '🟡',
        'high': '🔴',
        'critical': '🚨'
    }

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        email_config: Optional[Dict[str, Any]] = None,
        alert_file: Optional[str] = None
    ):
        """
        Initialize alert system

        Args:
            webhook_url: Webhook URL (Slack, Discord, etc.)
            email_config: Email configuration
            alert_file: File to log alerts
        """
        self.webhook_url = webhook_url
        self.email_config = email_config
        self.alert_file = alert_file
        self.logger = self._setup_logging()
        self.alerts: List[Alert] = []

        # Alert rules
        self.rules = self._load_default_rules()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("DarkWebAlerts")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_default_rules(self) -> Dict[str, Dict]:
        """Load default alert rules"""
        return {
            'high_risk_content': {
                'enabled': True,
                'severity': 'high',
                'condition': lambda result: result.risk_score >= 80
            },
            'cryptocurrency_found': {
                'enabled': True,
                'severity': 'medium',
                'condition': lambda result: len(result.cryptocurrency_addresses) > 0
            },
            'credentials_leak': {
                'enabled': True,
                'severity': 'critical',
                'condition': lambda result: 'credentials' in str(result.metadata).lower()
            },
            'entity_mention': {
                'enabled': True,
                'severity': 'medium',
                'condition': lambda result: len(result.entities) > 0
            },
            'marketplace_activity': {
                'enabled': True,
                'severity': 'medium',
                'condition': lambda result: result.source_type == 'marketplace'
            },
            'onion_url_found': {
                'enabled': True,
                'severity': 'low',
                'condition': lambda result: '.onion' in result.url
            }
        }

    async def send_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        result: Any,
        entities: Optional[List[str]] = None
    ):
        """
        Send alert

        Args:
            alert_type: Type of alert
            severity: Alert severity
            message: Alert message
            result: Related result object
            entities: Entities involved
        """
        import hashlib

        # Create alert
        alert = Alert(
            alert_id=hashlib.sha256(
                f"{alert_type}{result.id}{datetime.utcnow()}".encode()
            ).hexdigest()[:16],
            timestamp=datetime.utcnow(),
            alert_type=alert_type,
            severity=severity,
            title=f"Dark Web Alert: {alert_type.replace('_', ' ').title()}",
            message=message,
            source=result.source,
            url=result.url,
            entities=entities or result.entities,
            metadata={
                'result_id': result.id,
                'risk_score': result.risk_score,
                'source_type': result.source_type
            }
        )

        self.alerts.append(alert)

        # Send via configured channels
        await self._dispatch_alert(alert, result)

        self.logger.info(f"Alert sent: {alert.title} (severity: {severity})")

    async def _dispatch_alert(self, alert: Alert, result: Any):
        """
        Dispatch alert to configured channels

        Args:
            alert: Alert object
            result: Related result
        """
        tasks = []

        # Webhook notification
        if self.webhook_url:
            tasks.append(self._send_webhook_alert(alert, result))

        # Email notification
        if self.email_config:
            tasks.append(self._send_email_alert(alert, result))

        # File logging
        if self.alert_file:
            tasks.append(self._log_alert_to_file(alert))

        # Execute all notifications
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_webhook_alert(self, alert: Alert, result: Any):
        """
        Send alert via webhook

        Args:
            alert: Alert object
            result: Related result
        """
        try:
            # Detect webhook type
            if 'slack' in self.webhook_url.lower():
                payload = self._format_slack_alert(alert, result)
            elif 'discord' in self.webhook_url.lower():
                payload = self._format_discord_alert(alert, result)
            else:
                payload = self._format_generic_alert(alert, result)

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        self.logger.debug("Webhook alert sent successfully")
                    else:
                        self.logger.error(f"Webhook alert failed: {response.status}")

        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")

    def _format_slack_alert(self, alert: Alert, result: Any) -> Dict[str, Any]:
        """Format alert for Slack"""
        color = self.SEVERITY_COLORS.get(alert.severity, '#808080')

        return {
            'attachments': [{
                'color': color,
                'title': f"{self.SEVERITY_EMOJIS[alert.severity]} {alert.title}",
                'text': alert.message,
                'fields': [
                    {
                        'title': 'Severity',
                        'value': alert.severity.upper(),
                        'short': True
                    },
                    {
                        'title': 'Source',
                        'value': alert.source,
                        'short': True
                    },
                    {
                        'title': 'Alert Type',
                        'value': alert.alert_type.replace('_', ' ').title(),
                        'short': True
                    },
                    {
                        'title': 'Risk Score',
                        'value': f"{alert.metadata.get('risk_score', 0)}/100",
                        'short': True
                    },
                    {
                        'title': 'URL',
                        'value': alert.url or 'N/A',
                        'short': False
                    }
                ],
                'footer': 'Dark Web Monitor',
                'ts': int(alert.timestamp.timestamp())
            }]
        }

    def _format_discord_alert(self, alert: Alert, result: Any) -> Dict[str, Any]:
        """Format alert for Discord"""
        color_hex = self.SEVERITY_COLORS.get(alert.severity, '#808080')
        color_int = int(color_hex.replace('#', ''), 16)

        return {
            'embeds': [{
                'title': f"{self.SEVERITY_EMOJIS[alert.severity]} {alert.title}",
                'description': alert.message,
                'color': color_int,
                'fields': [
                    {
                        'name': 'Severity',
                        'value': alert.severity.upper(),
                        'inline': True
                    },
                    {
                        'name': 'Source',
                        'value': alert.source,
                        'inline': True
                    },
                    {
                        'name': 'Alert Type',
                        'value': alert.alert_type.replace('_', ' ').title(),
                        'inline': True
                    },
                    {
                        'name': 'Risk Score',
                        'value': f"{alert.metadata.get('risk_score', 0)}/100",
                        'inline': True
                    },
                    {
                        'name': 'URL',
                        'value': alert.url or 'N/A',
                        'inline': False
                    }
                ],
                'footer': {
                    'text': 'Dark Web Monitor'
                },
                'timestamp': alert.timestamp.isoformat()
            }]
        }

    def _format_generic_alert(self, alert: Alert, result: Any) -> Dict[str, Any]:
        """Format generic alert payload"""
        return {
            'alert': alert.to_dict(),
            'result': {
                'url': result.url,
                'title': result.title,
                'source': result.source,
                'source_type': result.source_type,
                'risk_score': result.risk_score,
                'keywords': result.keywords_found
            }
        }

    async def _send_email_alert(self, alert: Alert, result: Any):
        """
        Send alert via email

        Args:
            alert: Alert object
            result: Related result
        """
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = alert.title
            msg['From'] = self.email_config.get('from')
            msg['To'] = self.email_config.get('to')

            # HTML body
            html = self._format_email_html(alert, result)
            msg.attach(MIMEText(html, 'html'))

            # Send email
            with smtplib.SMTP(
                self.email_config.get('smtp_host'),
                self.email_config.get('smtp_port', 587)
            ) as server:
                server.starttls()
                server.login(
                    self.email_config.get('username'),
                    self.email_config.get('password')
                )
                server.send_message(msg)

            self.logger.debug("Email alert sent successfully")

        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")

    def _format_email_html(self, alert: Alert, result: Any) -> str:
        """Format alert as HTML email"""
        severity_color = self.SEVERITY_COLORS.get(alert.severity, '#808080')

        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: {severity_color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
                .footer {{ background-color: #f5f5f5; padding: 10px; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{self.SEVERITY_EMOJIS[alert.severity]} {alert.title}</h1>
            </div>
            <div class="content">
                <div class="field">
                    <span class="label">Severity:</span> {alert.severity.upper()}
                </div>
                <div class="field">
                    <span class="label">Message:</span> {alert.message}
                </div>
                <div class="field">
                    <span class="label">Source:</span> {alert.source}
                </div>
                <div class="field">
                    <span class="label">URL:</span> <a href="{alert.url}">{alert.url}</a>
                </div>
                <div class="field">
                    <span class="label">Risk Score:</span> {alert.metadata.get('risk_score', 0)}/100
                </div>
                <div class="field">
                    <span class="label">Timestamp:</span> {alert.timestamp.isoformat()}
                </div>
            </div>
            <div class="footer">
                Dark Web Monitor - Automated Alert
            </div>
        </body>
        </html>
        """

        return html

    async def _log_alert_to_file(self, alert: Alert):
        """
        Log alert to file

        Args:
            alert: Alert object
        """
        try:
            alert_path = Path(self.alert_file)
            alert_path.parent.mkdir(parents=True, exist_ok=True)

            # Append alert to file
            with open(alert_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert.to_dict()) + '\n')

        except Exception as e:
            self.logger.error(f"Error logging alert to file: {e}")

    def add_rule(
        self,
        rule_name: str,
        condition: callable,
        severity: str,
        enabled: bool = True
    ):
        """
        Add custom alert rule

        Args:
            rule_name: Rule name
            condition: Condition function (takes result object)
            severity: Alert severity
            enabled: Whether rule is enabled
        """
        self.rules[rule_name] = {
            'enabled': enabled,
            'severity': severity,
            'condition': condition
        }

        self.logger.info(f"Alert rule added: {rule_name}")

    def remove_rule(self, rule_name: str):
        """Remove alert rule"""
        if rule_name in self.rules:
            del self.rules[rule_name]
            self.logger.info(f"Alert rule removed: {rule_name}")

    def get_rules(self) -> Dict[str, Dict]:
        """Get all alert rules"""
        return self.rules

    def get_alerts(
        self,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Alert]:
        """
        Get alerts with optional filtering

        Args:
            severity: Filter by severity
            alert_type: Filter by alert type
            limit: Maximum number of alerts

        Returns:
            List of alerts
        """
        filtered = self.alerts

        if severity:
            filtered = [a for a in filtered if a.severity == severity]

        if alert_type:
            filtered = [a for a in filtered if a.alert_type == alert_type]

        if limit:
            filtered = filtered[-limit:]

        return filtered

    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_type': {},
                'by_source': {}
            }

        # Count by severity
        by_severity = {}
        for alert in self.alerts:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

        # Count by type
        by_type = {}
        for alert in self.alerts:
            by_type[alert.alert_type] = by_type.get(alert.alert_type, 0) + 1

        # Count by source
        by_source = {}
        for alert in self.alerts:
            by_source[alert.source] = by_source.get(alert.source, 0) + 1

        return {
            'total_alerts': len(self.alerts),
            'by_severity': by_severity,
            'by_type': by_type,
            'by_source': by_source
        }

    def export_alerts(self, output_file: str):
        """Export alerts to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'total_alerts': len(self.alerts),
            'statistics': self.get_statistics(),
            'alerts': [alert.to_dict() for alert in self.alerts]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Alerts exported to {output_file}")


async def main():
    """Example usage"""
    # Create alert system
    alerts = DarkWebAlerts(
        webhook_url=None,  # Set to actual webhook URL
        alert_file="darkweb_alerts.jsonl"
    )

    # Simulated result object
    from dataclasses import dataclass

    @dataclass
    class SimulatedResult:
        id: str
        source: str
        source_type: str
        url: str
        title: str
        risk_score: int
        entities: list
        cryptocurrency_addresses: list
        keywords_found: list
        metadata: dict

    result = SimulatedResult(
        id="test123",
        source="TestMarketplace",
        source_type="marketplace",
        url="http://example.onion",
        title="Test Listing",
        risk_score=85,
        entities=["test@example.com"],
        cryptocurrency_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        keywords_found=["test", "demo"],
        metadata={}
    )

    # Send test alert
    await alerts.send_alert(
        alert_type="high_risk_content",
        severity="high",
        message="High risk content detected in dark web marketplace",
        result=result
    )

    print("[+] Alert sent")

    # Get statistics
    stats = alerts.get_statistics()
    print(f"[+] Alert statistics: {stats}")

    # Export alerts
    alerts.export_alerts("alerts_export.json")
    print("[+] Alerts exported")


if __name__ == "__main__":
    asyncio.run(main())
