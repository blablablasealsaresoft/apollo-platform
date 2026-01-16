#!/usr/bin/env python3
"""
Apollo Platform Custom Metrics Exporter

Exposes domain-specific KPIs and business metrics for Prometheus scraping.
Includes metrics for investigations, surveillance, blockchain tracking, and OSINT.
"""

import os
import time
import logging
import threading
from typing import Dict, Any, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('apollo-metrics-exporter')

# Configuration
METRICS_PORT = int(os.environ.get('METRICS_PORT', 9101))
REFRESH_INTERVAL = int(os.environ.get('REFRESH_INTERVAL', 30))

# Database connection info (would be loaded from environment in production)
DB_HOST = os.environ.get('DB_HOST', 'localhost')
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')


class MetricsRegistry:
    """Registry for all custom metrics."""

    def __init__(self):
        self._metrics: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        metric_type: str,
        help_text: str,
        labels: list = None,
        collector: Callable = None
    ):
        """Register a new metric."""
        with self._lock:
            self._metrics[name] = {
                'type': metric_type,
                'help': help_text,
                'labels': labels or [],
                'collector': collector,
                'values': {}
            }

    def set(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a metric value."""
        with self._lock:
            if name in self._metrics:
                label_key = self._label_key(labels)
                self._metrics[name]['values'][label_key] = {
                    'value': value,
                    'labels': labels or {}
                }

    def inc(self, name: str, amount: float = 1, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        with self._lock:
            if name in self._metrics:
                label_key = self._label_key(labels)
                if label_key not in self._metrics[name]['values']:
                    self._metrics[name]['values'][label_key] = {
                        'value': 0,
                        'labels': labels or {}
                    }
                self._metrics[name]['values'][label_key]['value'] += amount

    def _label_key(self, labels: Dict[str, str] = None) -> str:
        """Generate a unique key for a set of labels."""
        if not labels:
            return ''
        return ','.join(f'{k}="{v}"' for k, v in sorted(labels.items()))

    def collect(self) -> str:
        """Collect all metrics in Prometheus format."""
        lines = []

        with self._lock:
            for name, metric in self._metrics.items():
                # Run collector if defined
                if metric['collector']:
                    try:
                        metric['collector']()
                    except Exception as e:
                        logger.error(f"Error collecting {name}: {e}")

                # Output HELP and TYPE
                lines.append(f"# HELP {name} {metric['help']}")
                lines.append(f"# TYPE {name} {metric['type']}")

                # Output values
                for label_key, data in metric['values'].items():
                    if label_key:
                        lines.append(f"{name}{{{label_key}}} {data['value']}")
                    else:
                        lines.append(f"{name} {data['value']}")

        return '\n'.join(lines) + '\n'


# Global metrics registry
registry = MetricsRegistry()


# =============================================================================
# INVESTIGATION METRICS
# =============================================================================

def collect_investigation_metrics():
    """Collect metrics from investigation database."""
    # In production, these would be actual database queries
    # Using mock data for demonstration
    import random

    # Active investigations by status
    registry.set('apollo_active_investigations', random.randint(15, 30))
    registry.set('apollo_investigations_by_status', random.randint(5, 10),
                 {'status': 'active'})
    registry.set('apollo_investigations_by_status', random.randint(2, 5),
                 {'status': 'pending_review'})
    registry.set('apollo_investigations_by_status', random.randint(100, 200),
                 {'status': 'closed'})

    # Investigation queue depth
    registry.set('investigation_queue_depth', random.randint(5, 50))

    # Investigation processing time (histogram buckets simulation)
    registry.set('investigation_processing_duration_seconds_bucket',
                 random.randint(50, 100), {'le': '60'})
    registry.set('investigation_processing_duration_seconds_bucket',
                 random.randint(100, 200), {'le': '300'})
    registry.set('investigation_processing_duration_seconds_bucket',
                 random.randint(200, 300), {'le': '900'})
    registry.set('investigation_processing_duration_seconds_bucket',
                 random.randint(250, 350), {'le': '+Inf'})


registry.register(
    'apollo_active_investigations',
    'gauge',
    'Number of currently active investigations',
    collector=collect_investigation_metrics
)

registry.register(
    'apollo_investigations_by_status',
    'gauge',
    'Number of investigations by status',
    labels=['status']
)

registry.register(
    'investigation_queue_depth',
    'gauge',
    'Number of investigations waiting to be processed'
)

registry.register(
    'investigation_processing_duration_seconds_bucket',
    'histogram',
    'Investigation processing duration in seconds'
)


# =============================================================================
# TARGET MONITORING METRICS
# =============================================================================

def collect_target_metrics():
    """Collect metrics about monitored targets."""
    import random

    registry.set('apollo_targets_monitored', random.randint(50, 100))
    registry.set('apollo_targets_by_priority', random.randint(5, 15),
                 {'priority': 'critical'})
    registry.set('apollo_targets_by_priority', random.randint(20, 40),
                 {'priority': 'high'})
    registry.set('apollo_targets_by_priority', random.randint(30, 50),
                 {'priority': 'medium'})

    # Target match detection flag (would be set by facial recognition system)
    # 0 = no match, 1 = match detected
    registry.set('apollo_target_match_detected', 0)


registry.register(
    'apollo_targets_monitored',
    'gauge',
    'Total number of targets under active monitoring',
    collector=collect_target_metrics
)

registry.register(
    'apollo_targets_by_priority',
    'gauge',
    'Number of targets by priority level',
    labels=['priority']
)

registry.register(
    'apollo_target_match_detected',
    'gauge',
    'Flag indicating if a target match has been detected (1=yes, 0=no)',
    labels=['target_id', 'location']
)


# =============================================================================
# SURVEILLANCE / FACIAL RECOGNITION METRICS
# =============================================================================

def collect_surveillance_metrics():
    """Collect surveillance and facial recognition metrics."""
    import random

    registry.set('apollo_surveillance_matches', random.randint(0, 5))
    registry.set('facial_recognition_health', 1)  # 1 = healthy, 0 = down

    # Scans and processing
    registry.inc('facial_recognition_scans_total', random.randint(100, 500))

    # Matches by confidence level
    registry.set('facial_recognition_matches_by_confidence',
                 random.randint(0, 2), {'confidence': 'high'})
    registry.set('facial_recognition_matches_by_confidence',
                 random.randint(0, 5), {'confidence': 'medium'})
    registry.set('facial_recognition_matches_by_confidence',
                 random.randint(0, 10), {'confidence': 'low'})

    # Camera feed status
    registry.set('surveillance_camera_feeds_active', random.randint(20, 50))
    registry.set('surveillance_camera_feeds_total', 50)


registry.register(
    'apollo_surveillance_matches',
    'gauge',
    'Number of surveillance matches in current period',
    collector=collect_surveillance_metrics
)

registry.register(
    'facial_recognition_health',
    'gauge',
    'Health status of facial recognition system (1=healthy, 0=unhealthy)'
)

registry.register(
    'facial_recognition_scans_total',
    'counter',
    'Total number of facial recognition scans performed'
)

registry.register(
    'facial_recognition_matches_total',
    'counter',
    'Total number of facial recognition matches'
)

registry.register(
    'facial_recognition_matches_by_confidence',
    'gauge',
    'Number of matches by confidence level',
    labels=['confidence']
)

registry.register(
    'surveillance_camera_feeds_active',
    'gauge',
    'Number of active camera feeds being processed'
)

registry.register(
    'surveillance_camera_feeds_total',
    'gauge',
    'Total number of configured camera feeds'
)


# =============================================================================
# BLOCKCHAIN TRACKING METRICS
# =============================================================================

def collect_blockchain_metrics():
    """Collect blockchain tracking metrics."""
    import random

    # Tracker health and lag
    registry.set('blockchain_tracker_health', 1)
    registry.set('blockchain_tracker_lag_seconds', random.randint(10, 120),
                 {'chain': 'bitcoin'})
    registry.set('blockchain_tracker_lag_seconds', random.randint(5, 60),
                 {'chain': 'ethereum'})

    # Wallets monitored
    registry.set('blockchain_wallets_monitored', random.randint(500, 1000),
                 {'chain': 'bitcoin'})
    registry.set('blockchain_wallets_monitored', random.randint(300, 700),
                 {'chain': 'ethereum'})

    # Transactions traced
    registry.inc('blockchain_transactions_traced_total', random.randint(50, 200),
                 {'chain': 'bitcoin'})
    registry.inc('blockchain_transactions_traced_total', random.randint(100, 300),
                 {'chain': 'ethereum'})

    # Suspicious activity flags
    registry.set('blockchain_suspicious_wallets_flagged', random.randint(5, 20))


registry.register(
    'blockchain_tracker_health',
    'gauge',
    'Health status of blockchain tracker (1=healthy, 0=unhealthy)',
    collector=collect_blockchain_metrics
)

registry.register(
    'blockchain_tracker_lag_seconds',
    'gauge',
    'Seconds behind the latest block for each chain',
    labels=['chain']
)

registry.register(
    'blockchain_wallets_monitored',
    'gauge',
    'Number of wallets under active monitoring',
    labels=['chain']
)

registry.register(
    'blockchain_transactions_traced_total',
    'counter',
    'Total number of transactions traced',
    labels=['chain']
)

registry.register(
    'blockchain_suspicious_wallets_flagged',
    'gauge',
    'Number of wallets flagged for suspicious activity'
)


# =============================================================================
# OSINT COLLECTION METRICS
# =============================================================================

def collect_osint_metrics():
    """Collect OSINT collection metrics."""
    import random

    # Records collected by source
    for source in ['social_media', 'public_records', 'news', 'forums', 'darkweb']:
        registry.inc('osint_records_collected_total', random.randint(10, 100),
                     {'source': source})

    # Collection health by source
    registry.set('osint_collector_health', 1, {'source': 'social_media'})
    registry.set('osint_collector_health', 1, {'source': 'public_records'})
    registry.set('osint_collector_health', 1, {'source': 'news'})
    registry.set('osint_collector_health', random.choice([0, 1]), {'source': 'darkweb'})

    # Correlations found
    registry.inc('intelligence_correlations_created_total', random.randint(5, 30))

    # Queue depths
    registry.set('osint_processing_queue_depth', random.randint(100, 500))


registry.register(
    'osint_records_collected_total',
    'counter',
    'Total number of OSINT records collected',
    labels=['source'],
    collector=collect_osint_metrics
)

registry.register(
    'osint_collector_health',
    'gauge',
    'Health status of OSINT collectors (1=healthy, 0=unhealthy)',
    labels=['source']
)

registry.register(
    'intelligence_correlations_created_total',
    'counter',
    'Total number of intelligence correlations created'
)

registry.register(
    'osint_processing_queue_depth',
    'gauge',
    'Number of OSINT records waiting to be processed'
)


# =============================================================================
# AUTHENTICATION & SESSION METRICS
# =============================================================================

def collect_auth_metrics():
    """Collect authentication metrics."""
    import random

    registry.set('active_user_sessions', random.randint(20, 100))

    # Auth attempts (would be from actual auth service)
    registry.inc('authentication_attempts_total', random.randint(10, 50),
                 {'result': 'success'})
    registry.inc('authentication_attempts_total', random.randint(0, 10),
                 {'result': 'failure', 'reason': 'invalid_credentials'})
    registry.inc('authentication_attempts_total', random.randint(0, 3),
                 {'result': 'failure', 'reason': 'account_locked'})


registry.register(
    'active_user_sessions',
    'gauge',
    'Number of currently active user sessions',
    collector=collect_auth_metrics
)

registry.register(
    'authentication_attempts_total',
    'counter',
    'Total number of authentication attempts',
    labels=['result', 'reason']
)


# =============================================================================
# ALERT METRICS
# =============================================================================

def collect_alert_metrics():
    """Collect alert processing metrics."""
    import random

    registry.set('alert_processing_latency_seconds', random.uniform(0.5, 3.0))
    registry.set('alerts_pending', random.randint(0, 20))
    registry.set('alerts_acknowledged', random.randint(0, 10))


registry.register(
    'alert_processing_latency_seconds',
    'gauge',
    'Latency of alert processing in seconds',
    collector=collect_alert_metrics
)

registry.register(
    'alerts_pending',
    'gauge',
    'Number of alerts pending acknowledgment'
)

registry.register(
    'alerts_acknowledged',
    'gauge',
    'Number of acknowledged but unresolved alerts'
)


# =============================================================================
# HTTP SERVER
# =============================================================================

class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for metrics endpoint."""

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.debug("%s - - [%s] %s" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)

        if parsed.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.end_headers()

            try:
                output = registry.collect()
                self.wfile.write(output.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                self.wfile.write(f"# Error collecting metrics: {e}\n".encode('utf-8'))

        elif parsed.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'healthy'}).encode('utf-8'))

        elif parsed.path == '/ready':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ready'}).encode('utf-8'))

        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found\n')


def main():
    """Main entry point."""
    logger.info(f"Starting Apollo metrics exporter on port {METRICS_PORT}")

    server = HTTPServer(('0.0.0.0', METRICS_PORT), MetricsHandler)

    try:
        logger.info(f"Apollo metrics exporter listening on :{METRICS_PORT}")
        logger.info("Endpoints: /metrics, /health, /ready")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down metrics exporter")
        server.shutdown()


if __name__ == "__main__":
    main()
