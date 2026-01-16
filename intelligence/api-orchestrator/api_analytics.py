"""
API Analytics - Usage Tracking and Performance Metrics
Tracks API calls, performance, costs, and quotas
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
import logging
import json

logger = logging.getLogger(__name__)


@dataclass
class APICallRecord:
    """Record of single API call"""
    api_name: str
    endpoint: str
    timestamp: float
    duration: float
    status: int
    success: bool
    error: Optional[str] = None
    response_size: int = 0
    cached: bool = False
    cost: float = 0.0


@dataclass
class APIQuota:
    """API usage quota"""
    api_name: str
    max_calls_per_day: int
    max_calls_per_month: int
    cost_per_call: float = 0.0
    max_cost_per_month: float = 0.0


@dataclass
class APIMetrics:
    """Aggregated API metrics"""
    api_name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    cached_calls: int = 0
    total_duration: float = 0.0
    min_duration: float = float('inf')
    max_duration: float = 0.0
    avg_duration: float = 0.0
    p50_duration: float = 0.0
    p95_duration: float = 0.0
    p99_duration: float = 0.0
    total_cost: float = 0.0
    success_rate: float = 0.0
    cache_hit_rate: float = 0.0
    errors: Dict[str, int] = field(default_factory=dict)
    durations: List[float] = field(default_factory=list)


class APIAnalytics:
    """API usage analytics and tracking"""

    def __init__(self):
        """Initialize analytics"""
        self.call_records: List[APICallRecord] = []
        self.metrics_by_api: Dict[str, APIMetrics] = {}
        self.quotas: Dict[str, APIQuota] = {}
        self.start_time = time.time()

    def record_call(
        self,
        api_name: str,
        endpoint: str,
        duration: float,
        status: int,
        success: bool,
        error: Optional[str] = None,
        response_size: int = 0,
        cached: bool = False
    ):
        """
        Record API call

        Args:
            api_name: API identifier
            endpoint: API endpoint
            duration: Request duration in seconds
            status: HTTP status code
            success: Whether call succeeded
            error: Error message if failed
            response_size: Response size in bytes
            cached: Whether response was cached
        """
        # Calculate cost
        quota = self.quotas.get(api_name)
        cost = quota.cost_per_call if quota and not cached else 0.0

        # Create record
        record = APICallRecord(
            api_name=api_name,
            endpoint=endpoint,
            timestamp=time.time(),
            duration=duration,
            status=status,
            success=success,
            error=error,
            response_size=response_size,
            cached=cached,
            cost=cost
        )

        self.call_records.append(record)

        # Update metrics
        self._update_metrics(record)

    def _update_metrics(self, record: APICallRecord):
        """Update metrics for API"""
        api_name = record.api_name

        if api_name not in self.metrics_by_api:
            self.metrics_by_api[api_name] = APIMetrics(api_name=api_name)

        metrics = self.metrics_by_api[api_name]

        # Update counters
        metrics.total_calls += 1
        if record.success:
            metrics.successful_calls += 1
        else:
            metrics.failed_calls += 1
            if record.error:
                metrics.errors[record.error] = metrics.errors.get(record.error, 0) + 1

        if record.cached:
            metrics.cached_calls += 1

        # Update durations
        metrics.durations.append(record.duration)
        metrics.total_duration += record.duration
        metrics.min_duration = min(metrics.min_duration, record.duration)
        metrics.max_duration = max(metrics.max_duration, record.duration)
        metrics.avg_duration = metrics.total_duration / metrics.total_calls

        # Update percentiles
        if len(metrics.durations) > 0:
            sorted_durations = sorted(metrics.durations)
            metrics.p50_duration = self._percentile(sorted_durations, 50)
            metrics.p95_duration = self._percentile(sorted_durations, 95)
            metrics.p99_duration = self._percentile(sorted_durations, 99)

        # Update rates
        metrics.success_rate = metrics.successful_calls / metrics.total_calls
        metrics.cache_hit_rate = metrics.cached_calls / metrics.total_calls

        # Update cost
        metrics.total_cost += record.cost

    def _percentile(self, sorted_data: List[float], percentile: int) -> float:
        """Calculate percentile"""
        if not sorted_data:
            return 0.0

        index = int((percentile / 100.0) * len(sorted_data))
        index = min(index, len(sorted_data) - 1)
        return sorted_data[index]

    def get_metrics(self, api_name: str) -> Optional[APIMetrics]:
        """Get metrics for specific API"""
        return self.metrics_by_api.get(api_name)

    def get_all_metrics(self) -> Dict[str, APIMetrics]:
        """Get metrics for all APIs"""
        return self.metrics_by_api.copy()

    def set_quota(
        self,
        api_name: str,
        max_calls_per_day: int,
        max_calls_per_month: int,
        cost_per_call: float = 0.0,
        max_cost_per_month: float = 0.0
    ):
        """
        Set usage quota for API

        Args:
            api_name: API identifier
            max_calls_per_day: Maximum daily calls
            max_calls_per_month: Maximum monthly calls
            cost_per_call: Cost per API call
            max_cost_per_month: Maximum monthly cost
        """
        self.quotas[api_name] = APIQuota(
            api_name=api_name,
            max_calls_per_day=max_calls_per_day,
            max_calls_per_month=max_calls_per_month,
            cost_per_call=cost_per_call,
            max_cost_per_month=max_cost_per_month
        )
        logger.info(f"Set quota for {api_name}: {max_calls_per_day}/day, "
                   f"{max_calls_per_month}/month")

    def check_quota(self, api_name: str) -> Dict[str, Any]:
        """
        Check quota usage for API

        Args:
            api_name: API identifier

        Returns:
            Quota status
        """
        quota = self.quotas.get(api_name)
        if not quota:
            return {'has_quota': False}

        # Calculate usage in different periods
        now = time.time()
        day_ago = now - 86400
        month_ago = now - 30 * 86400

        daily_calls = sum(
            1 for r in self.call_records
            if r.api_name == api_name and r.timestamp > day_ago and not r.cached
        )

        monthly_calls = sum(
            1 for r in self.call_records
            if r.api_name == api_name and r.timestamp > month_ago and not r.cached
        )

        monthly_cost = sum(
            r.cost for r in self.call_records
            if r.api_name == api_name and r.timestamp > month_ago
        )

        return {
            'has_quota': True,
            'api_name': api_name,
            'daily': {
                'used': daily_calls,
                'limit': quota.max_calls_per_day,
                'remaining': quota.max_calls_per_day - daily_calls,
                'percentage': (daily_calls / quota.max_calls_per_day) * 100
            },
            'monthly': {
                'used': monthly_calls,
                'limit': quota.max_calls_per_month,
                'remaining': quota.max_calls_per_month - monthly_calls,
                'percentage': (monthly_calls / quota.max_calls_per_month) * 100
            },
            'cost': {
                'monthly_cost': monthly_cost,
                'limit': quota.max_cost_per_month,
                'remaining': quota.max_cost_per_month - monthly_cost,
                'percentage': (
                    (monthly_cost / quota.max_cost_per_month) * 100
                    if quota.max_cost_per_month > 0 else 0
                )
            }
        }

    def is_quota_exceeded(self, api_name: str) -> bool:
        """Check if API quota is exceeded"""
        quota_status = self.check_quota(api_name)

        if not quota_status.get('has_quota'):
            return False

        # Check daily limit
        if quota_status['daily']['remaining'] <= 0:
            return True

        # Check monthly limit
        if quota_status['monthly']['remaining'] <= 0:
            return True

        # Check cost limit
        if quota_status['cost']['limit'] > 0:
            if quota_status['cost']['remaining'] <= 0:
                return True

        return False

    def get_top_apis(self, limit: int = 10, by: str = 'calls') -> List[Dict]:
        """
        Get top APIs by usage metric

        Args:
            limit: Number of APIs to return
            by: Metric to sort by (calls, duration, cost, errors)

        Returns:
            List of top APIs
        """
        if by == 'calls':
            key = lambda m: m.total_calls
        elif by == 'duration':
            key = lambda m: m.total_duration
        elif by == 'cost':
            key = lambda m: m.total_cost
        elif by == 'errors':
            key = lambda m: m.failed_calls
        else:
            key = lambda m: m.total_calls

        sorted_metrics = sorted(
            self.metrics_by_api.values(),
            key=key,
            reverse=True
        )

        return [
            {
                'api_name': m.api_name,
                'total_calls': m.total_calls,
                'success_rate': m.success_rate,
                'avg_duration': m.avg_duration,
                'total_cost': m.total_cost
            }
            for m in sorted_metrics[:limit]
        ]

    def get_slow_apis(self, threshold: float = 5.0, limit: int = 10) -> List[Dict]:
        """
        Get APIs with slow average response time

        Args:
            threshold: Duration threshold in seconds
            limit: Number of APIs to return

        Returns:
            List of slow APIs
        """
        slow_apis = [
            m for m in self.metrics_by_api.values()
            if m.avg_duration > threshold
        ]

        sorted_apis = sorted(
            slow_apis,
            key=lambda m: m.avg_duration,
            reverse=True
        )

        return [
            {
                'api_name': m.api_name,
                'avg_duration': m.avg_duration,
                'p95_duration': m.p95_duration,
                'p99_duration': m.p99_duration,
                'total_calls': m.total_calls
            }
            for m in sorted_apis[:limit]
        ]

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors across all APIs"""
        total_errors = sum(m.failed_calls for m in self.metrics_by_api.values())
        total_calls = sum(m.total_calls for m in self.metrics_by_api.values())

        error_by_api = {
            api_name: {
                'failed_calls': m.failed_calls,
                'error_rate': m.failed_calls / m.total_calls if m.total_calls > 0 else 0,
                'errors': m.errors
            }
            for api_name, m in self.metrics_by_api.items()
            if m.failed_calls > 0
        }

        return {
            'total_errors': total_errors,
            'total_calls': total_calls,
            'overall_error_rate': total_errors / total_calls if total_calls > 0 else 0,
            'error_by_api': error_by_api
        }

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get cost summary across all APIs"""
        total_cost = sum(m.total_cost for m in self.metrics_by_api.values())

        cost_by_api = {
            api_name: {
                'total_cost': m.total_cost,
                'avg_cost_per_call': m.total_cost / m.total_calls if m.total_calls > 0 else 0,
                'total_calls': m.total_calls
            }
            for api_name, m in self.metrics_by_api.items()
        }

        return {
            'total_cost': total_cost,
            'cost_by_api': cost_by_api
        }

    def get_time_series(
        self,
        api_name: Optional[str] = None,
        interval: int = 3600
    ) -> List[Dict]:
        """
        Get time series data for API calls

        Args:
            api_name: Specific API or None for all
            interval: Time interval in seconds

        Returns:
            List of time series data points
        """
        # Filter records
        records = [
            r for r in self.call_records
            if api_name is None or r.api_name == api_name
        ]

        if not records:
            return []

        # Group by time interval
        start_time = min(r.timestamp for r in records)
        end_time = max(r.timestamp for r in records)

        time_series = []
        current_time = start_time

        while current_time < end_time:
            interval_end = current_time + interval

            interval_records = [
                r for r in records
                if current_time <= r.timestamp < interval_end
            ]

            if interval_records:
                time_series.append({
                    'timestamp': current_time,
                    'total_calls': len(interval_records),
                    'successful_calls': sum(1 for r in interval_records if r.success),
                    'failed_calls': sum(1 for r in interval_records if not r.success),
                    'avg_duration': statistics.mean([r.duration for r in interval_records]),
                    'total_cost': sum(r.cost for r in interval_records)
                })

            current_time = interval_end

        return time_series

    def export_metrics(self, filepath: str):
        """Export metrics to JSON file"""
        data = {
            'export_time': datetime.now().isoformat(),
            'uptime_seconds': time.time() - self.start_time,
            'metrics': {
                api_name: {
                    'total_calls': m.total_calls,
                    'successful_calls': m.successful_calls,
                    'failed_calls': m.failed_calls,
                    'cached_calls': m.cached_calls,
                    'avg_duration': m.avg_duration,
                    'p50_duration': m.p50_duration,
                    'p95_duration': m.p95_duration,
                    'p99_duration': m.p99_duration,
                    'total_cost': m.total_cost,
                    'success_rate': m.success_rate,
                    'cache_hit_rate': m.cache_hit_rate,
                    'errors': m.errors
                }
                for api_name, m in self.metrics_by_api.items()
            },
            'quotas': {
                api_name: {
                    'max_calls_per_day': q.max_calls_per_day,
                    'max_calls_per_month': q.max_calls_per_month,
                    'cost_per_call': q.cost_per_call,
                    'max_cost_per_month': q.max_cost_per_month,
                    'status': self.check_quota(api_name)
                }
                for api_name, q in self.quotas.items()
            }
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported metrics to {filepath}")

    def reset(self):
        """Reset all analytics"""
        self.call_records.clear()
        self.metrics_by_api.clear()
        self.start_time = time.time()
        logger.info("Reset analytics")
