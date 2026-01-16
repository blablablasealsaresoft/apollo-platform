"""
Timeline Builder
Chronological event reconstruction with pattern extraction
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import re


class TimelineBuilder:
    """
    Timeline Generation Engine
    Constructs chronological timelines from multi-source intelligence
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Timeline Builder

        Args:
            config: Configuration dictionary
        """
        self.max_gap_days = config.get('max_gap_days', 30)
        self.min_events = config.get('min_events', 2)

    def build_timeline(self, profile: Any, intelligence_sources: List[Any]) -> List[Dict[str, Any]]:
        """
        Build comprehensive timeline from intelligence sources

        Args:
            profile: EntityProfile object
            intelligence_sources: List of IntelligenceSource objects

        Returns:
            Chronologically ordered list of events
        """
        events = []

        # Extract events from each source
        for source in intelligence_sources:
            source_events = self._extract_events(source, profile)
            events.extend(source_events)

        # Sort chronologically
        events = self._sort_events(events)

        # Deduplicate similar events
        events = self._deduplicate_events(events)

        # Identify gaps
        events = self._identify_gaps(events)

        # Extract patterns
        patterns = self._extract_patterns(events)

        # Add pattern metadata to timeline
        if patterns:
            events.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'analysis',
                'description': f'Detected {len(patterns)} behavioral patterns',
                'patterns': patterns,
                'is_metadata': True
            })

        return events

    def _extract_events(self, source: Any, profile: Any) -> List[Dict[str, Any]]:
        """Extract timeline events from intelligence source"""
        events = []

        # Use source timestamp as base
        base_timestamp = source.timestamp

        # Extract events based on source type
        if source.source_type == 'breach':
            event = self._create_breach_event(source, base_timestamp)
            if event:
                events.append(event)

        elif source.source_type == 'blockchain':
            blockchain_events = self._create_blockchain_events(source, base_timestamp)
            events.extend(blockchain_events)

        elif source.source_type == 'socmint':
            social_events = self._create_social_events(source, base_timestamp)
            events.extend(social_events)

        elif source.source_type == 'sherlock':
            platform_events = self._create_platform_events(source, base_timestamp)
            events.extend(platform_events)

        else:
            # Generic event
            event = {
                'timestamp': base_timestamp.isoformat(),
                'type': source.source_type,
                'description': f'Intelligence gathered from {source.source_type}',
                'source': source.source_id,
                'data': source.data
            }
            events.append(event)

        return events

    def _create_breach_event(self, source: Any, timestamp: datetime) -> Optional[Dict[str, Any]]:
        """Create event from data breach source"""
        data = source.data

        breach_name = data.get('breach') or data.get('source') or 'Unknown Breach'

        event = {
            'timestamp': timestamp.isoformat(),
            'type': 'breach',
            'severity': 'high',
            'description': f'Credentials exposed in {breach_name}',
            'source': source.source_id,
            'details': {
                'breach_name': breach_name,
                'exposed_data': []
            }
        }

        # Track what was exposed
        exposed = []
        if 'email' in data:
            exposed.append('email')
        if 'password' in data or 'password_hash' in data:
            exposed.append('password')
        if 'phone' in data:
            exposed.append('phone')
        if 'name' in data:
            exposed.append('name')

        event['details']['exposed_data'] = exposed

        return event

    def _create_blockchain_events(self, source: Any, timestamp: datetime) -> List[Dict[str, Any]]:
        """Create events from blockchain data"""
        events = []
        data = source.data

        # Wallet creation/first seen
        if 'wallet' in data or 'address' in data:
            wallet = data.get('wallet') or data.get('address')
            events.append({
                'timestamp': timestamp.isoformat(),
                'type': 'blockchain',
                'description': f'Cryptocurrency wallet identified: {wallet[:10]}...',
                'source': source.source_id,
                'details': {
                    'wallet': wallet,
                    'blockchain': data.get('blockchain', 'Unknown')
                }
            })

        # Transaction activity
        if 'transactions' in data:
            tx_count = data['transactions']
            events.append({
                'timestamp': timestamp.isoformat(),
                'type': 'blockchain',
                'description': f'{tx_count} blockchain transactions recorded',
                'source': source.source_id,
                'details': {
                    'transaction_count': tx_count,
                    'volume': data.get('total_volume', 'Unknown')
                }
            })

        return events

    def _create_social_events(self, source: Any, timestamp: datetime) -> List[Dict[str, Any]]:
        """Create events from social media intelligence"""
        events = []
        data = source.data

        # Account creation
        if 'joined_date' in data or 'created_at' in data:
            join_date = data.get('joined_date') or data.get('created_at')
            events.append({
                'timestamp': join_date if isinstance(join_date, str) else timestamp.isoformat(),
                'type': 'social_media',
                'description': f'Social media account created on {data.get("platform", "platform")}',
                'source': source.source_id,
                'details': {
                    'platform': data.get('platform', 'Unknown'),
                    'username': data.get('username', '')
                }
            })

        # Posts/activity
        if 'posts' in data or 'tweets' in data:
            post_count = data.get('posts') or data.get('tweets')
            events.append({
                'timestamp': timestamp.isoformat(),
                'type': 'social_media',
                'description': f'{post_count} social media posts analyzed',
                'source': source.source_id,
                'details': {
                    'post_count': post_count,
                    'platform': data.get('platform', 'Unknown')
                }
            })

        return events

    def _create_platform_events(self, source: Any, timestamp: datetime) -> List[Dict[str, Any]]:
        """Create events from Sherlock platform detection"""
        events = []
        data = source.data

        platforms = data.get('platforms', [])
        if isinstance(platforms, list):
            for platform in platforms:
                events.append({
                    'timestamp': timestamp.isoformat(),
                    'type': 'platform_presence',
                    'description': f'Account found on {platform}',
                    'source': source.source_id,
                    'details': {
                        'platform': platform,
                        'username': data.get('username', '')
                    }
                })

        return events

    def _sort_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort events chronologically"""
        def parse_timestamp(event):
            try:
                ts = event.get('timestamp', '')
                if isinstance(ts, datetime):
                    return ts
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except Exception:
                return datetime.min

        return sorted(events, key=parse_timestamp)

    def _deduplicate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate or very similar events"""
        if not events:
            return []

        deduplicated = []
        seen_signatures = set()

        for event in events:
            # Create signature from key attributes
            signature = self._create_event_signature(event)

            if signature not in seen_signatures:
                seen_signatures.add(signature)
                deduplicated.append(event)

        return deduplicated

    def _create_event_signature(self, event: Dict[str, Any]) -> str:
        """Create unique signature for event deduplication"""
        import hashlib

        # Use timestamp, type, and description
        sig_parts = [
            event.get('timestamp', '')[:10],  # Date only
            event.get('type', ''),
            event.get('description', '')[:50]  # First 50 chars
        ]

        signature = '|'.join(sig_parts)
        return hashlib.md5(signature.encode()).hexdigest()

    def _identify_gaps(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify and annotate significant gaps in timeline"""
        if len(events) < 2:
            return events

        enhanced_events = []
        max_gap = timedelta(days=self.max_gap_days)

        for i, event in enumerate(events):
            enhanced_events.append(event)

            # Check gap to next event
            if i < len(events) - 1:
                current_time = self._parse_timestamp(event['timestamp'])
                next_time = self._parse_timestamp(events[i + 1]['timestamp'])

                gap = next_time - current_time

                if gap > max_gap:
                    # Insert gap marker
                    gap_event = {
                        'timestamp': current_time.isoformat(),
                        'type': 'gap',
                        'description': f'Timeline gap: {gap.days} days of no recorded activity',
                        'is_metadata': True,
                        'gap_days': gap.days
                    }
                    enhanced_events.append(gap_event)

        return enhanced_events

    def _extract_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract behavioral patterns from timeline"""
        patterns = []

        if len(events) < self.min_events:
            return patterns

        # Pattern 1: Activity bursts
        burst_pattern = self._detect_activity_bursts(events)
        if burst_pattern:
            patterns.append(burst_pattern)

        # Pattern 2: Cyclic behavior
        cyclic_pattern = self._detect_cyclic_behavior(events)
        if cyclic_pattern:
            patterns.append(cyclic_pattern)

        # Pattern 3: Progressive escalation
        escalation_pattern = self._detect_escalation(events)
        if escalation_pattern:
            patterns.append(escalation_pattern)

        # Pattern 4: Account creation spree
        creation_pattern = self._detect_creation_spree(events)
        if creation_pattern:
            patterns.append(creation_pattern)

        return patterns

    def _detect_activity_bursts(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Detect sudden bursts of activity"""
        # Group events by month
        monthly_counts = defaultdict(int)

        for event in events:
            if event.get('is_metadata'):
                continue

            timestamp = self._parse_timestamp(event.get('timestamp', ''))
            month_key = timestamp.strftime('%Y-%m')
            monthly_counts[month_key] += 1

        if not monthly_counts:
            return None

        # Find bursts (>2x average)
        avg_activity = sum(monthly_counts.values()) / len(monthly_counts)
        bursts = [
            (month, count)
            for month, count in monthly_counts.items()
            if count > avg_activity * 2
        ]

        if bursts:
            return {
                'type': 'activity_burst',
                'description': f'Detected {len(bursts)} period(s) of unusually high activity',
                'details': {
                    'burst_periods': [month for month, _ in bursts],
                    'average_activity': round(avg_activity, 2)
                }
            }

        return None

    def _detect_cyclic_behavior(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Detect repeating patterns in timing"""
        # Look for events of same type at regular intervals
        type_timestamps = defaultdict(list)

        for event in events:
            if event.get('is_metadata'):
                continue

            event_type = event.get('type', '')
            timestamp = self._parse_timestamp(event.get('timestamp', ''))
            type_timestamps[event_type].append(timestamp)

        # Check for regular intervals
        for event_type, timestamps in type_timestamps.items():
            if len(timestamps) >= 3:
                timestamps.sort()

                # Calculate intervals
                intervals = [
                    (timestamps[i + 1] - timestamps[i]).days
                    for i in range(len(timestamps) - 1)
                ]

                # Check if intervals are similar (±20%)
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    if all(abs(interval - avg_interval) / avg_interval <= 0.2 for interval in intervals):
                        return {
                            'type': 'cyclic_behavior',
                            'description': f'Recurring {event_type} activity every ~{int(avg_interval)} days',
                            'details': {
                                'event_type': event_type,
                                'interval_days': int(avg_interval),
                                'occurrences': len(timestamps)
                            }
                        }

        return None

    def _detect_escalation(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Detect progressive escalation in activity severity"""
        # Map event types to severity levels
        severity_map = {
            'platform_presence': 1,
            'social_media': 2,
            'breach': 3,
            'blockchain': 4
        }

        severity_timeline = []
        for event in events:
            if event.get('is_metadata'):
                continue

            event_type = event.get('type', '')
            severity = event.get('severity', severity_map.get(event_type, 2))

            # Convert severity to numeric
            if severity == 'low':
                severity = 1
            elif severity == 'medium':
                severity = 2
            elif severity == 'high':
                severity = 3
            elif not isinstance(severity, int):
                severity = severity_map.get(event_type, 2)

            timestamp = self._parse_timestamp(event.get('timestamp', ''))
            severity_timeline.append((timestamp, severity))

        if len(severity_timeline) >= 3:
            severity_timeline.sort()

            # Check for increasing trend
            increasing = sum(
                1 for i in range(len(severity_timeline) - 1)
                if severity_timeline[i + 1][1] >= severity_timeline[i][1]
            )

            escalation_ratio = increasing / (len(severity_timeline) - 1)

            if escalation_ratio >= 0.7:  # 70% increasing
                return {
                    'type': 'escalation',
                    'description': 'Progressive escalation in activity severity detected',
                    'details': {
                        'escalation_ratio': round(escalation_ratio, 2),
                        'start_severity': severity_timeline[0][1],
                        'current_severity': severity_timeline[-1][1]
                    }
                }

        return None

    def _detect_creation_spree(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Detect rapid account/platform creation"""
        creation_events = [
            event for event in events
            if 'creat' in event.get('description', '').lower() or
               'joined' in event.get('description', '').lower() or
               event.get('type') == 'platform_presence'
        ]

        if len(creation_events) >= 3:
            timestamps = [
                self._parse_timestamp(e.get('timestamp', ''))
                for e in creation_events
            ]
            timestamps.sort()

            # Check if all within 30 days
            time_span = (timestamps[-1] - timestamps[0]).days

            if time_span <= 30:
                return {
                    'type': 'creation_spree',
                    'description': f'{len(creation_events)} accounts created within {time_span} days',
                    'details': {
                        'account_count': len(creation_events),
                        'time_span_days': time_span,
                        'rate_per_day': round(len(creation_events) / max(time_span, 1), 2)
                    }
                }

        return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime"""
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return datetime.now()

    def export_timeline(self, events: List[Dict[str, Any]],
                       output_path: str, format: str = 'json'):
        """
        Export timeline to file

        Args:
            events: Timeline events
            output_path: Output file path
            format: Export format (json, csv, html)
        """
        import json

        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(events, f, indent=2, default=str)

        elif format == 'csv':
            import csv
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'description'])
                writer.writeheader()
                for event in events:
                    writer.writerow({
                        'timestamp': event.get('timestamp', ''),
                        'type': event.get('type', ''),
                        'description': event.get('description', '')
                    })

        elif format == 'html':
            self._export_timeline_html(events, output_path)

    def _export_timeline_html(self, events: List[Dict[str, Any]], output_path: str):
        """Export timeline as interactive HTML"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Timeline</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .timeline { position: relative; padding: 20px 0; }
        .event { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #333; }
        .event.breach { border-left-color: #d32f2f; }
        .event.blockchain { border-left-color: #1976d2; }
        .event.social_media { border-left-color: #388e3c; }
        .event.gap { border-left-color: #ffa000; background: #fff3e0; }
        .timestamp { color: #666; font-size: 0.9em; }
        .description { margin: 5px 0; }
        .details { font-size: 0.85em; color: #555; }
    </style>
</head>
<body>
    <h1>Intelligence Timeline</h1>
    <div class="timeline">
"""
        for event in events:
            event_type = event.get('type', 'unknown')
            html += f"""
        <div class="event {event_type}">
            <div class="timestamp">{event.get('timestamp', 'Unknown')}</div>
            <div class="description"><strong>{event.get('description', 'N/A')}</strong></div>
            <div class="details">Type: {event_type}</div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        with open(output_path, 'w') as f:
            f.write(html)
