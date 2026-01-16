"""
TimescaleDB Location Store - Time-Series Location Data Storage
Apollo Platform - GEOINT Transportation Tracking

Provides efficient time-series storage and querying for location data
using TimescaleDB's hypertable capabilities.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
import json
from enum import Enum
import os

# Database drivers (async)
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LocationRecord:
    """Location record for database storage"""
    device_id: str
    latitude: float
    longitude: float
    altitude: float = 0.0
    speed: float = 0.0
    heading: float = 0.0
    accuracy: float = 10.0
    battery_level: int = 100
    signal_strength: int = 100
    timestamp: datetime = field(default_factory=datetime.now)
    case_id: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class GeofenceRecord:
    """Geofence zone record"""
    geofence_id: str
    name: str
    center_latitude: float
    center_longitude: float
    radius_meters: float
    case_id: Optional[str] = None
    priority: str = "medium"
    active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class AlertRecord:
    """Alert record"""
    alert_id: str
    geofence_id: str
    device_id: str
    event_type: str
    latitude: float
    longitude: float
    priority: str
    acknowledged: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


class TimescaleLocationStore:
    """
    TimescaleDB-backed location storage

    Provides efficient time-series storage with:
    - Hypertables for location data
    - Automatic data retention policies
    - Continuous aggregates for analytics
    - Efficient time-range queries
    """

    # SQL Schema definitions
    SCHEMA_SQL = """
    -- Enable TimescaleDB extension
    CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
    CREATE EXTENSION IF NOT EXISTS postgis CASCADE;

    -- Tracking Devices table
    CREATE TABLE IF NOT EXISTS tracking_devices (
        device_id VARCHAR(100) PRIMARY KEY,
        device_name VARCHAR(255) NOT NULL,
        target_description TEXT,
        case_id VARCHAR(100),
        authorization VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_update TIMESTAMPTZ,
        battery_level INTEGER DEFAULT 100,
        warrant_expiration TIMESTAMPTZ,
        authorized_by VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        CONSTRAINT valid_battery CHECK (battery_level >= 0 AND battery_level <= 100)
    );

    -- Location history table (will be converted to hypertable)
    CREATE TABLE IF NOT EXISTS location_history (
        time TIMESTAMPTZ NOT NULL,
        device_id VARCHAR(100) NOT NULL REFERENCES tracking_devices(device_id),
        latitude DOUBLE PRECISION NOT NULL,
        longitude DOUBLE PRECISION NOT NULL,
        altitude DOUBLE PRECISION DEFAULT 0,
        speed DOUBLE PRECISION DEFAULT 0,
        heading DOUBLE PRECISION DEFAULT 0,
        accuracy DOUBLE PRECISION DEFAULT 10,
        battery_level INTEGER DEFAULT 100,
        signal_strength INTEGER DEFAULT 100,
        case_id VARCHAR(100),
        metadata JSONB DEFAULT '{}',
        CONSTRAINT valid_coordinates CHECK (
            latitude >= -90 AND latitude <= 90 AND
            longitude >= -180 AND longitude <= 180
        )
    );

    -- Convert to hypertable (if not already)
    SELECT create_hypertable('location_history', 'time',
        if_not_exists => TRUE,
        chunk_time_interval => INTERVAL '1 day'
    );

    -- Geofence zones table
    CREATE TABLE IF NOT EXISTS geofence_zones (
        geofence_id VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        center_latitude DOUBLE PRECISION NOT NULL,
        center_longitude DOUBLE PRECISION NOT NULL,
        radius_meters DOUBLE PRECISION NOT NULL,
        case_id VARCHAR(100),
        priority VARCHAR(50) DEFAULT 'medium',
        alert_on TEXT[] DEFAULT ARRAY['entry'],
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB DEFAULT '{}'
    );

    -- Geofence alerts table (hypertable for time-series alerts)
    CREATE TABLE IF NOT EXISTS geofence_alerts (
        time TIMESTAMPTZ NOT NULL,
        alert_id VARCHAR(100) NOT NULL,
        geofence_id VARCHAR(100) REFERENCES geofence_zones(geofence_id),
        device_id VARCHAR(100) REFERENCES tracking_devices(device_id),
        event_type VARCHAR(50) NOT NULL,
        latitude DOUBLE PRECISION NOT NULL,
        longitude DOUBLE PRECISION NOT NULL,
        priority VARCHAR(50) DEFAULT 'medium',
        acknowledged BOOLEAN DEFAULT FALSE,
        metadata JSONB DEFAULT '{}'
    );

    SELECT create_hypertable('geofence_alerts', 'time',
        if_not_exists => TRUE,
        chunk_time_interval => INTERVAL '7 days'
    );

    -- Movement patterns table (aggregated analysis results)
    CREATE TABLE IF NOT EXISTS movement_patterns (
        pattern_id VARCHAR(100) PRIMARY KEY,
        device_id VARCHAR(100) REFERENCES tracking_devices(device_id),
        analysis_period VARCHAR(100),
        frequent_locations JSONB DEFAULT '[]',
        travel_patterns JSONB DEFAULT '[]',
        home_location JSONB,
        work_location JSONB,
        suspicious_activities JSONB DEFAULT '[]',
        predicted_locations JSONB DEFAULT '[]',
        average_daily_distance_km DOUBLE PRECISION DEFAULT 0,
        confidence_score DOUBLE PRECISION DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    -- Indexes for efficient querying
    CREATE INDEX IF NOT EXISTS idx_location_device_time
        ON location_history (device_id, time DESC);
    CREATE INDEX IF NOT EXISTS idx_location_case
        ON location_history (case_id, time DESC);
    CREATE INDEX IF NOT EXISTS idx_geofence_case
        ON geofence_zones (case_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_device
        ON geofence_alerts (device_id, time DESC);
    CREATE INDEX IF NOT EXISTS idx_alerts_geofence
        ON geofence_alerts (geofence_id, time DESC);
    CREATE INDEX IF NOT EXISTS idx_alerts_unacknowledged
        ON geofence_alerts (acknowledged, time DESC) WHERE acknowledged = FALSE;

    -- Spatial index for location queries (if PostGIS is available)
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
            EXECUTE 'CREATE INDEX IF NOT EXISTS idx_location_geom
                ON location_history USING GIST (
                    ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)
                )';
        END IF;
    END $$;

    -- Continuous aggregate for hourly location summaries
    CREATE MATERIALIZED VIEW IF NOT EXISTS location_hourly_summary
    WITH (timescaledb.continuous) AS
    SELECT
        time_bucket('1 hour', time) AS bucket,
        device_id,
        AVG(latitude) as avg_latitude,
        AVG(longitude) as avg_longitude,
        AVG(speed) as avg_speed,
        MAX(speed) as max_speed,
        COUNT(*) as point_count,
        AVG(battery_level) as avg_battery
    FROM location_history
    GROUP BY bucket, device_id
    WITH NO DATA;

    -- Data retention policy - keep detailed data for 90 days
    SELECT add_retention_policy('location_history', INTERVAL '90 days', if_not_exists => TRUE);
    SELECT add_retention_policy('geofence_alerts', INTERVAL '365 days', if_not_exists => TRUE);

    -- Refresh policy for continuous aggregates
    SELECT add_continuous_aggregate_policy('location_hourly_summary',
        start_offset => INTERVAL '3 hours',
        end_offset => INTERVAL '1 hour',
        schedule_interval => INTERVAL '1 hour',
        if_not_exists => TRUE
    );
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize TimescaleDB location store

        Args:
            config: Database configuration
        """
        self.config = config or self._default_config()
        self._pool = None
        self._sync_conn = None

        logger.info("TimescaleLocationStore initialized")

    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'host': os.getenv('TIMESCALE_HOST', 'localhost'),
            'port': int(os.getenv('TIMESCALE_PORT', 5432)),
            'database': os.getenv('TIMESCALE_DATABASE', 'apollo_geoint'),
            'user': os.getenv('TIMESCALE_USER', 'apollo'),
            'password': os.getenv('TIMESCALE_PASSWORD', 'apollo_secure_password'),
            'min_connections': 5,
            'max_connections': 20,
            'ssl': os.getenv('TIMESCALE_SSL', 'prefer')
        }

    # ==================== Connection Management ====================

    async def connect(self):
        """Establish async connection pool"""
        if not HAS_ASYNCPG:
            raise ImportError("asyncpg is required for async operations")

        self._pool = await asyncpg.create_pool(
            host=self.config['host'],
            port=self.config['port'],
            database=self.config['database'],
            user=self.config['user'],
            password=self.config['password'],
            min_size=self.config['min_connections'],
            max_size=self.config['max_connections'],
            ssl=self.config['ssl']
        )
        logger.info("Connected to TimescaleDB")

    async def disconnect(self):
        """Close connection pool"""
        if self._pool:
            await self._pool.close()
            self._pool = None

    def connect_sync(self):
        """Establish synchronous connection"""
        if not HAS_PSYCOPG2:
            raise ImportError("psycopg2 is required for sync operations")

        self._sync_conn = psycopg2.connect(
            host=self.config['host'],
            port=self.config['port'],
            database=self.config['database'],
            user=self.config['user'],
            password=self.config['password']
        )
        logger.info("Connected to TimescaleDB (sync)")

    def disconnect_sync(self):
        """Close synchronous connection"""
        if self._sync_conn:
            self._sync_conn.close()
            self._sync_conn = None

    async def initialize_schema(self):
        """Initialize database schema"""
        async with self._pool.acquire() as conn:
            await conn.execute(self.SCHEMA_SQL)
            logger.info("Database schema initialized")

    def initialize_schema_sync(self):
        """Initialize schema synchronously"""
        with self._sync_conn.cursor() as cur:
            cur.execute(self.SCHEMA_SQL)
            self._sync_conn.commit()
            logger.info("Database schema initialized (sync)")

    # ==================== Device Operations ====================

    async def register_device(self, device: Dict) -> str:
        """Register a tracking device"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO tracking_devices (
                    device_id, device_name, target_description, case_id,
                    authorization, status, warrant_expiration, authorized_by, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (device_id) DO UPDATE SET
                    device_name = EXCLUDED.device_name,
                    status = EXCLUDED.status
            """,
                device['device_id'],
                device['device_name'],
                device.get('target_description'),
                device.get('case_id'),
                device['authorization'],
                device.get('status', 'active'),
                device.get('warrant_expiration'),
                device.get('authorized_by'),
                json.dumps(device.get('metadata', {}))
            )

        return device['device_id']

    async def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device by ID"""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM tracking_devices WHERE device_id = $1
            """, device_id)

        if row:
            return dict(row)
        return None

    async def get_devices_by_case(self, case_id: str) -> List[Dict]:
        """Get all devices for a case"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM tracking_devices WHERE case_id = $1
            """, case_id)

        return [dict(row) for row in rows]

    async def update_device_status(self, device_id: str, status: str,
                                  battery_level: Optional[int] = None):
        """Update device status"""
        async with self._pool.acquire() as conn:
            if battery_level is not None:
                await conn.execute("""
                    UPDATE tracking_devices
                    SET status = $2, battery_level = $3, last_update = NOW()
                    WHERE device_id = $1
                """, device_id, status, battery_level)
            else:
                await conn.execute("""
                    UPDATE tracking_devices
                    SET status = $2, last_update = NOW()
                    WHERE device_id = $1
                """, device_id, status)

    # ==================== Location Operations ====================

    async def insert_location(self, location: LocationRecord) -> bool:
        """Insert a single location record"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO location_history (
                    time, device_id, latitude, longitude, altitude,
                    speed, heading, accuracy, battery_level, signal_strength,
                    case_id, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """,
                location.timestamp,
                location.device_id,
                location.latitude,
                location.longitude,
                location.altitude,
                location.speed,
                location.heading,
                location.accuracy,
                location.battery_level,
                location.signal_strength,
                location.case_id,
                json.dumps(location.metadata)
            )

        return True

    async def insert_locations_batch(self, locations: List[LocationRecord]) -> int:
        """Batch insert location records"""
        if not locations:
            return 0

        async with self._pool.acquire() as conn:
            records = [
                (
                    loc.timestamp, loc.device_id, loc.latitude, loc.longitude,
                    loc.altitude, loc.speed, loc.heading, loc.accuracy,
                    loc.battery_level, loc.signal_strength, loc.case_id,
                    json.dumps(loc.metadata)
                )
                for loc in locations
            ]

            await conn.executemany("""
                INSERT INTO location_history (
                    time, device_id, latitude, longitude, altitude,
                    speed, heading, accuracy, battery_level, signal_strength,
                    case_id, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """, records)

        return len(locations)

    async def get_location_history(self,
                                   device_id: str,
                                   start_time: Optional[datetime] = None,
                                   end_time: Optional[datetime] = None,
                                   limit: int = 1000) -> List[Dict]:
        """
        Get location history for a device

        Args:
            device_id: Device ID
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum records to return

        Returns:
            List of location records
        """
        query = """
            SELECT * FROM location_history
            WHERE device_id = $1
        """
        params = [device_id]

        if start_time:
            query += " AND time >= $" + str(len(params) + 1)
            params.append(start_time)

        if end_time:
            query += " AND time <= $" + str(len(params) + 1)
            params.append(end_time)

        query += f" ORDER BY time DESC LIMIT {limit}"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [dict(row) for row in rows]

    async def get_latest_location(self, device_id: str) -> Optional[Dict]:
        """Get most recent location for a device"""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM location_history
                WHERE device_id = $1
                ORDER BY time DESC
                LIMIT 1
            """, device_id)

        return dict(row) if row else None

    async def get_locations_in_area(self,
                                    min_lat: float, max_lat: float,
                                    min_lon: float, max_lon: float,
                                    start_time: Optional[datetime] = None,
                                    end_time: Optional[datetime] = None,
                                    limit: int = 1000) -> List[Dict]:
        """
        Get all locations within a bounding box

        Args:
            min_lat, max_lat: Latitude bounds
            min_lon, max_lon: Longitude bounds
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum records

        Returns:
            List of location records
        """
        query = """
            SELECT * FROM location_history
            WHERE latitude BETWEEN $1 AND $2
            AND longitude BETWEEN $3 AND $4
        """
        params = [min_lat, max_lat, min_lon, max_lon]

        if start_time:
            query += " AND time >= $5"
            params.append(start_time)
            if end_time:
                query += " AND time <= $6"
                params.append(end_time)
        elif end_time:
            query += " AND time <= $5"
            params.append(end_time)

        query += f" ORDER BY time DESC LIMIT {limit}"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [dict(row) for row in rows]

    async def get_hourly_summary(self,
                                device_id: str,
                                start_time: datetime,
                                end_time: datetime) -> List[Dict]:
        """Get hourly location summary from continuous aggregate"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM location_hourly_summary
                WHERE device_id = $1
                AND bucket BETWEEN $2 AND $3
                ORDER BY bucket DESC
            """, device_id, start_time, end_time)

        return [dict(row) for row in rows]

    # ==================== Geofence Operations ====================

    async def create_geofence(self, geofence: GeofenceRecord) -> str:
        """Create a geofence zone"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO geofence_zones (
                    geofence_id, name, center_latitude, center_longitude,
                    radius_meters, case_id, priority, active, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
                geofence.geofence_id,
                geofence.name,
                geofence.center_latitude,
                geofence.center_longitude,
                geofence.radius_meters,
                geofence.case_id,
                geofence.priority,
                geofence.active,
                json.dumps(geofence.metadata)
            )

        return geofence.geofence_id

    async def get_geofence(self, geofence_id: str) -> Optional[Dict]:
        """Get geofence by ID"""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM geofence_zones WHERE geofence_id = $1
            """, geofence_id)

        return dict(row) if row else None

    async def get_geofences_by_case(self, case_id: str) -> List[Dict]:
        """Get all geofences for a case"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM geofence_zones WHERE case_id = $1 AND active = TRUE
            """, case_id)

        return [dict(row) for row in rows]

    async def update_geofence(self, geofence_id: str, updates: Dict) -> bool:
        """Update geofence properties"""
        set_clauses = []
        params = [geofence_id]

        for key, value in updates.items():
            if key in ['name', 'center_latitude', 'center_longitude',
                      'radius_meters', 'priority', 'active']:
                params.append(value)
                set_clauses.append(f"{key} = ${len(params)}")

        if not set_clauses:
            return False

        query = f"UPDATE geofence_zones SET {', '.join(set_clauses)} WHERE geofence_id = $1"

        async with self._pool.acquire() as conn:
            await conn.execute(query, *params)

        return True

    async def delete_geofence(self, geofence_id: str) -> bool:
        """Delete a geofence (soft delete by deactivating)"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                UPDATE geofence_zones SET active = FALSE WHERE geofence_id = $1
            """, geofence_id)

        return True

    # ==================== Alert Operations ====================

    async def insert_alert(self, alert: AlertRecord) -> str:
        """Insert a geofence alert"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO geofence_alerts (
                    time, alert_id, geofence_id, device_id, event_type,
                    latitude, longitude, priority, acknowledged, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
                alert.timestamp,
                alert.alert_id,
                alert.geofence_id,
                alert.device_id,
                alert.event_type,
                alert.latitude,
                alert.longitude,
                alert.priority,
                alert.acknowledged,
                json.dumps(alert.metadata)
            )

        return alert.alert_id

    async def get_alerts(self,
                        device_id: Optional[str] = None,
                        geofence_id: Optional[str] = None,
                        acknowledged: Optional[bool] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None,
                        limit: int = 100) -> List[Dict]:
        """Get alerts with optional filters"""
        query = "SELECT * FROM geofence_alerts WHERE 1=1"
        params = []

        if device_id:
            params.append(device_id)
            query += f" AND device_id = ${len(params)}"

        if geofence_id:
            params.append(geofence_id)
            query += f" AND geofence_id = ${len(params)}"

        if acknowledged is not None:
            params.append(acknowledged)
            query += f" AND acknowledged = ${len(params)}"

        if start_time:
            params.append(start_time)
            query += f" AND time >= ${len(params)}"

        if end_time:
            params.append(end_time)
            query += f" AND time <= ${len(params)}"

        query += f" ORDER BY time DESC LIMIT {limit}"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [dict(row) for row in rows]

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        async with self._pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE geofence_alerts SET acknowledged = TRUE
                WHERE alert_id = $1
            """, alert_id)

        return True

    async def get_unacknowledged_alerts_count(self,
                                              device_id: Optional[str] = None) -> int:
        """Get count of unacknowledged alerts"""
        query = "SELECT COUNT(*) FROM geofence_alerts WHERE acknowledged = FALSE"
        params = []

        if device_id:
            params.append(device_id)
            query += f" AND device_id = ${len(params)}"

        async with self._pool.acquire() as conn:
            count = await conn.fetchval(query, *params)

        return count

    # ==================== Analytics Queries ====================

    async def get_movement_statistics(self,
                                     device_id: str,
                                     start_time: datetime,
                                     end_time: datetime) -> Dict:
        """Get movement statistics for a device"""
        async with self._pool.acquire() as conn:
            stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_points,
                    AVG(speed) as avg_speed,
                    MAX(speed) as max_speed,
                    AVG(accuracy) as avg_accuracy,
                    MIN(battery_level) as min_battery,
                    AVG(battery_level) as avg_battery,
                    MIN(latitude) as min_lat,
                    MAX(latitude) as max_lat,
                    MIN(longitude) as min_lon,
                    MAX(longitude) as max_lon
                FROM location_history
                WHERE device_id = $1
                AND time BETWEEN $2 AND $3
            """, device_id, start_time, end_time)

            # Calculate total distance
            distance = await conn.fetchval("""
                WITH ordered_points AS (
                    SELECT
                        latitude, longitude,
                        LAG(latitude) OVER (ORDER BY time) as prev_lat,
                        LAG(longitude) OVER (ORDER BY time) as prev_lon
                    FROM location_history
                    WHERE device_id = $1
                    AND time BETWEEN $2 AND $3
                )
                SELECT SUM(
                    6371000 * 2 * ASIN(SQRT(
                        POWER(SIN(RADIANS(latitude - prev_lat) / 2), 2) +
                        COS(RADIANS(prev_lat)) * COS(RADIANS(latitude)) *
                        POWER(SIN(RADIANS(longitude - prev_lon) / 2), 2)
                    ))
                ) as total_distance_meters
                FROM ordered_points
                WHERE prev_lat IS NOT NULL
            """, device_id, start_time, end_time)

        return {
            **dict(stats),
            'total_distance_meters': distance or 0,
            'total_distance_km': (distance or 0) / 1000,
            'time_span_hours': (end_time - start_time).total_seconds() / 3600
        }

    async def get_frequent_locations(self,
                                    device_id: str,
                                    start_time: datetime,
                                    end_time: datetime,
                                    grid_size: float = 0.001,
                                    min_count: int = 5) -> List[Dict]:
        """Find frequently visited locations using grid clustering"""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    ROUND(latitude / $4) * $4 as cluster_lat,
                    ROUND(longitude / $4) * $4 as cluster_lon,
                    COUNT(*) as visit_count,
                    AVG(speed) as avg_speed_at_location,
                    MIN(time) as first_visit,
                    MAX(time) as last_visit
                FROM location_history
                WHERE device_id = $1
                AND time BETWEEN $2 AND $3
                GROUP BY cluster_lat, cluster_lon
                HAVING COUNT(*) >= $5
                ORDER BY visit_count DESC
                LIMIT 20
            """, device_id, start_time, end_time, grid_size, min_count)

        return [dict(row) for row in rows]

    async def get_time_at_location(self,
                                  device_id: str,
                                  latitude: float,
                                  longitude: float,
                                  radius_meters: float,
                                  start_time: datetime,
                                  end_time: datetime) -> Dict:
        """Calculate time spent at a specific location"""
        # Approximate degree distance for the radius
        lat_deg = radius_meters / 111320
        lon_deg = radius_meters / (111320 * abs(3.14159 / 180 * latitude))

        async with self._pool.acquire() as conn:
            result = await conn.fetchrow("""
                WITH in_zone AS (
                    SELECT time,
                           LAG(time) OVER (ORDER BY time) as prev_time
                    FROM location_history
                    WHERE device_id = $1
                    AND time BETWEEN $2 AND $3
                    AND latitude BETWEEN $4 - $6 AND $4 + $6
                    AND longitude BETWEEN $5 - $7 AND $5 + $7
                )
                SELECT
                    COUNT(*) as points_in_zone,
                    SUM(EXTRACT(EPOCH FROM (time - prev_time))) as total_seconds
                FROM in_zone
                WHERE prev_time IS NOT NULL
                AND EXTRACT(EPOCH FROM (time - prev_time)) < 600
            """, device_id, start_time, end_time, latitude, longitude, lat_deg, lon_deg)

        return {
            'points_in_zone': result['points_in_zone'] or 0,
            'total_time_seconds': result['total_seconds'] or 0,
            'total_time_minutes': (result['total_seconds'] or 0) / 60,
            'total_time_hours': (result['total_seconds'] or 0) / 3600
        }

    # ==================== Pattern Storage ====================

    async def save_movement_pattern(self, pattern: Dict) -> str:
        """Save analyzed movement pattern"""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO movement_patterns (
                    pattern_id, device_id, analysis_period,
                    frequent_locations, travel_patterns, home_location,
                    work_location, suspicious_activities, predicted_locations,
                    average_daily_distance_km, confidence_score
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (pattern_id) DO UPDATE SET
                    frequent_locations = EXCLUDED.frequent_locations,
                    travel_patterns = EXCLUDED.travel_patterns,
                    confidence_score = EXCLUDED.confidence_score
            """,
                pattern['pattern_id'],
                pattern['device_id'],
                pattern.get('analysis_period', 'Unknown'),
                json.dumps(pattern.get('frequent_locations', [])),
                json.dumps(pattern.get('travel_patterns', [])),
                json.dumps(pattern.get('home_location')),
                json.dumps(pattern.get('work_location')),
                json.dumps(pattern.get('suspicious_activities', [])),
                json.dumps(pattern.get('predicted_locations', [])),
                pattern.get('average_daily_distance_km', 0),
                pattern.get('confidence_score', 0)
            )

        return pattern['pattern_id']

    async def get_movement_pattern(self, device_id: str) -> Optional[Dict]:
        """Get latest movement pattern for a device"""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM movement_patterns
                WHERE device_id = $1
                ORDER BY created_at DESC
                LIMIT 1
            """, device_id)

        if row:
            result = dict(row)
            # Parse JSON fields
            for field in ['frequent_locations', 'travel_patterns',
                         'home_location', 'work_location',
                         'suspicious_activities', 'predicted_locations']:
                if result.get(field):
                    result[field] = json.loads(result[field]) if isinstance(result[field], str) else result[field]
            return result

        return None


# Factory function
def create_location_store(config: Optional[Dict] = None) -> TimescaleLocationStore:
    """Create a TimescaleLocationStore instance"""
    return TimescaleLocationStore(config)


# Example usage and testing
if __name__ == "__main__":
    async def test_store():
        store = TimescaleLocationStore()
        await store.connect()
        await store.initialize_schema()

        # Register a device
        await store.register_device({
            'device_id': 'TEST-DEVICE-001',
            'device_name': 'Test Tracker',
            'authorization': 'TEST-WARRANT-001',
            'case_id': 'TEST-CASE-001'
        })

        # Insert location
        location = LocationRecord(
            device_id='TEST-DEVICE-001',
            latitude=40.7128,
            longitude=-74.0060,
            speed=25.5,
            case_id='TEST-CASE-001'
        )
        await store.insert_location(location)

        # Query locations
        history = await store.get_location_history('TEST-DEVICE-001', limit=10)
        print(f"Location history: {len(history)} records")

        await store.disconnect()

    asyncio.run(test_store())
