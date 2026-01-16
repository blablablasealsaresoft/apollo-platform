-- Apollo Platform - TimescaleDB Time-Series Schemas
-- Optimized for: Blockchain transactions, surveillance events, communication logs

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================================================
-- BLOCKCHAIN TRANSACTIONS (Time-Series)
-- ============================================================================

CREATE TABLE blockchain_transactions (
    time TIMESTAMPTZ NOT NULL,

    -- Transaction Identity
    tx_hash VARCHAR(128) NOT NULL,
    blockchain VARCHAR(50) NOT NULL, -- bitcoin, ethereum, litecoin, etc.
    block_number BIGINT,
    block_hash VARCHAR(128),

    -- Transaction Details
    from_address VARCHAR(128) NOT NULL,
    to_address VARCHAR(128) NOT NULL,
    amount DECIMAL(36,18) NOT NULL, -- Support for very large and precise values
    fee DECIMAL(36,18),
    gas_used BIGINT, -- For Ethereum
    gas_price DECIMAL(36,18), -- For Ethereum

    -- Fiat Conversion
    usd_value DECIMAL(18,2),
    eur_value DECIMAL(18,2),
    exchange_rate DECIMAL(18,8),
    exchange_rate_source VARCHAR(100),

    -- Investigation Links
    investigation_id UUID,
    target_id UUID,
    is_flagged BOOLEAN DEFAULT false,
    flag_reason TEXT,

    -- Analysis
    is_mixer BOOLEAN DEFAULT false, -- Transaction through mixing service
    is_exchange BOOLEAN DEFAULT false, -- Transaction to/from exchange
    exchange_name VARCHAR(200),
    risk_score DECIMAL(5,4), -- 0.0000 to 1.0000

    -- Wallet clustering
    from_wallet_cluster UUID,
    to_wallet_cluster UUID,

    -- Transaction pattern
    tx_type VARCHAR(50), -- deposit, withdrawal, transfer, contract_call
    is_suspicious BOOLEAN DEFAULT false,
    suspicious_patterns TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Processing
    processed BOOLEAN DEFAULT false,
    processed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable (TimescaleDB-specific)
SELECT create_hypertable('blockchain_transactions', 'time',
    chunk_time_interval => INTERVAL '1 week',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_btx_hash ON blockchain_transactions (tx_hash, blockchain);
CREATE INDEX idx_btx_from ON blockchain_transactions (from_address, time DESC);
CREATE INDEX idx_btx_to ON blockchain_transactions (to_address, time DESC);
CREATE INDEX idx_btx_blockchain ON blockchain_transactions (blockchain, time DESC);
CREATE INDEX idx_btx_investigation ON blockchain_transactions (investigation_id, time DESC);
CREATE INDEX idx_btx_target ON blockchain_transactions (target_id, time DESC);
CREATE INDEX idx_btx_flagged ON blockchain_transactions (is_flagged, time DESC) WHERE is_flagged = true;
CREATE INDEX idx_btx_suspicious ON blockchain_transactions (is_suspicious, time DESC) WHERE is_suspicious = true;
CREATE INDEX idx_btx_amount ON blockchain_transactions (amount DESC, time DESC);
CREATE INDEX idx_btx_tags ON blockchain_transactions USING gin(tags);

-- Continuous aggregate for daily transaction summaries
CREATE MATERIALIZED VIEW blockchain_daily_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS day,
    blockchain,
    COUNT(*) as transaction_count,
    SUM(amount) as total_amount,
    AVG(amount) as avg_amount,
    MAX(amount) as max_amount,
    SUM(usd_value) as total_usd_value,
    COUNT(DISTINCT from_address) as unique_senders,
    COUNT(DISTINCT to_address) as unique_receivers,
    COUNT(*) FILTER (WHERE is_flagged = true) as flagged_count,
    COUNT(*) FILTER (WHERE is_suspicious = true) as suspicious_count,
    COUNT(*) FILTER (WHERE is_mixer = true) as mixer_count,
    COUNT(*) FILTER (WHERE is_exchange = true) as exchange_count
FROM blockchain_transactions
GROUP BY day, blockchain
WITH NO DATA;

-- Refresh policy for continuous aggregate
SELECT add_continuous_aggregate_policy('blockchain_daily_summary',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- ============================================================================
-- SURVEILLANCE EVENTS (Time-Series)
-- ============================================================================

CREATE TABLE surveillance_events (
    time TIMESTAMPTZ NOT NULL,

    -- Event Identity
    event_id UUID DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- face_detected, vehicle_detected, person_detected, etc.

    -- Source
    camera_id VARCHAR(200) NOT NULL,
    camera_name VARCHAR(300),
    location VARCHAR(500) NOT NULL,
    location_coords POINT,
    location_country VARCHAR(100),
    location_city VARCHAR(100),

    -- Detection Details
    detection_system VARCHAR(100), -- facial_recognition, vehicle_recognition, etc.
    confidence DECIMAL(5,4) NOT NULL, -- 0.0000 to 1.0000
    threshold_used DECIMAL(5,4),

    -- Target Matching
    target_id UUID,
    investigation_id UUID,
    is_match BOOLEAN DEFAULT false,
    match_score DECIMAL(5,4),

    -- Face Recognition Specific
    face_encoding JSONB, -- Store face encoding for re-analysis
    face_bbox JSONB, -- Bounding box coordinates
    face_quality_score DECIMAL(5,4),
    age_estimate INTEGER,
    gender_estimate VARCHAR(20),

    -- Vehicle Recognition Specific (if applicable)
    license_plate VARCHAR(50),
    vehicle_make VARCHAR(100),
    vehicle_model VARCHAR(100),
    vehicle_color VARCHAR(50),

    -- Media
    image_url VARCHAR(1000),
    video_url VARCHAR(1000),
    thumbnail_url VARCHAR(1000),
    image_hash VARCHAR(64), -- SHA-256 of image

    -- Alert Status
    alert_generated BOOLEAN DEFAULT false,
    alert_id UUID,
    reviewed BOOLEAN DEFAULT false,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    review_result VARCHAR(50), -- true_positive, false_positive, unknown

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable
SELECT create_hypertable('surveillance_events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_surv_camera ON surveillance_events (camera_id, time DESC);
CREATE INDEX idx_surv_location ON surveillance_events (location_city, time DESC);
CREATE INDEX idx_surv_target ON surveillance_events (target_id, time DESC);
CREATE INDEX idx_surv_investigation ON surveillance_events (investigation_id, time DESC);
CREATE INDEX idx_surv_type ON surveillance_events (event_type, time DESC);
CREATE INDEX idx_surv_match ON surveillance_events (is_match, time DESC) WHERE is_match = true;
CREATE INDEX idx_surv_alert ON surveillance_events (alert_generated, time DESC) WHERE alert_generated = true;
CREATE INDEX idx_surv_confidence ON surveillance_events (confidence DESC, time DESC);
CREATE INDEX idx_surv_location_coords ON surveillance_events USING gist(location_coords);
CREATE INDEX idx_surv_tags ON surveillance_events USING gin(tags);

-- Continuous aggregate for hourly surveillance summary
CREATE MATERIALIZED VIEW surveillance_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS hour,
    camera_id,
    location_city,
    event_type,
    COUNT(*) as event_count,
    AVG(confidence) as avg_confidence,
    COUNT(*) FILTER (WHERE is_match = true) as match_count,
    COUNT(*) FILTER (WHERE alert_generated = true) as alert_count,
    MAX(confidence) as max_confidence,
    COUNT(DISTINCT target_id) as unique_targets
FROM surveillance_events
GROUP BY hour, camera_id, location_city, event_type
WITH NO DATA;

SELECT add_continuous_aggregate_policy('surveillance_hourly_summary',
    start_offset => INTERVAL '2 days',
    end_offset => INTERVAL '10 minutes',
    schedule_interval => INTERVAL '10 minutes'
);

-- ============================================================================
-- COMMUNICATION LOGS (Time-Series)
-- ============================================================================

CREATE TABLE communication_logs (
    time TIMESTAMPTZ NOT NULL,

    -- Communication Identity
    comm_id UUID DEFAULT gen_random_uuid(),
    comm_type VARCHAR(100) NOT NULL, -- call, sms, email, voip, messaging, social_media

    -- Parties
    from_identifier VARCHAR(500) NOT NULL, -- phone, email, username, etc.
    to_identifier VARCHAR(500) NOT NULL,
    from_target_id UUID,
    to_target_id UUID,

    -- Call/Message Details
    duration_seconds INTEGER, -- For calls
    message_preview TEXT, -- First 200 chars of message
    message_hash VARCHAR(64), -- SHA-256 of full message

    -- Metadata
    provider VARCHAR(200), -- carrier, platform, service
    location_from VARCHAR(500),
    location_to VARCHAR(500),
    coords_from POINT,
    coords_to POINT,

    -- Analysis
    is_encrypted BOOLEAN DEFAULT false,
    encryption_type VARCHAR(100),
    is_intercepted BOOLEAN DEFAULT false,
    intercept_method VARCHAR(200),

    -- Content Analysis
    sentiment VARCHAR(50), -- positive, negative, neutral
    topics TEXT[] DEFAULT ARRAY[]::TEXT[],
    keywords_detected TEXT[] DEFAULT ARRAY[]::TEXT[],
    language VARCHAR(50),

    -- Investigation
    investigation_id UUID,
    is_relevant BOOLEAN DEFAULT false,
    relevance_score DECIMAL(5,4),
    flagged BOOLEAN DEFAULT false,
    flag_reason TEXT,

    -- Media attachments
    has_attachments BOOLEAN DEFAULT false,
    attachment_urls TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Legal
    warrant_number VARCHAR(100),
    legal_authorization TEXT,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable
SELECT create_hypertable('communication_logs', 'time',
    chunk_time_interval => INTERVAL '1 week',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_comm_from ON communication_logs (from_identifier, time DESC);
CREATE INDEX idx_comm_to ON communication_logs (to_identifier, time DESC);
CREATE INDEX idx_comm_type ON communication_logs (comm_type, time DESC);
CREATE INDEX idx_comm_from_target ON communication_logs (from_target_id, time DESC);
CREATE INDEX idx_comm_to_target ON communication_logs (to_target_id, time DESC);
CREATE INDEX idx_comm_investigation ON communication_logs (investigation_id, time DESC);
CREATE INDEX idx_comm_flagged ON communication_logs (flagged, time DESC) WHERE flagged = true;
CREATE INDEX idx_comm_relevant ON communication_logs (is_relevant, time DESC) WHERE is_relevant = true;
CREATE INDEX idx_comm_tags ON communication_logs USING gin(tags);

-- ============================================================================
-- DATA RETENTION POLICIES
-- ============================================================================

-- Retention policy: Keep blockchain data for 5 years
SELECT add_retention_policy('blockchain_transactions', INTERVAL '5 years');

-- Retention policy: Keep surveillance data for 3 years
SELECT add_retention_policy('surveillance_events', INTERVAL '3 years');

-- Retention policy: Keep communication logs for 7 years (legal requirement)
SELECT add_retention_policy('communication_logs', INTERVAL '7 years');

-- ============================================================================
-- COMPRESSION POLICIES (Save storage space)
-- ============================================================================

-- Compress blockchain data older than 30 days
SELECT add_compression_policy('blockchain_transactions', INTERVAL '30 days');

-- Compress surveillance data older than 7 days
SELECT add_compression_policy('surveillance_events', INTERVAL '7 days');

-- Compress communication logs older than 30 days
SELECT add_compression_policy('communication_logs', INTERVAL '30 days');

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to get recent blockchain activity for a target
CREATE OR REPLACE FUNCTION get_target_blockchain_activity(
    p_target_id UUID,
    p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    day DATE,
    blockchain VARCHAR,
    transaction_count BIGINT,
    total_sent DECIMAL,
    total_received DECIMAL,
    total_usd_value DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        time::DATE as day,
        bt.blockchain,
        COUNT(*) as transaction_count,
        SUM(CASE WHEN bt.investigation_id = p_target_id THEN bt.amount ELSE 0 END) as total_sent,
        SUM(CASE WHEN bt.target_id = p_target_id THEN bt.amount ELSE 0 END) as total_received,
        SUM(bt.usd_value) as total_usd_value
    FROM blockchain_transactions bt
    WHERE (bt.investigation_id = p_target_id OR bt.target_id = p_target_id)
        AND time > NOW() - (p_days || ' days')::INTERVAL
    GROUP BY day, bt.blockchain
    ORDER BY day DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get surveillance matches for a target
CREATE OR REPLACE FUNCTION get_target_surveillance_matches(
    p_target_id UUID,
    p_days INTEGER DEFAULT 30,
    p_min_confidence DECIMAL DEFAULT 0.85
)
RETURNS TABLE (
    detection_time TIMESTAMPTZ,
    location VARCHAR,
    camera_name VARCHAR,
    confidence DECIMAL,
    image_url VARCHAR,
    reviewed BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        se.time as detection_time,
        se.location,
        se.camera_name,
        se.confidence,
        se.image_url,
        se.reviewed
    FROM surveillance_events se
    WHERE se.target_id = p_target_id
        AND se.is_match = true
        AND se.confidence >= p_min_confidence
        AND se.time > NOW() - (p_days || ' days')::INTERVAL
    ORDER BY se.time DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE blockchain_transactions IS 'Time-series blockchain transaction data for cryptocurrency tracking';
COMMENT ON TABLE surveillance_events IS 'Time-series surveillance camera detections and facial recognition matches';
COMMENT ON TABLE communication_logs IS 'Time-series communication intercepts and logs (calls, messages, emails)';

-- ============================================================================
-- LOCATION TRACKING EVENTS (Time-Series)
-- ============================================================================

CREATE TABLE location_tracking_events (
    time TIMESTAMPTZ NOT NULL,

    -- Event Identity
    event_id UUID DEFAULT gen_random_uuid(),
    tracking_source VARCHAR(100) NOT NULL, -- gps, cell_tower, wifi, ip_geolocation, manual, surveillance, financial

    -- Target
    target_id UUID NOT NULL,
    investigation_id UUID,

    -- Location
    location_name VARCHAR(500),
    address VARCHAR(1000),
    city VARCHAR(200),
    country VARCHAR(100),
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    altitude DOUBLE PRECISION,
    accuracy_meters DOUBLE PRECISION,
    coords POINT,

    -- Movement
    speed_kmh DOUBLE PRECISION,
    heading DOUBLE PRECISION, -- Direction in degrees
    is_stationary BOOLEAN DEFAULT false,

    -- Source Details
    source_device_id VARCHAR(255),
    source_device_type VARCHAR(100), -- phone, vehicle, wearable, beacon
    source_network VARCHAR(200), -- Carrier or WiFi network name

    -- Verification
    confidence DECIMAL(5,4) DEFAULT 0.5,
    is_verified BOOLEAN DEFAULT false,
    verified_by UUID,
    verified_at TIMESTAMPTZ,

    -- Related Data
    evidence_id UUID,
    surveillance_event_id UUID,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable
SELECT create_hypertable('location_tracking_events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_loc_target ON location_tracking_events (target_id, time DESC);
CREATE INDEX idx_loc_investigation ON location_tracking_events (investigation_id, time DESC);
CREATE INDEX idx_loc_source ON location_tracking_events (tracking_source, time DESC);
CREATE INDEX idx_loc_country ON location_tracking_events (country, time DESC);
CREATE INDEX idx_loc_city ON location_tracking_events (city, time DESC);
CREATE INDEX idx_loc_coords ON location_tracking_events USING gist(coords);
CREATE INDEX idx_loc_tags ON location_tracking_events USING gin(tags);

-- Retention policy: Keep location data for 5 years
SELECT add_retention_policy('location_tracking_events', INTERVAL '5 years');

-- Compression policy
SELECT add_compression_policy('location_tracking_events', INTERVAL '14 days');

-- ============================================================================
-- OSINT COLLECTION EVENTS (Time-Series)
-- ============================================================================

CREATE TABLE osint_collection_events (
    time TIMESTAMPTZ NOT NULL,

    -- Event Identity
    event_id UUID DEFAULT gen_random_uuid(),
    collection_type VARCHAR(100) NOT NULL, -- social_media_post, news_article, forum_post, dark_web, blockchain

    -- Source
    source_platform VARCHAR(200) NOT NULL, -- twitter, facebook, reddit, news_site, etc.
    source_url VARCHAR(2000),
    source_id VARCHAR(500), -- Platform-specific ID

    -- Target Links
    target_id UUID,
    investigation_id UUID,

    -- Content
    title VARCHAR(1000),
    content_preview TEXT, -- First 500 chars
    content_hash VARCHAR(64), -- SHA-256 of full content
    language VARCHAR(50),
    author_username VARCHAR(500),
    author_id VARCHAR(500),

    -- Analysis
    sentiment VARCHAR(50), -- positive, negative, neutral
    sentiment_score DECIMAL(5,4), -- -1.0000 to 1.0000
    relevance_score DECIMAL(5,4), -- 0.0000 to 1.0000
    keywords TEXT[] DEFAULT ARRAY[]::TEXT[],
    entities_detected JSONB, -- Named entities
    topics TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Engagement (for social media)
    likes_count INTEGER,
    shares_count INTEGER,
    comments_count INTEGER,
    views_count INTEGER,

    -- Location (if available)
    geo_location VARCHAR(500),
    geo_coords POINT,

    -- Flags
    is_relevant BOOLEAN DEFAULT false,
    is_flagged BOOLEAN DEFAULT false,
    flag_reason TEXT,
    is_processed BOOLEAN DEFAULT false,
    processed_at TIMESTAMPTZ,

    -- Intelligence Report Link
    intelligence_report_id UUID,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable
SELECT create_hypertable('osint_collection_events', 'time',
    chunk_time_interval => INTERVAL '1 week',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_osint_target ON osint_collection_events (target_id, time DESC);
CREATE INDEX idx_osint_investigation ON osint_collection_events (investigation_id, time DESC);
CREATE INDEX idx_osint_platform ON osint_collection_events (source_platform, time DESC);
CREATE INDEX idx_osint_type ON osint_collection_events (collection_type, time DESC);
CREATE INDEX idx_osint_relevant ON osint_collection_events (is_relevant, time DESC) WHERE is_relevant = true;
CREATE INDEX idx_osint_flagged ON osint_collection_events (is_flagged, time DESC) WHERE is_flagged = true;
CREATE INDEX idx_osint_keywords ON osint_collection_events USING gin(keywords);
CREATE INDEX idx_osint_tags ON osint_collection_events USING gin(tags);
CREATE INDEX idx_osint_author ON osint_collection_events (author_username);

-- Continuous aggregate for daily OSINT summary
CREATE MATERIALIZED VIEW osint_daily_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS day,
    source_platform,
    collection_type,
    COUNT(*) as event_count,
    COUNT(DISTINCT target_id) as unique_targets,
    AVG(relevance_score) as avg_relevance,
    COUNT(*) FILTER (WHERE is_relevant = true) as relevant_count,
    COUNT(*) FILTER (WHERE is_flagged = true) as flagged_count,
    SUM(likes_count) as total_engagement
FROM osint_collection_events
GROUP BY day, source_platform, collection_type
WITH NO DATA;

SELECT add_continuous_aggregate_policy('osint_daily_summary',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- Retention policy: Keep OSINT data for 3 years
SELECT add_retention_policy('osint_collection_events', INTERVAL '3 years');

-- Compression policy
SELECT add_compression_policy('osint_collection_events', INTERVAL '30 days');

-- ============================================================================
-- ALERT METRICS (Time-Series for Analytics)
-- ============================================================================

CREATE TABLE alert_metrics (
    time TIMESTAMPTZ NOT NULL,

    -- Alert Info
    alert_id UUID NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,

    -- Investigation/Target
    investigation_id UUID,
    target_id UUID,

    -- Source System
    source_system VARCHAR(200) NOT NULL,

    -- Response Metrics
    detection_to_alert_ms INTEGER, -- Time from detection to alert generation
    alert_to_ack_ms INTEGER, -- Time from alert to acknowledgment
    alert_to_resolution_ms INTEGER, -- Time from alert to resolution

    -- Outcome
    outcome VARCHAR(50), -- true_positive, false_positive, unknown, pending
    was_actionable BOOLEAN,
    action_taken VARCHAR(200),

    -- Confidence
    initial_confidence DECIMAL(5,4),
    final_confidence DECIMAL(5,4),

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable
SELECT create_hypertable('alert_metrics', 'time',
    chunk_time_interval => INTERVAL '1 month',
    if_not_exists => TRUE
);

-- Create indexes
CREATE INDEX idx_alert_metrics_type ON alert_metrics (alert_type, time DESC);
CREATE INDEX idx_alert_metrics_severity ON alert_metrics (severity, time DESC);
CREATE INDEX idx_alert_metrics_investigation ON alert_metrics (investigation_id, time DESC);
CREATE INDEX idx_alert_metrics_target ON alert_metrics (target_id, time DESC);
CREATE INDEX idx_alert_metrics_outcome ON alert_metrics (outcome, time DESC);

-- Continuous aggregate for alert performance metrics
CREATE MATERIALIZED VIEW alert_performance_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS day,
    alert_type,
    severity,
    source_system,
    COUNT(*) as total_alerts,
    AVG(alert_to_ack_ms) as avg_ack_time_ms,
    AVG(alert_to_resolution_ms) as avg_resolution_time_ms,
    COUNT(*) FILTER (WHERE outcome = 'true_positive') as true_positives,
    COUNT(*) FILTER (WHERE outcome = 'false_positive') as false_positives,
    COUNT(*) FILTER (WHERE was_actionable = true) as actionable_count,
    AVG(initial_confidence) as avg_initial_confidence,
    AVG(final_confidence) as avg_final_confidence
FROM alert_metrics
GROUP BY day, alert_type, severity, source_system
WITH NO DATA;

SELECT add_continuous_aggregate_policy('alert_performance_daily',
    start_offset => INTERVAL '7 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- Retention policy: Keep alert metrics for 2 years
SELECT add_retention_policy('alert_metrics', INTERVAL '2 years');

-- Compression policy
SELECT add_compression_policy('alert_metrics', INTERVAL '60 days');

-- ============================================================================
-- ADDITIONAL HELPER FUNCTIONS
-- ============================================================================

-- Function to get target movement pattern
CREATE OR REPLACE FUNCTION get_target_movement_pattern(
    p_target_id UUID,
    p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    time_window TIMESTAMPTZ,
    country VARCHAR,
    city VARCHAR,
    event_count BIGINT,
    unique_locations BIGINT,
    avg_confidence DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        time_bucket('6 hours', time) as time_window,
        lte.country,
        lte.city,
        COUNT(*) as event_count,
        COUNT(DISTINCT (lte.latitude, lte.longitude)) as unique_locations,
        AVG(lte.confidence) as avg_confidence
    FROM location_tracking_events lte
    WHERE lte.target_id = p_target_id
        AND time > NOW() - (p_days || ' days')::INTERVAL
    GROUP BY time_window, lte.country, lte.city
    ORDER BY time_window DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get OSINT activity for a target
CREATE OR REPLACE FUNCTION get_target_osint_activity(
    p_target_id UUID,
    p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    day DATE,
    platform VARCHAR,
    event_count BIGINT,
    relevant_count BIGINT,
    avg_sentiment DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        time::DATE as day,
        oce.source_platform as platform,
        COUNT(*) as event_count,
        COUNT(*) FILTER (WHERE oce.is_relevant = true) as relevant_count,
        AVG(oce.sentiment_score) as avg_sentiment
    FROM osint_collection_events oce
    WHERE oce.target_id = p_target_id
        AND time > NOW() - (p_days || ' days')::INTERVAL
    GROUP BY day, oce.source_platform
    ORDER BY day DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE location_tracking_events IS 'Time-series location tracking data from various sources';
COMMENT ON TABLE osint_collection_events IS 'Time-series OSINT collection events from social media and other sources';
COMMENT ON TABLE alert_metrics IS 'Time-series metrics for alert performance analysis';
