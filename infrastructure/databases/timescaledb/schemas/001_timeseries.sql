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
