-- Biometric Authentication and Session Management Schema
-- Migration: 005_biometric_auth.sql

-- ==================================
-- Biometric Enrollments Table
-- ==================================
CREATE TABLE IF NOT EXISTS biometric_enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    biometric_type VARCHAR(50) NOT NULL CHECK (biometric_type IN ('fingerprint', 'face_id', 'voice_print')),
    template_hash VARCHAR(64) NOT NULL,
    encrypted_template TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'enrolled' CHECK (status IN ('not_enrolled', 'enrolled', 'locked_out', 'disabled')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    device_id VARCHAR(64),
    metadata JSONB,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Ensure one enrollment per type per user
    UNIQUE(user_id, biometric_type)
);

-- Indexes for biometric_enrollments
CREATE INDEX IF NOT EXISTS idx_biometric_enrollments_user_id ON biometric_enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_biometric_enrollments_type ON biometric_enrollments(biometric_type);
CREATE INDEX IF NOT EXISTS idx_biometric_enrollments_status ON biometric_enrollments(status);

-- ==================================
-- User Sessions Table
-- ==================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    ip_address INET,
    user_agent TEXT,
    location VARCHAR(255),
    access_token TEXT NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    mfa_verified BOOLEAN NOT NULL DEFAULT false,
    biometric_verified BOOLEAN NOT NULL DEFAULT false,

    -- Indexes
    CONSTRAINT unique_refresh_token UNIQUE (refresh_token_hash)
);

-- Indexes for user_sessions
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_id ON user_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_is_active ON user_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions(last_activity);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);

-- ==================================
-- API Keys Table
-- ==================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'expired', 'revoked', 'rate_limited')),
    rate_limit INTEGER NOT NULL DEFAULT 100,
    rate_limit_window INTEGER NOT NULL DEFAULT 60,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    last_rotated TIMESTAMP WITH TIME ZONE,
    ip_whitelist JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for api_keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);

-- ==================================
-- API Key Usage Table (for analytics)
-- ==================================
CREATE TABLE IF NOT EXISTS api_key_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(500) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for api_key_usage
CREATE INDEX IF NOT EXISTS idx_api_key_usage_key_id ON api_key_usage(api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_timestamp ON api_key_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_endpoint ON api_key_usage(endpoint);

-- Partition by time for better performance (optional - for high-volume systems)
-- CREATE TABLE api_key_usage_partitioned (LIKE api_key_usage) PARTITION BY RANGE (timestamp);

-- ==================================
-- Update Users Table for Biometric Support
-- ==================================
DO $$
BEGIN
    -- Add biometric_enabled column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'users' AND column_name = 'biometric_enabled') THEN
        ALTER TABLE users ADD COLUMN biometric_enabled BOOLEAN DEFAULT false;
    END IF;

    -- Add biometric_types array column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'users' AND column_name = 'biometric_types') THEN
        ALTER TABLE users ADD COLUMN biometric_types TEXT[] DEFAULT ARRAY[]::TEXT[];
    END IF;

    -- Add phone_number column if not exists (for SMS MFA)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'users' AND column_name = 'phone_number') THEN
        ALTER TABLE users ADD COLUMN phone_number VARCHAR(20);
    END IF;

    -- Add email_verified column if not exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'users' AND column_name = 'email_verified') THEN
        ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
    END IF;
END $$;

-- ==================================
-- MFA Challenges Table (for multi-step MFA)
-- ==================================
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(50) NOT NULL,
    required_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    verified_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for mfa_challenges
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_status ON mfa_challenges(status);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);

-- ==================================
-- Functions and Triggers
-- ==================================

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for biometric_enrollments
DROP TRIGGER IF EXISTS update_biometric_enrollments_updated_at ON biometric_enrollments;
CREATE TRIGGER update_biometric_enrollments_updated_at
    BEFORE UPDATE ON biometric_enrollments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for api_keys
DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ==================================
-- Cleanup Functions
-- ==================================

-- Function to cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM user_sessions
        WHERE expires_at < NOW() OR (is_active = false AND updated_at < NOW() - INTERVAL '7 days')
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired API keys
CREATE OR REPLACE FUNCTION cleanup_expired_api_keys()
RETURNS INTEGER AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    WITH updated AS (
        UPDATE api_keys
        SET status = 'expired'
        WHERE expires_at < NOW() AND status = 'active'
        RETURNING id
    )
    SELECT COUNT(*) INTO updated_count FROM updated;

    RETURN updated_count;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old API key usage data (keep last 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_api_key_usage()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM api_key_usage
        WHERE timestamp < NOW() - INTERVAL '90 days'
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ==================================
-- Security Views
-- ==================================

-- View for active sessions summary
CREATE OR REPLACE VIEW active_sessions_summary AS
SELECT
    u.id AS user_id,
    u.email,
    u.username,
    COUNT(s.id) AS active_session_count,
    MAX(s.last_activity) AS last_activity,
    ARRAY_AGG(DISTINCT s.device_type) AS device_types
FROM users u
LEFT JOIN user_sessions s ON u.id = s.user_id AND s.is_active = true
GROUP BY u.id, u.email, u.username;

-- View for API key summary
CREATE OR REPLACE VIEW api_key_summary AS
SELECT
    k.id,
    k.user_id,
    u.email AS user_email,
    k.name,
    k.key_prefix,
    k.status,
    k.scopes,
    k.rate_limit,
    k.expires_at,
    k.last_used,
    k.created_at,
    COALESCE(usage.request_count, 0) AS total_requests
FROM api_keys k
JOIN users u ON k.user_id = u.id
LEFT JOIN (
    SELECT api_key_id, COUNT(*) AS request_count
    FROM api_key_usage
    WHERE timestamp > NOW() - INTERVAL '30 days'
    GROUP BY api_key_id
) usage ON k.id = usage.api_key_id;

-- ==================================
-- Grant Permissions (adjust as needed)
-- ==================================
-- GRANT SELECT, INSERT, UPDATE, DELETE ON biometric_enrollments TO apollo_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON user_sessions TO apollo_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO apollo_app;
-- GRANT SELECT, INSERT ON api_key_usage TO apollo_app;
-- GRANT SELECT, INSERT, UPDATE ON mfa_challenges TO apollo_app;

COMMENT ON TABLE biometric_enrollments IS 'Stores biometric authentication enrollments (fingerprint, face, voice)';
COMMENT ON TABLE user_sessions IS 'Tracks active user sessions with device binding and MFA status';
COMMENT ON TABLE api_keys IS 'Manages API keys with scope-based permissions and rate limiting';
COMMENT ON TABLE api_key_usage IS 'Audit log for API key usage and analytics';
COMMENT ON TABLE mfa_challenges IS 'Tracks multi-factor authentication challenges in progress';
