-- Users and Authentication Tables
-- Secure authentication system for Apollo platform

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'viewer',
    clearance_level clearance_level NOT NULL DEFAULT 'unclassified'
    organization VARCHAR(200),
    department VARCHAR(200),
    badge_number VARCHAR(50),
    avatar_url VARCHAR(1000),

    -- Authentication state
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    is_mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255),
    mfa_backup_codes TEXT,

    -- OAuth
    oauth_provider VARCHAR(50),
    oauth_id VARCHAR(255),

    -- Password management
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    password_changed_at TIMESTAMP DEFAULT NOW(),
    must_change_password BOOLEAN DEFAULT false,

    -- Login tracking
    last_login TIMESTAMP,
    last_login_ip INET,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),

    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Create indexes for fast lookups
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_clearance_level ON users(clearance_level);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX idx_users_organization ON users(organization);
CREATE INDEX idx_users_mfa_enabled ON users(is_mfa_enabled) WHERE is_mfa_enabled = true;
CREATE INDEX idx_users_created ON users(created_at DESC);

-- User sessions table (for JWT token management)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(128) UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    refresh_expires_at TIMESTAMP,
    ip_address INET,
    user_agent TEXT,
    device_id VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_sessions_active ON user_sessions(is_active) WHERE is_active = true;

-- Multi-factor authentication table
CREATE TABLE user_mfa (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_type VARCHAR(50) NOT NULL CHECK (mfa_type IN ('totp', 'sms', 'email', 'hardware_key')),
    secret_encrypted VARCHAR(500),
    backup_codes_encrypted TEXT,
    is_enabled BOOLEAN DEFAULT false,
    is_verified BOOLEAN DEFAULT false,
    phone_number VARCHAR(20),
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, mfa_type)
);

CREATE INDEX idx_user_mfa_user_id ON user_mfa(user_id);
CREATE INDEX idx_user_mfa_enabled ON user_mfa(is_enabled) WHERE is_enabled = true;

-- OAuth providers table
CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('google', 'microsoft', 'github', 'okta')),
    provider_user_id VARCHAR(255) NOT NULL,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TIMESTAMP,
    scope TEXT,
    profile_data JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_user_id ON oauth_providers(user_id);
CREATE INDEX idx_oauth_provider ON oauth_providers(provider);

-- API keys table (for programmatic access)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL, -- First 10 chars for identification
    permissions JSONB DEFAULT '[]'::jsonb,
    rate_limit INTEGER DEFAULT 1000, -- Requests per hour
    ip_whitelist INET[] DEFAULT NULL,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP,
    revoked_by UUID REFERENCES users(id)
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    ip_address INET,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_password_reset_token ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_user ON password_reset_tokens(user_id);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_email_verify_token ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verify_user ON email_verification_tokens(user_id);

-- Login attempts tracking (security)
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255),
    username VARCHAR(100),
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_email ON login_attempts(email);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address);
CREATE INDEX idx_login_attempts_created ON login_attempts(created_at);

-- Audit log for security-sensitive operations
CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_user ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_action ON auth_audit_log(action);
CREATE INDEX idx_auth_audit_created ON auth_audit_log(created_at);
CREATE INDEX idx_auth_audit_resource ON auth_audit_log(resource_type, resource_id);

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_mfa_updated_at BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_providers_updated_at BEFORE UPDATE ON oauth_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to handle failed login attempts and account locking
CREATE OR REPLACE FUNCTION handle_failed_login(p_email VARCHAR, p_ip INET)
RETURNS VOID AS $$
DECLARE
    v_user_id UUID;
    v_attempts INTEGER;
BEGIN
    -- Get user
    SELECT id, failed_login_attempts INTO v_user_id, v_attempts
    FROM users WHERE email = p_email;

    IF v_user_id IS NOT NULL THEN
        -- Increment failed attempts
        v_attempts := v_attempts + 1;

        -- Lock account if too many attempts
        IF v_attempts >= 5 THEN
            UPDATE users
            SET failed_login_attempts = v_attempts,
                locked_until = NOW() + INTERVAL '30 minutes',
                updated_at = NOW()
            WHERE id = v_user_id;
        ELSE
            UPDATE users
            SET failed_login_attempts = v_attempts,
                updated_at = NOW()
            WHERE id = v_user_id;
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function to reset failed login attempts on successful login
CREATE OR REPLACE FUNCTION handle_successful_login(p_user_id UUID, p_ip INET)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET failed_login_attempts = 0,
        locked_until = NULL,
        last_login_at = NOW(),
        last_login_ip = p_ip,
        updated_at = NOW()
    WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Create default admin user (password: ChangeMe2026! - MUST be changed in production)
-- Password hash is for 'ChangeMe2026!' using bcrypt (cost=12)
INSERT INTO users (
    email,
    username,
    password_hash,
    first_name,
    last_name,
    role,
    clearance_level,
    is_active,
    is_verified,
    is_mfa_enabled
) VALUES (
    'admin@apollo.local',
    'apollo_admin',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqNg7fCXzi',
    'Apollo',
    'Administrator',
    'admin',
    'top_secret',
    true,
    true,
    false
) ON CONFLICT (email) DO NOTHING;

COMMENT ON TABLE users IS 'Apollo platform users with role-based access control';
COMMENT ON TABLE user_sessions IS 'Active JWT sessions for authentication';
COMMENT ON TABLE user_mfa IS 'Multi-factor authentication configuration per user';
COMMENT ON TABLE oauth_providers IS 'OAuth provider integrations (Google, Microsoft, etc.)';
COMMENT ON TABLE api_keys IS 'API keys for programmatic access to Apollo platform';
COMMENT ON TABLE login_attempts IS 'Security tracking of all login attempts';
COMMENT ON TABLE auth_audit_log IS 'Comprehensive audit trail for security-sensitive operations';
