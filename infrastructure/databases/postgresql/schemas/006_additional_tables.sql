-- Apollo Platform - Additional Tables and Enhancements
-- Extended tables for complete platform functionality
-- Migration: 006_additional_tables.sql
-- Version: 1.2.0

-- ============================================================================
-- PERMISSIONS AND ROLES SYSTEM
-- ============================================================================

-- Permissions table (granular access control)
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL, -- investigations, targets, evidence, operations, intelligence, admin
    action VARCHAR(50) NOT NULL, -- create, read, update, delete, execute, approve
    scope VARCHAR(50) DEFAULT 'own', -- own, team, department, all
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);
CREATE INDEX idx_permissions_action ON permissions(action);

-- Role permissions mapping
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role user_role NOT NULL,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    UNIQUE(role, permission_id)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);

-- User-specific permissions (override role permissions)
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    is_granted BOOLEAN DEFAULT true, -- Can be used to deny a permission
    granted_at TIMESTAMP DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    expires_at TIMESTAMP, -- Temporary permissions
    notes TEXT,
    UNIQUE(user_id, permission_id)
);

CREATE INDEX idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX idx_user_permissions_permission ON user_permissions(permission_id);

-- ============================================================================
-- FIELD REPORTS (Operations)
-- ============================================================================

CREATE TABLE field_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operation_id UUID NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Report Details
    report_number VARCHAR(100) UNIQUE,
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    content TEXT NOT NULL,
    report_type VARCHAR(100), -- surveillance, interview, observation, incident, progress

    -- Location
    location VARCHAR(500),
    location_coords POINT,

    -- Timing
    report_date TIMESTAMP NOT NULL DEFAULT NOW(),
    event_start_time TIMESTAMP,
    event_end_time TIMESTAMP,

    -- Classification
    classification_level VARCHAR(50) DEFAULT 'CONFIDENTIAL',

    -- Attachments
    attachments JSONB DEFAULT '[]'::jsonb, -- Array of file references

    -- Status
    status VARCHAR(50) DEFAULT 'draft', -- draft, submitted, reviewed, approved, archived
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMP,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP,

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_field_reports_operation ON field_reports(operation_id);
CREATE INDEX idx_field_reports_investigation ON field_reports(investigation_id);
CREATE INDEX idx_field_reports_date ON field_reports(report_date DESC);
CREATE INDEX idx_field_reports_status ON field_reports(status);
CREATE INDEX idx_field_reports_tags ON field_reports USING gin(tags);

-- ============================================================================
-- NOTIFICATIONS SYSTEM
-- ============================================================================

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Notification Content
    type VARCHAR(50) NOT NULL, -- alert, message, system, assignment, mention, update
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,

    -- Linking
    entity_type VARCHAR(100), -- investigation, target, operation, evidence, intelligence, alert
    entity_id UUID,
    action_url VARCHAR(1000),

    -- Status
    is_read BOOLEAN DEFAULT false,
    read_at TIMESTAMP,
    is_archived BOOLEAN DEFAULT false,
    archived_at TIMESTAMP,

    -- Priority
    priority VARCHAR(50) DEFAULT 'normal', -- low, normal, high, urgent

    -- Delivery
    email_sent BOOLEAN DEFAULT false,
    email_sent_at TIMESTAMP,
    push_sent BOOLEAN DEFAULT false,
    push_sent_at TIMESTAMP,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_unread ON notifications(user_id, is_read) WHERE is_read = false;
CREATE INDEX idx_notifications_type ON notifications(type);
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);
CREATE INDEX idx_notifications_entity ON notifications(entity_type, entity_id);

-- ============================================================================
-- ACTIVITY LOGS (Comprehensive Audit Trail)
-- ============================================================================

CREATE TABLE activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Action Details
    action VARCHAR(100) NOT NULL,
    action_category VARCHAR(50), -- auth, data, admin, system, search, export

    -- Resource
    resource_type VARCHAR(100), -- user, investigation, target, evidence, operation, intelligence
    resource_id UUID,
    resource_name VARCHAR(500), -- Human-readable name

    -- Changes (for updates)
    changes JSONB, -- {field: {old: value, new: value}}

    -- Request Context
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(100),
    session_id UUID,

    -- Geographic
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),
    geo_coords POINT,

    -- Status
    status VARCHAR(50) DEFAULT 'success', -- success, failure, error
    error_message TEXT,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_activity_user ON activity_logs(user_id);
CREATE INDEX idx_activity_action ON activity_logs(action);
CREATE INDEX idx_activity_category ON activity_logs(action_category);
CREATE INDEX idx_activity_resource ON activity_logs(resource_type, resource_id);
CREATE INDEX idx_activity_timestamp ON activity_logs(timestamp DESC);
CREATE INDEX idx_activity_ip ON activity_logs(ip_address);
CREATE INDEX idx_activity_status ON activity_logs(status);

-- Partitioning by month for large-scale deployments
-- Note: Enable partitioning in production for better performance
-- CREATE TABLE activity_logs_partitioned (...) PARTITION BY RANGE (timestamp);

-- ============================================================================
-- USER SETTINGS
-- ============================================================================

CREATE TABLE user_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,

    -- Display Settings
    theme VARCHAR(20) DEFAULT 'dark', -- light, dark, auto
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    date_format VARCHAR(50) DEFAULT 'YYYY-MM-DD',
    time_format VARCHAR(10) DEFAULT '24h', -- 12h, 24h

    -- Notification Settings
    email_notifications BOOLEAN DEFAULT true,
    push_notifications BOOLEAN DEFAULT true,
    alert_sound BOOLEAN DEFAULT true,
    notification_digest VARCHAR(20) DEFAULT 'realtime', -- realtime, hourly, daily, weekly
    alert_types_enabled TEXT[] DEFAULT ARRAY['critical', 'high', 'medium']::TEXT[],

    -- Privacy Settings
    profile_visibility VARCHAR(20) DEFAULT 'team', -- public, team, private
    activity_tracking BOOLEAN DEFAULT true,

    -- Dashboard Settings
    dashboard_layout JSONB DEFAULT '{}'::jsonb,
    default_investigation_view VARCHAR(50) DEFAULT 'list', -- list, board, timeline
    items_per_page INTEGER DEFAULT 20,

    -- Map Settings
    default_map_center POINT DEFAULT POINT(0, 0),
    default_map_zoom INTEGER DEFAULT 2,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_user_settings_user ON user_settings(user_id);

-- ============================================================================
-- FINANCIAL PROFILES (Extended Target Financial Data)
-- ============================================================================

CREATE TABLE financial_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    -- Wealth Estimate
    estimated_total_wealth DECIMAL(20,2),
    wealth_confidence VARCHAR(50), -- verified, probable, estimated, unknown
    wealth_last_assessed TIMESTAMP,

    -- Summary
    financial_summary TEXT,
    risk_indicators TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_financial_profile_target ON financial_profiles(target_id);

-- Bank accounts linked to targets
CREATE TABLE target_bank_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    financial_profile_id UUID NOT NULL REFERENCES financial_profiles(id) ON DELETE CASCADE,

    institution VARCHAR(300) NOT NULL,
    account_number_masked VARCHAR(100), -- Last 4 digits visible
    account_type VARCHAR(100), -- checking, savings, investment, offshore
    currency VARCHAR(10) DEFAULT 'USD',
    estimated_balance DECIMAL(20,2),
    balance_date TIMESTAMP,

    -- Location
    country VARCHAR(100),
    swift_code VARCHAR(20),
    iban VARCHAR(50),

    -- Status
    is_frozen BOOLEAN DEFAULT false,
    frozen_date TIMESTAMP,
    frozen_by VARCHAR(200), -- Agency that froze account

    -- Investigation
    is_verified BOOLEAN DEFAULT false,
    source VARCHAR(200),

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_bank_accounts_profile ON target_bank_accounts(financial_profile_id);

-- Cryptocurrency wallets linked to targets
CREATE TABLE target_crypto_wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    financial_profile_id UUID NOT NULL REFERENCES financial_profiles(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,

    -- Wallet Details
    blockchain VARCHAR(50) NOT NULL, -- bitcoin, ethereum, litecoin, monero, etc.
    address VARCHAR(200) NOT NULL,
    label VARCHAR(200),

    -- Balance
    balance DECIMAL(36,18),
    balance_usd DECIMAL(20,2),
    balance_last_updated TIMESTAMP,

    -- Activity
    first_seen TIMESTAMP,
    last_active TIMESTAMP,
    transaction_count INTEGER DEFAULT 0,
    total_received DECIMAL(36,18),
    total_sent DECIMAL(36,18),

    -- Clustering
    cluster_id UUID,
    cluster_name VARCHAR(200),

    -- Risk Analysis
    risk_score DECIMAL(5,4), -- 0.0000 to 1.0000
    risk_factors TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_mixer_associated BOOLEAN DEFAULT false,
    is_darknet_associated BOOLEAN DEFAULT false,
    exchange_interactions TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Monitoring
    is_watched BOOLEAN DEFAULT true,
    alert_on_transaction BOOLEAN DEFAULT true,
    alert_threshold DECIMAL(36,18),

    -- Verification
    is_verified BOOLEAN DEFAULT false,
    verification_source VARCHAR(200),

    -- Investigation
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_crypto_wallets_profile ON target_crypto_wallets(financial_profile_id);
CREATE INDEX idx_crypto_wallets_target ON target_crypto_wallets(target_id);
CREATE INDEX idx_crypto_wallets_address ON target_crypto_wallets(address);
CREATE INDEX idx_crypto_wallets_blockchain ON target_crypto_wallets(blockchain);
CREATE INDEX idx_crypto_wallets_watched ON target_crypto_wallets(is_watched) WHERE is_watched = true;
CREATE INDEX idx_crypto_wallets_investigation ON target_crypto_wallets(investigation_id);
CREATE INDEX idx_crypto_wallets_cluster ON target_crypto_wallets(cluster_id);

-- Assets linked to targets
CREATE TABLE target_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    financial_profile_id UUID NOT NULL REFERENCES financial_profiles(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,

    -- Asset Details
    asset_type VARCHAR(100) NOT NULL, -- real_estate, vehicle, yacht, aircraft, jewelry, art, business
    description TEXT NOT NULL,
    estimated_value DECIMAL(20,2),
    currency VARCHAR(10) DEFAULT 'USD',

    -- Location
    location VARCHAR(500),
    location_coords POINT,
    country VARCHAR(100),

    -- Ownership
    ownership_type VARCHAR(100), -- sole, joint, corporate, trust
    registered_to VARCHAR(500), -- Name on title/registration
    shell_company VARCHAR(500), -- If owned through shell company

    -- Identification
    registration_number VARCHAR(200),
    serial_number VARCHAR(200),

    -- Status
    is_seized BOOLEAN DEFAULT false,
    seized_date TIMESTAMP,
    seized_by VARCHAR(200),
    seizure_order_number VARCHAR(100),

    -- Verification
    is_verified BOOLEAN DEFAULT false,
    verification_source VARCHAR(200),

    -- Media
    photo_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    document_urls TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_assets_profile ON target_assets(financial_profile_id);
CREATE INDEX idx_assets_target ON target_assets(target_id);
CREATE INDEX idx_assets_type ON target_assets(asset_type);
CREATE INDEX idx_assets_country ON target_assets(country);
CREATE INDEX idx_assets_seized ON target_assets(is_seized);

-- ============================================================================
-- TARGET ASSOCIATIONS (Detailed Relationship Mapping)
-- ============================================================================

CREATE TABLE target_associations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Related Targets
    source_target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    associated_target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    -- Relationship
    relationship_type VARCHAR(100) NOT NULL, -- family, business, criminal, romantic, financial, communication
    relationship_description TEXT,
    relationship_subtype VARCHAR(100), -- For family: sibling, parent, spouse, etc.

    -- Strength and Confidence
    strength VARCHAR(50) DEFAULT 'moderate', -- weak, moderate, strong, confirmed
    confidence DECIMAL(5,4) NOT NULL DEFAULT 0.5, -- 0.0000 to 1.0000

    -- Timing
    relationship_start DATE,
    relationship_end DATE,
    is_active BOOLEAN DEFAULT true,
    last_contact_date DATE,

    -- Evidence
    evidence_ids UUID[] DEFAULT ARRAY[]::UUID[],
    intelligence_report_ids UUID[] DEFAULT ARRAY[]::UUID[],

    -- Verification
    is_verified BOOLEAN DEFAULT false,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,

    -- Investigation
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Metadata
    notes TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id),

    -- Prevent duplicate relationships
    UNIQUE(source_target_id, associated_target_id, relationship_type),
    -- Prevent self-association
    CONSTRAINT no_self_association CHECK (source_target_id != associated_target_id)
);

CREATE INDEX idx_assoc_source ON target_associations(source_target_id);
CREATE INDEX idx_assoc_associated ON target_associations(associated_target_id);
CREATE INDEX idx_assoc_type ON target_associations(relationship_type);
CREATE INDEX idx_assoc_active ON target_associations(is_active) WHERE is_active = true;
CREATE INDEX idx_assoc_investigation ON target_associations(investigation_id);
CREATE INDEX idx_assoc_confidence ON target_associations(confidence DESC);

-- ============================================================================
-- LOCATION HISTORY (Target Movement Tracking)
-- ============================================================================

CREATE TABLE target_location_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Location
    location_name VARCHAR(500),
    address VARCHAR(1000),
    city VARCHAR(200),
    state VARCHAR(200),
    country VARCHAR(100) NOT NULL,
    postal_code VARCHAR(50),
    coords POINT,

    -- Timing
    sighting_time TIMESTAMP NOT NULL,
    departure_time TIMESTAMP,
    duration_minutes INTEGER,

    -- Source
    source VARCHAR(200) NOT NULL, -- surveillance, osint, informant, facial_recognition, financial
    source_system VARCHAR(200),
    source_id VARCHAR(255),

    -- Confidence
    confidence DECIMAL(5,4) NOT NULL DEFAULT 0.5,
    is_verified BOOLEAN DEFAULT false,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,

    -- Associated Data
    evidence_id UUID REFERENCES evidence(id),
    alert_id UUID REFERENCES alerts(id),
    surveillance_event_id UUID,

    -- Media
    image_url VARCHAR(1000),
    video_url VARCHAR(1000),

    -- Context
    activity_description TEXT,
    companions TEXT[] DEFAULT ARRAY[]::TEXT[], -- People seen with target

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_location_history_target ON target_location_history(target_id);
CREATE INDEX idx_location_history_time ON target_location_history(sighting_time DESC);
CREATE INDEX idx_location_history_country ON target_location_history(country);
CREATE INDEX idx_location_history_city ON target_location_history(city);
CREATE INDEX idx_location_history_coords ON target_location_history USING gist(coords);
CREATE INDEX idx_location_history_source ON target_location_history(source);
CREATE INDEX idx_location_history_investigation ON target_location_history(investigation_id);

-- ============================================================================
-- SAVED SEARCHES
-- ============================================================================

CREATE TABLE saved_searches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Search Details
    name VARCHAR(200) NOT NULL,
    description TEXT,
    search_type VARCHAR(100) NOT NULL, -- target, investigation, evidence, intelligence, blockchain

    -- Query
    query_params JSONB NOT NULL, -- Saved search parameters

    -- Display
    sort_field VARCHAR(100),
    sort_order VARCHAR(10) DEFAULT 'desc',
    columns_visible TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Alerts
    alert_on_new_results BOOLEAN DEFAULT false,
    alert_frequency VARCHAR(50), -- immediate, hourly, daily
    last_alert_sent_at TIMESTAMP,

    -- Usage
    is_favorite BOOLEAN DEFAULT false,
    last_used_at TIMESTAMP,
    use_count INTEGER DEFAULT 0,

    -- Sharing
    is_shared BOOLEAN DEFAULT false,
    shared_with UUID[] DEFAULT ARRAY[]::UUID[],

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_saved_searches_user ON saved_searches(user_id);
CREATE INDEX idx_saved_searches_type ON saved_searches(search_type);
CREATE INDEX idx_saved_searches_favorite ON saved_searches(user_id, is_favorite) WHERE is_favorite = true;

-- ============================================================================
-- CASE FILES (Investigation Documents)
-- ============================================================================

CREATE TABLE case_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    -- File Details
    file_name VARCHAR(500) NOT NULL,
    file_path VARCHAR(1000),
    file_url VARCHAR(1000),
    file_size_bytes BIGINT,
    mime_type VARCHAR(200),
    file_hash_sha256 VARCHAR(64),

    -- Classification
    file_type VARCHAR(100) NOT NULL, -- report, transcript, legal_document, correspondence, media, other
    title VARCHAR(500),
    description TEXT,
    classification_level VARCHAR(50) DEFAULT 'CONFIDENTIAL',

    -- Document Metadata
    document_date DATE,
    author VARCHAR(500),
    source VARCHAR(500),
    version VARCHAR(50) DEFAULT '1.0',

    -- Processing
    is_ocr_processed BOOLEAN DEFAULT false,
    ocr_text TEXT,
    is_ai_analyzed BOOLEAN DEFAULT false,
    ai_summary TEXT,
    extracted_entities JSONB, -- Named entities extracted

    -- Tags and Categories
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    categories TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_case_files_investigation ON case_files(investigation_id);
CREATE INDEX idx_case_files_type ON case_files(file_type);
CREATE INDEX idx_case_files_hash ON case_files(file_hash_sha256);
CREATE INDEX idx_case_files_tags ON case_files USING gin(tags);
CREATE INDEX idx_case_files_created ON case_files(created_at DESC);

-- Full-text search on case file content
CREATE INDEX idx_case_files_fts ON case_files USING gin(
    to_tsvector('english',
        coalesce(title, '') || ' ' ||
        coalesce(description, '') || ' ' ||
        coalesce(ocr_text, '')
    )
);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_field_reports_updated_at BEFORE UPDATE ON field_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_settings_updated_at BEFORE UPDATE ON user_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_financial_profiles_updated_at BEFORE UPDATE ON financial_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bank_accounts_updated_at BEFORE UPDATE ON target_bank_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_crypto_wallets_updated_at BEFORE UPDATE ON target_crypto_wallets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assets_updated_at BEFORE UPDATE ON target_assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_associations_updated_at BEFORE UPDATE ON target_associations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_saved_searches_updated_at BEFORE UPDATE ON saved_searches
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_case_files_updated_at BEFORE UPDATE ON case_files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DEFAULT PERMISSIONS
-- ============================================================================

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action, scope) VALUES
    -- User permissions
    ('users:read:own', 'View own user profile', 'users', 'read', 'own'),
    ('users:read:all', 'View all user profiles', 'users', 'read', 'all'),
    ('users:update:own', 'Update own user profile', 'users', 'update', 'own'),
    ('users:update:all', 'Update any user profile', 'users', 'update', 'all'),
    ('users:create', 'Create new users', 'users', 'create', 'all'),
    ('users:delete', 'Delete users', 'users', 'delete', 'all'),

    -- Investigation permissions
    ('investigations:read:own', 'View assigned investigations', 'investigations', 'read', 'own'),
    ('investigations:read:team', 'View team investigations', 'investigations', 'read', 'team'),
    ('investigations:read:all', 'View all investigations', 'investigations', 'read', 'all'),
    ('investigations:create', 'Create investigations', 'investigations', 'create', 'all'),
    ('investigations:update:own', 'Update assigned investigations', 'investigations', 'update', 'own'),
    ('investigations:update:all', 'Update any investigation', 'investigations', 'update', 'all'),
    ('investigations:delete', 'Delete investigations', 'investigations', 'delete', 'all'),

    -- Target permissions
    ('targets:read:own', 'View targets in assigned investigations', 'targets', 'read', 'own'),
    ('targets:read:all', 'View all targets', 'targets', 'read', 'all'),
    ('targets:create', 'Create targets', 'targets', 'create', 'all'),
    ('targets:update', 'Update targets', 'targets', 'update', 'all'),
    ('targets:delete', 'Delete targets', 'targets', 'delete', 'all'),

    -- Evidence permissions
    ('evidence:read:own', 'View evidence in assigned cases', 'evidence', 'read', 'own'),
    ('evidence:read:all', 'View all evidence', 'evidence', 'read', 'all'),
    ('evidence:create', 'Create evidence records', 'evidence', 'create', 'all'),
    ('evidence:update', 'Update evidence records', 'evidence', 'update', 'all'),
    ('evidence:delete', 'Delete evidence records', 'evidence', 'delete', 'all'),

    -- Intelligence permissions
    ('intelligence:read:own', 'View intelligence for assigned cases', 'intelligence', 'read', 'own'),
    ('intelligence:read:all', 'View all intelligence', 'intelligence', 'read', 'all'),
    ('intelligence:create', 'Create intelligence reports', 'intelligence', 'create', 'all'),
    ('intelligence:update', 'Update intelligence reports', 'intelligence', 'update', 'all'),
    ('intelligence:verify', 'Verify intelligence reports', 'intelligence', 'execute', 'all'),

    -- Operations permissions
    ('operations:read:own', 'View assigned operations', 'operations', 'read', 'own'),
    ('operations:read:all', 'View all operations', 'operations', 'read', 'all'),
    ('operations:create', 'Create operations', 'operations', 'create', 'all'),
    ('operations:update', 'Update operations', 'operations', 'update', 'all'),
    ('operations:approve', 'Approve operations', 'operations', 'approve', 'all'),

    -- Admin permissions
    ('admin:users', 'Administer users', 'admin', 'execute', 'all'),
    ('admin:system', 'System administration', 'admin', 'execute', 'all'),
    ('admin:audit', 'View audit logs', 'admin', 'read', 'all'),
    ('admin:export', 'Export data', 'admin', 'execute', 'all')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
-- Admin gets all permissions
INSERT INTO role_permissions (role, permission_id)
SELECT 'admin'::user_role, p.id FROM permissions p
ON CONFLICT (role, permission_id) DO NOTHING;

-- Lead investigator permissions
INSERT INTO role_permissions (role, permission_id)
SELECT 'lead_investigator'::user_role, p.id
FROM permissions p
WHERE p.name IN (
    'users:read:all', 'users:update:own',
    'investigations:read:all', 'investigations:create', 'investigations:update:all',
    'targets:read:all', 'targets:create', 'targets:update',
    'evidence:read:all', 'evidence:create', 'evidence:update',
    'intelligence:read:all', 'intelligence:create', 'intelligence:update', 'intelligence:verify',
    'operations:read:all', 'operations:create', 'operations:update', 'operations:approve'
)
ON CONFLICT (role, permission_id) DO NOTHING;

-- Investigator permissions
INSERT INTO role_permissions (role, permission_id)
SELECT 'investigator'::user_role, p.id
FROM permissions p
WHERE p.name IN (
    'users:read:own', 'users:update:own',
    'investigations:read:team', 'investigations:create', 'investigations:update:own',
    'targets:read:all', 'targets:create', 'targets:update',
    'evidence:read:all', 'evidence:create', 'evidence:update',
    'intelligence:read:all', 'intelligence:create',
    'operations:read:own', 'operations:create', 'operations:update'
)
ON CONFLICT (role, permission_id) DO NOTHING;

-- Analyst permissions
INSERT INTO role_permissions (role, permission_id)
SELECT 'analyst'::user_role, p.id
FROM permissions p
WHERE p.name IN (
    'users:read:own', 'users:update:own',
    'investigations:read:team',
    'targets:read:all',
    'evidence:read:all',
    'intelligence:read:all', 'intelligence:create',
    'operations:read:own'
)
ON CONFLICT (role, permission_id) DO NOTHING;

-- Viewer permissions
INSERT INTO role_permissions (role, permission_id)
SELECT 'viewer'::user_role, p.id
FROM permissions p
WHERE p.name IN (
    'users:read:own',
    'investigations:read:own',
    'targets:read:own',
    'evidence:read:own',
    'intelligence:read:own',
    'operations:read:own'
)
ON CONFLICT (role, permission_id) DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE permissions IS 'Granular permission definitions for role-based access control';
COMMENT ON TABLE role_permissions IS 'Mapping of permissions to user roles';
COMMENT ON TABLE user_permissions IS 'User-specific permission overrides';
COMMENT ON TABLE field_reports IS 'Field reports from operations and surveillance';
COMMENT ON TABLE notifications IS 'User notifications and alerts';
COMMENT ON TABLE activity_logs IS 'Comprehensive audit trail of all system activities';
COMMENT ON TABLE user_settings IS 'User preferences and display settings';
COMMENT ON TABLE financial_profiles IS 'Detailed financial profiles for targets';
COMMENT ON TABLE target_bank_accounts IS 'Bank accounts linked to targets';
COMMENT ON TABLE target_crypto_wallets IS 'Cryptocurrency wallets linked to targets';
COMMENT ON TABLE target_assets IS 'Physical and digital assets owned by targets';
COMMENT ON TABLE target_associations IS 'Relationships between targets';
COMMENT ON TABLE target_location_history IS 'Historical location data for targets';
COMMENT ON TABLE saved_searches IS 'User saved search queries';
COMMENT ON TABLE case_files IS 'Documents and files associated with investigations';

-- Update schema version
INSERT INTO schema_version (version, description)
VALUES ('1.2.0', 'Additional tables for permissions, notifications, financial tracking, associations, and case files');
