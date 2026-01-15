-- Evidence and Intelligence Tables
-- Critical for storing investigation evidence and intelligence data

-- Evidence table
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Evidence Classification
    evidence_number VARCHAR(100) UNIQUE,
    evidence_type evidence_type NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    summary TEXT,

    -- File Information
    file_url VARCHAR(1000),
    file_path VARCHAR(1000),
    file_name VARCHAR(500),
    file_size_bytes BIGINT,
    file_mime_type VARCHAR(100),
    file_hash_sha256 VARCHAR(64), -- For integrity verification
    file_hash_md5 VARCHAR(32),

    -- Source Information
    source_type VARCHAR(100), -- osint, surveillance, informant, seizure, subpoena
    source_description TEXT,
    source_reliability VARCHAR(50), -- verified, probable, possible, unconfirmed
    collected_date TIMESTAMP,
    collected_location VARCHAR(500),
    collected_by UUID REFERENCES users(id),

    -- Legal Chain of Custody
    chain_of_custody JSONB DEFAULT '[]'::jsonb, -- Array of custody transfers
    is_admissible BOOLEAN DEFAULT true,
    legal_notes TEXT,
    seizure_warrant_number VARCHAR(100),
    subpoena_number VARCHAR(100),

    -- Processing Status
    is_processed BOOLEAN DEFAULT false,
    processed_at TIMESTAMP,
    processed_by UUID REFERENCES users(id),
    processing_notes TEXT,

    -- Analysis
    analysis_results JSONB,
    ai_analysis JSONB, -- AI-generated analysis
    extracted_data JSONB, -- Structured data extracted from evidence

    -- Classification & Security
    classification_level VARCHAR(50) DEFAULT 'CONFIDENTIAL',
    access_restrictions TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_sealed BOOLEAN DEFAULT false,

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    related_evidence_ids UUID[] DEFAULT ARRAY[]::UUID[],
    metadata JSONB DEFAULT '{}'::jsonb,
    notes TEXT,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX idx_evidence_target ON evidence(target_id);
CREATE INDEX idx_evidence_type ON evidence(evidence_type);
CREATE INDEX idx_evidence_number ON evidence(evidence_number);
CREATE INDEX idx_evidence_hash ON evidence(file_hash_sha256);
CREATE INDEX idx_evidence_collected ON evidence(collected_date);
CREATE INDEX idx_evidence_tags ON evidence USING gin(tags);
CREATE INDEX idx_evidence_created ON evidence(created_at);

-- Intelligence reports table
CREATE TABLE intelligence_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Report Information
    report_number VARCHAR(100) UNIQUE,
    intelligence_type intelligence_type NOT NULL,
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    content TEXT NOT NULL,
    key_findings TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Source Information
    source VARCHAR(200) NOT NULL, -- sherlock, blockchain_analyzer, facial_recognition, etc.
    source_tool VARCHAR(200), -- Specific tool that generated this
    source_confidence DECIMAL(3,2) CHECK (source_confidence >= 0 AND source_confidence <= 1), -- 0.00 to 1.00
    collection_method VARCHAR(200),

    -- Verification
    is_verified BOOLEAN DEFAULT false,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,
    verification_notes TEXT,
    corroborating_reports UUID[] DEFAULT ARRAY[]::UUID[],

    -- Processing
    raw_data JSONB, -- Original data from tool
    processed_data JSONB, -- Cleaned/structured data
    ai_enrichment JSONB, -- AI-added context

    -- Timeline
    intelligence_date TIMESTAMP, -- When the intelligence was collected
    reporting_date TIMESTAMP DEFAULT NOW(), -- When it was reported to system

    -- Actionability
    is_actionable BOOLEAN DEFAULT false,
    action_items TEXT[] DEFAULT ARRAY[]::TEXT[],
    priority VARCHAR(50) DEFAULT 'medium',

    -- Linking
    related_evidence UUID REFERENCES evidence(id),
    related_reports UUID[] DEFAULT ARRAY[]::UUID[],
    linked_targets UUID[] DEFAULT ARRAY[]::UUID[],

    -- Metadata
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    metadata JSONB DEFAULT '{}'::jsonb,
    classification_level VARCHAR(50) DEFAULT 'CONFIDENTIAL',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_intel_investigation ON intelligence_reports(investigation_id);
CREATE INDEX idx_intel_target ON intelligence_reports(target_id);
CREATE INDEX idx_intel_type ON intelligence_reports(intelligence_type);
CREATE INDEX idx_intel_source ON intelligence_reports(source);
CREATE INDEX idx_intel_verified ON intelligence_reports(is_verified);
CREATE INDEX idx_intel_actionable ON intelligence_reports(is_actionable);
CREATE INDEX idx_intel_date ON intelligence_reports(intelligence_date);
CREATE INDEX idx_intel_tags ON intelligence_reports USING gin(tags);
CREATE INDEX idx_intel_created ON intelligence_reports(created_at);

-- Full-text search on intelligence
CREATE INDEX idx_intel_fts ON intelligence_reports USING gin(
    to_tsvector('english',
        coalesce(title, '') || ' ' ||
        coalesce(summary, '') || ' ' ||
        coalesce(content, '')
    )
);

-- Alerts table (real-time notifications)
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Alert Information
    alert_type VARCHAR(100) NOT NULL, -- facial_match, blockchain_movement, location_detected, etc.
    severity alert_severity NOT NULL DEFAULT 'medium',
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    details JSONB,

    -- Source
    source_system VARCHAR(200) NOT NULL, -- facial_recognition_system, blockchain_monitor, etc.
    source_id VARCHAR(255), -- ID in source system
    detection_time TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Match/Detection Information
    confidence_score DECIMAL(5,4), -- 0.0000 to 1.0000
    match_threshold DECIMAL(5,4), -- Threshold used for detection
    location_detected VARCHAR(500),
    location_coords POINT,

    -- Evidence Links
    image_url VARCHAR(1000),
    video_url VARCHAR(1000),
    evidence_id UUID REFERENCES evidence(id),
    intelligence_report_id UUID REFERENCES intelligence_reports(id),

    -- Status
    is_acknowledged BOOLEAN DEFAULT false,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP,

    is_verified BOOLEAN DEFAULT false,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,
    verification_result VARCHAR(50), -- true_positive, false_positive, unknown

    is_dismissed BOOLEAN DEFAULT false,
    dismissed_by UUID REFERENCES users(id),
    dismissed_at TIMESTAMP,
    dismissed_reason TEXT,

    -- Actions Taken
    actions_taken TEXT[] DEFAULT ARRAY[]::TEXT[],
    assigned_to UUID[] DEFAULT ARRAY[]::UUID[],

    -- Notifications
    notification_sent BOOLEAN DEFAULT false,
    notified_users UUID[] DEFAULT ARRAY[]::UUID[],

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],

    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE INDEX idx_alerts_investigation ON alerts(investigation_id);
CREATE INDEX idx_alerts_target ON alerts(target_id);
CREATE INDEX idx_alerts_type ON alerts(alert_type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_acknowledged ON alerts(is_acknowledged) WHERE is_acknowledged = false;
CREATE INDEX idx_alerts_verified ON alerts(is_verified);
CREATE INDEX idx_alerts_detection_time ON alerts(detection_time);
CREATE INDEX idx_alerts_location ON alerts USING gist(location_coords);
CREATE INDEX idx_alerts_created ON alerts(created_at);

-- Operations table (planned/executed operations)
CREATE TABLE operations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,

    -- Operation Details
    operation_number VARCHAR(100) UNIQUE,
    operation_name VARCHAR(200) NOT NULL,
    operation_type operation_type NOT NULL,
    status VARCHAR(50) DEFAULT 'planning', -- planning, approved, in_progress, completed, cancelled
    priority VARCHAR(50) DEFAULT 'medium',

    -- Planning
    objective TEXT NOT NULL,
    strategy TEXT,
    resources_required TEXT,
    risk_assessment TEXT,
    legal_authorization TEXT,
    warrant_numbers TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Scheduling
    planned_date TIMESTAMP,
    scheduled_start TIMESTAMP,
    scheduled_end TIMESTAMP,
    actual_start TIMESTAMP,
    actual_end TIMESTAMP,

    -- Team
    operation_lead UUID REFERENCES users(id),
    team_members UUID[] DEFAULT ARRAY[]::UUID[],
    external_agencies TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Location
    operation_location VARCHAR(500),
    operation_coords POINT,

    -- Results
    outcome VARCHAR(50), -- success, partial_success, failure, aborted
    result_summary TEXT,
    evidence_collected UUID[] DEFAULT ARRAY[]::UUID[],
    arrests_made INTEGER DEFAULT 0,
    seizures JSONB,

    -- After-Action
    after_action_report TEXT,
    lessons_learned TEXT,
    follow_up_required BOOLEAN DEFAULT false,
    follow_up_notes TEXT,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    classification_level VARCHAR(50) DEFAULT 'SECRET',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_operations_investigation ON operations(investigation_id);
CREATE INDEX idx_operations_target ON operations(target_id);
CREATE INDEX idx_operations_type ON operations(operation_type);
CREATE INDEX idx_operations_status ON operations(status);
CREATE INDEX idx_operations_date ON operations(planned_date);
CREATE INDEX idx_operations_lead ON operations(operation_lead);
CREATE INDEX idx_operations_created ON operations(created_at);

-- Triggers
CREATE TRIGGER update_evidence_updated_at BEFORE UPDATE ON evidence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_intelligence_updated_at BEFORE UPDATE ON intelligence_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_operations_updated_at BEFORE UPDATE ON operations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to automatically generate evidence numbers
CREATE OR REPLACE FUNCTION generate_evidence_number()
RETURNS TRIGGER AS $$
DECLARE
    inv_case_number VARCHAR(100);
    evidence_count INTEGER;
    new_evidence_number VARCHAR(100);
BEGIN
    -- Get investigation case number
    SELECT case_number INTO inv_case_number
    FROM investigations
    WHERE id = NEW.investigation_id;

    -- Count existing evidence for this investigation
    SELECT COUNT(*) + 1 INTO evidence_count
    FROM evidence
    WHERE investigation_id = NEW.investigation_id;

    -- Generate: CASE_NUMBER-E-NNNN
    new_evidence_number := inv_case_number || '-E-' || LPAD(evidence_count::TEXT, 4, '0');

    NEW.evidence_number := new_evidence_number;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER generate_evidence_number_trigger
BEFORE INSERT ON evidence
FOR EACH ROW
WHEN (NEW.evidence_number IS NULL OR NEW.evidence_number = '')
EXECUTE FUNCTION generate_evidence_number();

-- Function to send alert notifications (placeholder - will be implemented by Agent 1)
CREATE OR REPLACE FUNCTION notify_alert()
RETURNS TRIGGER AS $$
BEGIN
    -- This will trigger notification service
    -- Implementation will be added by Agent 1 (Backend Services)
    PERFORM pg_notify('apollo_alerts', json_build_object(
        'alert_id', NEW.id,
        'investigation_id', NEW.investigation_id,
        'target_id', NEW.target_id,
        'severity', NEW.severity,
        'title', NEW.title
    )::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER alert_notification_trigger
AFTER INSERT ON alerts
FOR EACH ROW
EXECUTE FUNCTION notify_alert();

COMMENT ON TABLE evidence IS 'Digital and physical evidence with chain of custody tracking';
COMMENT ON TABLE intelligence_reports IS 'Intelligence gathered from OSINT, SIGINT, GEOINT, and other sources';
COMMENT ON TABLE alerts IS 'Real-time alerts from facial recognition, blockchain monitoring, and other systems';
COMMENT ON TABLE operations IS 'Planned and executed law enforcement operations';
