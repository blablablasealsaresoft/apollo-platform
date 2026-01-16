-- Apollo Platform - Database Initialization
-- High-value target investigation platform
-- Created: 2026-01-14

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- For advanced indexing
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- For query performance monitoring

-- Create custom types
CREATE TYPE user_role AS ENUM ('admin', 'lead_investigator', 'investigator', 'analyst', 'field_agent', 'viewer', 'external');
CREATE TYPE clearance_level AS ENUM ('unclassified', 'restricted', 'confidential', 'secret', 'top_secret');
CREATE TYPE investigation_status AS ENUM ('planning', 'active', 'on_hold', 'monitoring', 'closed', 'archived', 'suspended');
CREATE TYPE investigation_priority AS ENUM ('low', 'medium', 'high', 'critical', 'top_ten');
CREATE TYPE target_status AS ENUM ('active', 'monitoring', 'located', 'apprehended', 'deceased', 'cleared', 'unknown');
CREATE TYPE threat_level AS ENUM ('low', 'medium', 'high', 'extreme', 'fbi_most_wanted');
CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'extreme');
CREATE TYPE evidence_type AS ENUM ('document', 'photo', 'video', 'audio', 'digital', 'physical', 'testimony', 'financial', 'communication');
CREATE TYPE intelligence_type AS ENUM ('osint', 'sigint', 'geoint', 'humint', 'finint', 'imint', 'techint', 'blockchain', 'facial_recognition', 'voice_recognition');
CREATE TYPE intelligence_source AS ENUM ('humint', 'sigint', 'osint', 'geoint', 'finint', 'techint');
CREATE TYPE confidence_level AS ENUM ('verified', 'high', 'medium', 'low', 'unconfirmed');
CREATE TYPE alert_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical', 'immediate');
CREATE TYPE alert_status AS ENUM ('new', 'acknowledged', 'in_progress', 'resolved', 'dismissed');
CREATE TYPE operation_type AS ENUM ('surveillance', 'raid', 'interview', 'arrest', 'search', 'monitoring', 'undercover', 'digital_forensics', 'asset_seizure');
CREATE TYPE operation_status AS ENUM ('planning', 'approved', 'active', 'on_hold', 'in_progress', 'completed', 'cancelled', 'archived');

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Set timezone to UTC for all operations
SET timezone = 'UTC';

-- Create schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL,
    description TEXT,
    applied_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO schema_version (version, description)
VALUES ('1.0.0', 'Initial Apollo platform database schema');

-- Grant permissions to apollo_admin user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO apollo_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO apollo_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO apollo_admin;
