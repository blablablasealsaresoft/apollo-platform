-- Investigations and Targets Tables
-- Core tables for criminal investigations and high-value targets

-- Investigations table
CREATE TABLE investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_number VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    status investigation_status NOT NULL DEFAULT 'planning',
    priority investigation_priority NOT NULL DEFAULT 'medium',
    classification VARCHAR(50) DEFAULT 'CONFIDENTIAL',
    lead_investigator_id UUID NOT NULL REFERENCES users(id),
    assigned_agency VARCHAR(200),
    case_type VARCHAR(100), -- fraud, trafficking, terrorism, cryptocurrency, predator
    target_category VARCHAR(100), -- fugitive, financial_criminal, cyber_criminal, predator
    estimated_value DECIMAL(20,2), -- Estimated value of crime/loss
    jurisdiction VARCHAR(200),
    start_date DATE DEFAULT CURRENT_DATE,
    target_apprehension_date DATE,
    closed_date DATE,
    outcome TEXT,
    lessons_learned TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

CREATE INDEX idx_investigations_case_number ON investigations(case_number);
CREATE INDEX idx_investigations_status ON investigations(status);
CREATE INDEX idx_investigations_priority ON investigations(priority);
CREATE INDEX idx_investigations_lead ON investigations(lead_investigator_id);
CREATE INDEX idx_investigations_dates ON investigations(start_date, closed_date);
CREATE INDEX idx_investigations_type ON investigations(case_type);
CREATE INDEX idx_investigations_tags ON investigations USING gin(tags);
CREATE INDEX idx_investigations_created ON investigations(created_at);

-- Investigation team members
CREATE TABLE investigation_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(100) NOT NULL, -- lead, investigator, analyst, consultant
    permissions JSONB DEFAULT '{"read": true, "write": false, "admin": false}'::jsonb,
    joined_at TIMESTAMP DEFAULT NOW(),
    left_at TIMESTAMP,
    added_by UUID NOT NULL REFERENCES users(id),
    UNIQUE(investigation_id, user_id)
);

CREATE INDEX idx_inv_members_investigation ON investigation_members(investigation_id);
CREATE INDEX idx_inv_members_user ON investigation_members(user_id);
CREATE INDEX idx_inv_members_active ON investigation_members(investigation_id, user_id) WHERE left_at IS NULL;

-- Targets table (high-value individuals being investigated)
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,

    -- Personal Information
    first_name VARCHAR(100),
    middle_name VARCHAR(100),
    last_name VARCHAR(100),
    full_name VARCHAR(300),
    aliases TEXT[] DEFAULT ARRAY[]::TEXT[],
    date_of_birth DATE,
    age_estimate INTEGER,
    place_of_birth VARCHAR(200),
    nationality VARCHAR(100),
    secondary_nationalities TEXT[] DEFAULT ARRAY[]::TEXT[],
    gender VARCHAR(50),

    -- Physical Description
    height_cm INTEGER,
    weight_kg INTEGER,
    eye_color VARCHAR(50),
    hair_color VARCHAR(50),
    distinguishing_marks TEXT,
    build VARCHAR(50),
    ethnicity VARCHAR(100),

    -- Identification
    passport_numbers TEXT[] DEFAULT ARRAY[]::TEXT[],
    national_id_numbers TEXT[] DEFAULT ARRAY[]::TEXT[],
    driver_license_numbers TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_phone_numbers TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_email_addresses TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_social_media TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_cryptocurrency_addresses TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Location
    last_known_location VARCHAR(500),
    last_known_location_coords POINT,
    last_seen_date DATE,
    possible_locations TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_addresses TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Status
    status target_status NOT NULL DEFAULT 'active',
    threat_level threat_level NOT NULL DEFAULT 'medium',
    is_armed BOOLEAN DEFAULT false,
    is_dangerous BOOLEAN DEFAULT false,
    special_handling_notes TEXT,

    -- Criminal Information
    criminal_history TEXT,
    known_associates TEXT[] DEFAULT ARRAY[]::TEXT[],
    known_organizations TEXT[] DEFAULT ARRAY[]::TEXT[],
    estimated_wealth DECIMAL(20,2),
    reward_amount DECIMAL(20,2),

    -- Media
    photo_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    video_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    audio_urls TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Biometric Data (stored as JSON for flexibility)
    facial_encodings JSONB, -- Array of face encoding vectors
    voice_print JSONB, -- Voice biometric data
    fingerprints JSONB, -- Fingerprint data if available
    dna_profile JSONB, -- DNA markers if available

    -- Intelligence
    languages_spoken TEXT[] DEFAULT ARRAY[]::TEXT[],
    education TEXT,
    occupation TEXT,
    skills TEXT[] DEFAULT ARRAY[]::TEXT[],
    habits TEXT[] DEFAULT ARRAY[]::TEXT[],
    psychological_profile TEXT,

    -- Investigation Notes
    notes TEXT,
    threat_assessment TEXT,
    capture_strategy TEXT,

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    external_references JSONB, -- Links to FBI, Interpol, etc.

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id)
);

-- Comprehensive indexes for fast searching
CREATE INDEX idx_targets_investigation ON targets(investigation_id);
CREATE INDEX idx_targets_name ON targets(last_name, first_name);
CREATE INDEX idx_targets_full_name ON targets(full_name);
CREATE INDEX idx_targets_aliases ON targets USING gin(aliases);
CREATE INDEX idx_targets_status ON targets(status);
CREATE INDEX idx_targets_threat ON targets(threat_level);
CREATE INDEX idx_targets_location ON targets USING gist(last_known_location_coords);
CREATE INDEX idx_targets_dob ON targets(date_of_birth);
CREATE INDEX idx_targets_phones ON targets USING gin(known_phone_numbers);
CREATE INDEX idx_targets_emails ON targets USING gin(known_email_addresses);
CREATE INDEX idx_targets_crypto ON targets USING gin(known_cryptocurrency_addresses);
CREATE INDEX idx_targets_tags ON targets USING gin(tags);
CREATE INDEX idx_targets_created ON targets(created_at);

-- Full-text search on target data
CREATE INDEX idx_targets_fts ON targets USING gin(
    to_tsvector('english',
        coalesce(full_name, '') || ' ' ||
        coalesce(array_to_string(aliases, ' '), '') || ' ' ||
        coalesce(notes, '')
    )
);

-- Triggers for auto-updating
CREATE TRIGGER update_investigations_updated_at BEFORE UPDATE ON investigations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON targets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to automatically generate case number
CREATE OR REPLACE FUNCTION generate_case_number()
RETURNS TRIGGER AS $$
DECLARE
    prefix VARCHAR(10);
    year VARCHAR(4);
    sequence INTEGER;
    new_case_number VARCHAR(100);
BEGIN
    -- Determine prefix based on case type
    CASE NEW.case_type
        WHEN 'cryptocurrency' THEN prefix := 'CRYPTO';
        WHEN 'fraud' THEN prefix := 'FRAUD';
        WHEN 'trafficking' THEN prefix := 'TRAFFIC';
        WHEN 'terrorism' THEN prefix := 'TERROR';
        WHEN 'predator' THEN prefix := 'PRED';
        ELSE prefix := 'INV';
    END CASE;

    year := EXTRACT(YEAR FROM NOW())::VARCHAR;

    -- Get next sequence number for this year
    SELECT COALESCE(MAX(
        SUBSTRING(case_number FROM '[0-9]+$')::INTEGER
    ), 0) + 1
    INTO sequence
    FROM investigations
    WHERE case_number LIKE prefix || '-' || year || '%';

    -- Generate case number: PREFIX-YYYY-NNNN
    new_case_number := prefix || '-' || year || '-' || LPAD(sequence::TEXT, 4, '0');

    NEW.case_number := new_case_number;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-generate case numbers if not provided
CREATE TRIGGER generate_case_number_trigger
BEFORE INSERT ON investigations
FOR EACH ROW
WHEN (NEW.case_number IS NULL OR NEW.case_number = '')
EXECUTE FUNCTION generate_case_number();

-- Insert Ignatova investigation
INSERT INTO investigations (
    case_number,
    title,
    description,
    status,
    priority,
    classification,
    lead_investigator_id,
    case_type,
    target_category,
    estimated_value,
    start_date,
    tags,
    created_by
)
SELECT
    'CRYPTO-2026-0001',
    'OneCoin - Ruja Ignatova (CryptoQueen)',
    'Investigation into Ruja Ignatova, founder of $4 billion OneCoin cryptocurrency fraud. Subject is on FBI Top 10 Most Wanted list. Last known location: possibly Dubai, UAE. Case involves international fraud, money laundering, and organized crime.',
    'active',
    'top_ten',
    'SECRET',
    u.id,
    'cryptocurrency',
    'fugitive',
    4000000000.00,
    '2017-10-25',
    ARRAY['fbi_most_wanted', 'cryptocurrency', 'fraud', 'international', 'high_value_target'],
    u.id
FROM users u
WHERE u.username = 'apollo_admin'
ON CONFLICT (case_number) DO NOTHING;

-- Insert Ruja Ignatova as target
INSERT INTO targets (
    investigation_id,
    first_name,
    middle_name,
    last_name,
    full_name,
    aliases,
    date_of_birth,
    place_of_birth,
    nationality,
    gender,
    height_cm,
    eye_color,
    hair_color,
    status,
    threat_level,
    last_seen_date,
    possible_locations,
    known_organizations,
    estimated_wealth,
    reward_amount,
    criminal_history,
    notes,
    tags,
    metadata,
    created_by
)
SELECT
    i.id,
    'Ruja',
    'Plamenova',
    'Ignatova',
    'Ruja Plamenova Ignatova',
    ARRAY['CryptoQueen', 'Dr. Ruja', 'The Missing Cryptoqueen'],
    '1980-05-30',
    'Sofia, Bulgaria',
    'Bulgaria',
    'Female',
    165,
    'Brown',
    'Dark Brown',
    'active',
    'fbi_most_wanted',
    '2017-10-25',
    ARRAY['Dubai, UAE', 'Bulgaria', 'Germany', 'Greece', 'Russia'],
    ARRAY['OneCoin', 'OneLife'],
    4000000000.00,
    250000.00,
    'Founder of OneCoin, a $4 billion cryptocurrency Ponzi scheme. Wanted by FBI, Europol, and multiple international agencies. Disappeared October 2017. Armed and dangerous status unknown.',
    'Subject disappeared in October 2017 after being tipped off about investigation. Believed to have undergone plastic surgery. May be traveling under false identity. Has significant financial resources. Brother Konstantin Ignatov arrested and cooperating. Last confirmed sighting in Athens, Greece before disappearance. High-priority target.',
    ARRAY['fbi_most_wanted', 'cryptocurrency', 'fraud', 'international_fugitive', 'high_value'],
    jsonb_build_object(
        'fbi_case', 'https://www.fbi.gov/wanted/topten/ruja-ignatova',
        'reward', 250000,
        'age_at_disappearance', 37,
        'current_age_estimate', 45,
        'years_missing', 8,
        'plastic_surgery_likely', true,
        'languages', ARRAY['Bulgarian', 'English', 'German'],
        'education', 'PhD in European Private Law, University of Constance, Germany'
    ),
    u.id
FROM investigations i
JOIN users u ON u.username = 'apollo_admin'
WHERE i.case_number = 'CRYPTO-2026-0001'
ON CONFLICT DO NOTHING;

COMMENT ON TABLE investigations IS 'Criminal investigations managed through Apollo platform';
COMMENT ON TABLE targets IS 'High-value targets and persons of interest in investigations';
COMMENT ON TABLE investigation_members IS 'Team members assigned to each investigation';
COMMENT ON COLUMN targets.facial_encodings IS 'Face recognition encoding vectors for biometric matching';
COMMENT ON COLUMN targets.voice_print IS 'Voice biometric data for audio recognition';
