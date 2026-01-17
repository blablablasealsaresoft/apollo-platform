-- Apollo Platform Seed Data
-- Test data for development and demonstration

-- Store admin user ID
DO $$
DECLARE
    admin_id UUID := '20b3e119-b2dc-4af8-a32e-6449d16b6080';

    -- Investigation IDs
    inv_shadow_network UUID;
    inv_crypto_cartel UUID;
    inv_ghost_protocol UUID;
    inv_dark_money UUID;

    -- Target IDs
    target_volkov UUID;
    target_chen UUID;
    target_santos UUID;
    target_mueller UUID;
    target_nakamura UUID;

    -- Operation IDs
    op_intercept UUID;
    op_watchdog UUID;
    op_frozen_assets UUID;

BEGIN
    -- =====================================================
    -- INVESTIGATIONS
    -- =====================================================

    -- Investigation 1: Shadow Network
    INSERT INTO investigations (
        id, case_number, title, description, status, priority, classification,
        lead_investigator_id, assigned_agency, case_type, target_category,
        estimated_value, jurisdiction, start_date, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        'INV-2026-0001',
        'Operation Shadow Network',
        'Investigation into an international cybercriminal network involved in ransomware attacks against critical infrastructure. The network operates across multiple jurisdictions and has ties to state-sponsored actors.',
        'active',
        'critical',
        'TOP SECRET',
        admin_id,
        'FBI Cyber Division',
        'Cybercrime',
        'Criminal Organization',
        50000000.00,
        'International',
        '2025-11-15',
        ARRAY['ransomware', 'critical-infrastructure', 'state-sponsored', 'cryptocurrency'],
        admin_id
    ) RETURNING id INTO inv_shadow_network;

    -- Investigation 2: Crypto Cartel
    INSERT INTO investigations (
        id, case_number, title, description, status, priority, classification,
        lead_investigator_id, assigned_agency, case_type, target_category,
        estimated_value, jurisdiction, start_date, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        'INV-2026-0002',
        'Crypto Cartel Financial Network',
        'Multi-agency investigation into cryptocurrency-based money laundering operations linked to drug cartels. Evidence suggests over $2 billion in illicit funds have been processed through decentralized exchanges.',
        'active',
        'high',
        'SECRET',
        admin_id,
        'DEA / FinCEN Joint Task Force',
        'Money Laundering',
        'Drug Trafficking Organization',
        2000000000.00,
        'Americas',
        '2025-09-01',
        ARRAY['cryptocurrency', 'money-laundering', 'cartel', 'defi', 'blockchain'],
        admin_id
    ) RETURNING id INTO inv_crypto_cartel;

    -- Investigation 3: Ghost Protocol
    INSERT INTO investigations (
        id, case_number, title, description, status, priority, classification,
        lead_investigator_id, assigned_agency, case_type, target_category,
        estimated_value, jurisdiction, start_date, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        'INV-2026-0003',
        'Ghost Protocol - Insider Threat',
        'Internal investigation into potential insider threat within defense contractor network. Classified documents may have been exfiltrated over an 18-month period.',
        'active',
        'top_ten',
        'TOP SECRET',
        admin_id,
        'NSA / FBI Counterintelligence',
        'Espionage',
        'Insider Threat',
        NULL,
        'Domestic',
        '2026-01-02',
        ARRAY['insider-threat', 'espionage', 'defense-contractor', 'data-exfiltration'],
        admin_id
    ) RETURNING id INTO inv_ghost_protocol;

    -- Investigation 4: Dark Money (monitoring)
    INSERT INTO investigations (
        id, case_number, title, description, status, priority, classification,
        lead_investigator_id, assigned_agency, case_type, target_category,
        estimated_value, jurisdiction, start_date, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        'INV-2026-0004',
        'Dark Money Political Networks',
        'Long-term monitoring of suspected foreign influence operations through political action committees and shell corporations.',
        'monitoring',
        'medium',
        'SECRET',
        admin_id,
        'FBI Counterintelligence',
        'Foreign Influence',
        'Political Organization',
        75000000.00,
        'Domestic',
        '2024-06-15',
        ARRAY['foreign-influence', 'pac', 'shell-companies', 'election-interference'],
        admin_id
    ) RETURNING id INTO inv_dark_money;

    -- =====================================================
    -- TARGETS
    -- =====================================================

    -- Target 1: Viktor Volkov (Shadow Network leader)
    INSERT INTO targets (
        id, investigation_id, first_name, middle_name, last_name, full_name,
        aliases, date_of_birth, nationality, gender, status, threat_level,
        is_armed, is_dangerous, criminal_history, known_organizations,
        estimated_wealth, languages_spoken, occupation, skills,
        last_known_location, psychological_profile, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_shadow_network,
        'Viktor',
        'Alekseyevich',
        'Volkov',
        'Viktor Alekseyevich Volkov',
        ARRAY['DarkWolf', 'V.A.V.', 'The Architect'],
        '1985-03-22',
        'Russian',
        'Male',
        'active',
        'extreme',
        true,
        true,
        'Former GRU cyber operations. Suspected involvement in NotPetya attack. Multiple Interpol red notices.',
        ARRAY['Shadow Collective', 'EvilCorp remnants', 'REvil affiliates'],
        150000000.00,
        ARRAY['Russian', 'English', 'German', 'Ukrainian'],
        'Cybercrime Syndicate Leader',
        ARRAY['Advanced persistent threats', 'Zero-day exploitation', 'Ransomware development', 'Operational security'],
        'Moscow, Russia (suspected)',
        'Highly intelligent, paranoid, methodical. Shows narcissistic traits with need for recognition in underground forums. Risk-seeking but calculates odds carefully.',
        ARRAY['hacker', 'ransomware', 'gru', 'most-wanted'],
        admin_id
    ) RETURNING id INTO target_volkov;

    -- Target 2: Li Wei Chen (Crypto Cartel facilitator)
    INSERT INTO targets (
        id, investigation_id, first_name, last_name, full_name,
        aliases, date_of_birth, nationality, gender, status, threat_level,
        is_armed, is_dangerous, criminal_history, known_organizations,
        estimated_wealth, known_cryptocurrency_addresses, languages_spoken,
        occupation, skills, last_known_location, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_crypto_cartel,
        'Li Wei',
        'Chen',
        'Li Wei Chen',
        ARRAY['CryptoKing', 'The Mixer', 'LWC'],
        '1990-08-14',
        'Chinese',
        'Male',
        'active',
        'high',
        false,
        false,
        'Previously charged with securities fraud in Hong Kong (2019). Case dismissed due to insufficient evidence.',
        ARRAY['Lazarus Group (suspected)', 'Sinaloa Cartel financial network'],
        500000000.00,
        ARRAY['bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', '0x742d35Cc6634C0532925a3b844Bc9e7595f3B8A1'],
        ARRAY['Mandarin', 'English', 'Cantonese', 'Spanish'],
        'Cryptocurrency Exchange Operator',
        ARRAY['DeFi protocols', 'Smart contract development', 'Money laundering techniques', 'Offshore banking'],
        'Dubai, UAE',
        ARRAY['cryptocurrency', 'money-laundering', 'fintech'],
        admin_id
    ) RETURNING id INTO target_chen;

    -- Target 3: Maria Santos (Cartel CFO)
    INSERT INTO targets (
        id, investigation_id, first_name, last_name, full_name,
        aliases, date_of_birth, nationality, gender, status, threat_level,
        is_armed, is_dangerous, criminal_history, known_organizations,
        estimated_wealth, languages_spoken, occupation, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_crypto_cartel,
        'Maria',
        'Santos',
        'Maria Isabella Santos',
        ARRAY['La Contadora', 'The Accountant'],
        '1978-12-03',
        'Colombian',
        'Female',
        'active',
        'high',
        false,
        true,
        'Known associate of multiple cartel leaders. Suspected of orchestrating assassinations of rival accountants.',
        ARRAY['Gulf Cartel', 'CJNG financial division'],
        200000000.00,
        ARRAY['Spanish', 'English', 'Portuguese'],
        'Financial Consultant (cover)',
        ARRAY['cartel', 'finance', 'colombia'],
        admin_id
    ) RETURNING id INTO target_santos;

    -- Target 4: Hans Mueller (Insider threat suspect)
    INSERT INTO targets (
        id, investigation_id, first_name, last_name, full_name,
        aliases, date_of_birth, nationality, gender, status, threat_level,
        is_armed, is_dangerous, criminal_history, known_organizations,
        occupation, skills, last_known_location, psychological_profile, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_ghost_protocol,
        'Hans',
        'Mueller',
        'Hans Friedrich Mueller',
        ARRAY['None known'],
        '1972-06-18',
        'American',
        'Male',
        'monitoring',
        'medium',
        false,
        false,
        'No criminal history. 20-year career in defense industry with top secret clearance.',
        ARRAY['Lockheed Martin (former)', 'Raytheon (current)'],
        'Senior Systems Engineer',
        ARRAY['Classified systems access', 'Network architecture', 'Embedded systems'],
        'Arlington, Virginia',
        'Financial difficulties noted. Recent divorce proceedings. Signs of disillusionment with employer noted in digital communications.',
        ARRAY['insider-threat', 'defense-contractor', 'engineer'],
        admin_id
    ) RETURNING id INTO target_mueller;

    -- Target 5: Yuki Nakamura (Dark Money facilitator)
    INSERT INTO targets (
        id, investigation_id, first_name, last_name, full_name,
        aliases, date_of_birth, nationality, gender, status, threat_level,
        is_armed, is_dangerous, known_organizations, occupation, skills,
        last_known_location, tags, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_dark_money,
        'Yuki',
        'Nakamura',
        'Yuki Nakamura',
        ARRAY['The Facilitator', 'Y.N.'],
        '1982-04-09',
        'Japanese',
        'Female',
        'monitoring',
        'low',
        false,
        false,
        ARRAY['Unnamed PAC network', 'International consulting firms'],
        'Political Consultant',
        ARRAY['Campaign finance', 'Shell company formation', 'International wire transfers'],
        'Washington, D.C.',
        ARRAY['political', 'foreign-influence', 'pac'],
        admin_id
    ) RETURNING id INTO target_nakamura;

    -- =====================================================
    -- OPERATIONS
    -- =====================================================

    -- Operation 1: Intercept (Shadow Network)
    INSERT INTO operations (
        id, investigation_id, target_id, operation_number, operation_name,
        operation_type, status, priority, objective, strategy,
        risk_assessment, legal_authorization, planned_date,
        operation_lead, classification_level, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_shadow_network,
        target_volkov,
        'OP-2026-0001',
        'Operation Intercept',
        'digital_forensics',
        'active',
        'critical',
        'Infiltrate Shadow Network command and control infrastructure to identify all members and gather evidence for prosecution.',
        'Deploy honeypot infrastructure mimicking vulnerable targets. Establish persistent access to C2 servers. Document all communications and money flows.',
        'HIGH RISK: Target has sophisticated counter-surveillance capabilities. Potential for detection could compromise ongoing intelligence operations.',
        'FISA Court Order #2026-1847',
        '2026-01-20',
        admin_id,
        'TOP SECRET',
        admin_id
    ) RETURNING id INTO op_intercept;

    -- Operation 2: Watchdog (Crypto Cartel)
    INSERT INTO operations (
        id, investigation_id, target_id, operation_number, operation_name,
        operation_type, status, priority, objective, strategy,
        risk_assessment, legal_authorization, scheduled_start, scheduled_end,
        operation_lead, external_agencies, classification_level, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_crypto_cartel,
        target_chen,
        'OP-2026-0002',
        'Operation Watchdog',
        'surveillance',
        'approved',
        'high',
        'Conduct 24/7 surveillance of target Li Wei Chen during Dubai visit to document meetings and identify additional network members.',
        'Coordinate with UAE intelligence services for legal surveillance. Deploy technical collection assets. Document all contacts.',
        'MEDIUM RISK: Operating in foreign jurisdiction requires careful coordination. Risk of diplomatic incident if exposed.',
        'Mutual Legal Assistance Treaty (UAE-US)',
        '2026-01-25 08:00:00',
        '2026-02-10 20:00:00',
        admin_id,
        ARRAY['UAE State Security', 'Interpol Dubai', 'DEA Dubai Office'],
        'SECRET',
        admin_id
    ) RETURNING id INTO op_watchdog;

    -- Operation 3: Frozen Assets
    INSERT INTO operations (
        id, investigation_id, target_id, operation_number, operation_name,
        operation_type, status, priority, objective, strategy,
        risk_assessment, legal_authorization, planned_date,
        operation_lead, classification_level, created_by
    ) VALUES (
        uuid_generate_v4(),
        inv_crypto_cartel,
        target_santos,
        'OP-2026-0003',
        'Operation Frozen Assets',
        'asset_seizure',
        'planning',
        'high',
        'Coordinate simultaneous asset seizures across 7 countries to freeze cartel financial infrastructure.',
        'Work with OFAC to designate additional sanctions targets. Coordinate with foreign counterparts for simultaneous execution. Prepare civil forfeiture actions.',
        'MEDIUM RISK: Coordinating across multiple jurisdictions increases operational security concerns.',
        'Federal Grand Jury Subpoenas / International Asset Freeze Orders',
        '2026-02-15',
        admin_id,
        'SECRET',
        admin_id
    ) RETURNING id INTO op_frozen_assets;

    -- =====================================================
    -- INTELLIGENCE REPORTS
    -- =====================================================

    -- Intel Report 1: OSINT on Shadow Network
    INSERT INTO intelligence_reports (
        investigation_id, target_id, intelligence_type, title, summary, content,
        key_findings, source, source_confidence, collection_method,
        is_verified, verified_by, is_actionable, action_items, priority,
        classification_level, tags, created_by
    ) VALUES (
        inv_shadow_network,
        target_volkov,
        'osint',
        'Shadow Network Infrastructure Analysis',
        'Comprehensive analysis of Shadow Network digital infrastructure based on open source intelligence gathering.',
        E'Analysis of dark web forums, cryptocurrency transactions, and domain registrations has revealed the following infrastructure components:\n\n1. Command and Control Servers:\n   - Primary C2 located in bulletproof hosting in Moldova\n   - Backup C2 identified in Seychelles\n   - TOR hidden services for affiliate communication\n\n2. Financial Infrastructure:\n   - 47 cryptocurrency wallets identified\n   - Estimated $12.3M in Bitcoin across wallets\n   - Connection to Garantex exchange confirmed\n\n3. Personnel:\n   - Core team estimated at 15-20 individuals\n   - Development team likely based in Russia/Ukraine\n   - English-speaking affiliates in Western Europe',
        ARRAY['Primary C2 in Moldova bulletproof hosting', 'Backup infrastructure in Seychelles', '47 crypto wallets holding $12.3M BTC', '15-20 core team members identified'],
        'OSINT Collection Team Alpha',
        0.85,
        'Dark web monitoring, blockchain analysis, domain reconnaissance',
        true,
        admin_id,
        true,
        ARRAY['Initiate takedown request with Moldovan authorities', 'Submit wallet addresses to Chainalysis for enhanced tracking', 'Coordinate with Europol on affiliate identification'],
        'critical',
        'TOP SECRET',
        ARRAY['osint', 'infrastructure', 'cryptocurrency', 'dark-web'],
        admin_id
    );

    -- Intel Report 2: SIGINT intercept
    INSERT INTO intelligence_reports (
        investigation_id, target_id, intelligence_type, title, summary, content,
        key_findings, source, source_confidence, collection_method,
        is_verified, is_actionable, action_items, priority,
        classification_level, tags, created_by
    ) VALUES (
        inv_shadow_network,
        target_volkov,
        'sigint',
        'Intercepted Communications - Shadow Network Leadership',
        'Summary of intercepted communications between suspected Shadow Network leadership discussing upcoming operations.',
        E'CLASSIFICATION: TOP SECRET//SI//NOFORN\n\nIntercept Date: 2026-01-10\nCollection Platform: [REDACTED]\n\nSummary of Communications:\n\nSubject VOLKOV communicated with unknown individual (designated SHADOW-02) regarding planned ransomware campaign targeting US healthcare infrastructure.\n\nKey excerpts (translated from Russian):\n\nVOLKOV: "The healthcare targets are confirmed. We deploy on [date redacted]."\nSHADOW-02: "What about the new variant? Testing complete?"\nVOLKOV: "Yes. The encryption is unbreakable. Even with [REDACTED] they cannot recover."\n\nAnalysis suggests imminent attack within 30 days targeting hospital networks.',
        ARRAY['Imminent attack on US healthcare infrastructure planned', 'New ransomware variant with advanced encryption', 'Attack timeline within 30 days', 'At least 2 leadership figures identified'],
        'NSA SIGINT Collection',
        0.95,
        'Signals Intelligence',
        true,
        true,
        ARRAY['IMMEDIATE: Alert CISA for healthcare sector warning', 'Coordinate with FBI Cyber for defensive posture', 'Request additional collection resources', 'Brief healthcare ISAC'],
        'critical',
        'TOP SECRET',
        ARRAY['sigint', 'ransomware', 'healthcare', 'imminent-threat'],
        admin_id
    );

    -- Intel Report 3: FININT cryptocurrency analysis
    INSERT INTO intelligence_reports (
        investigation_id, target_id, intelligence_type, title, summary, content,
        key_findings, source, source_confidence, collection_method,
        is_verified, is_actionable, priority, classification_level, tags, created_by
    ) VALUES (
        inv_crypto_cartel,
        target_chen,
        'finint',
        'Cryptocurrency Flow Analysis - Cartel Financial Network',
        'Detailed blockchain analysis tracing drug proceeds through DeFi protocols and exchanges.',
        E'Financial Intelligence Report\nCase: Crypto Cartel\nSubject: Li Wei Chen\n\nBlockchain Analysis Summary:\n\nOur analysis has traced approximately $847 million in suspected drug proceeds through the following channels:\n\n1. Initial Deposits:\n   - Cash converted to USDT via OTC desks in Mexico\n   - Deposited to Binance using synthetic identities\n\n2. Layering:\n   - Funds routed through Tornado Cash (pre-sanctions stockpile)\n   - Multiple DeFi swaps across Uniswap, Curve, and smaller DEXs\n   - Cross-chain bridges to Ethereum, BSC, and Polygon\n\n3. Integration:\n   - Conversion to stablecoins\n   - Purchase of Dubai real estate through shell companies\n   - Investment in legitimate businesses in Southeast Asia\n\nKey Finding: Subject CHEN operates as the primary architect of this laundering system, taking a 3% fee on all processed funds.',
        ARRAY['$847M in suspected drug proceeds traced', 'Pre-sanctions Tornado Cash stockpile used', 'Dubai real estate purchases identified', 'Chen takes 3% fee as system architect'],
        'FinCEN / Chainalysis Joint Analysis',
        0.90,
        'Blockchain forensics and financial records analysis',
        true,
        true,
        'high',
        'SECRET',
        ARRAY['finint', 'cryptocurrency', 'money-laundering', 'defi'],
        admin_id
    );

    -- Intel Report 4: HUMINT on insider threat
    INSERT INTO intelligence_reports (
        investigation_id, target_id, intelligence_type, title, summary, content,
        key_findings, source, source_confidence, is_verified, is_actionable,
        priority, classification_level, tags, created_by
    ) VALUES (
        inv_ghost_protocol,
        target_mueller,
        'humint',
        'Source Report: Suspicious Activity - Defense Contractor',
        'Confidential source reports suspicious behavior by subject at defense contractor facility.',
        E'HUMAN INTELLIGENCE REPORT\nSource: [REDACTED] - Reliability: B (Usually Reliable)\n\nBackground:\nSource is a colleague of subject MUELLER at [REDACTED] defense facility with direct observation access.\n\nReported Observations:\n\n1. Subject has been accessing classified systems outside normal work hours (0200-0400 local)\n\n2. Subject was observed using personal USB device near classified terminal (strict violation of policy)\n\n3. Subject has made unusual comments about "unfair treatment" and being "passed over for promotion despite superior work"\n\n4. Source observed subject meeting with unknown Asian male at off-site location (restaurant) - subject appeared nervous, passed envelope\n\n5. Subject has recently purchased new vehicle (cash) despite known financial difficulties\n\nSource Assessment:\nBehavior pattern consistent with possible espionage recruitment and handling. Recommend enhanced surveillance.',
        ARRAY['Unauthorized after-hours access to classified systems', 'USB device policy violation observed', 'Cash purchase inconsistent with financial profile', 'Meeting with unknown contact - envelope exchange'],
        'Confidential Human Source',
        0.75,
        false,
        true,
        'critical',
        'TOP SECRET',
        ARRAY['humint', 'insider-threat', 'espionage', 'counterintelligence'],
        admin_id
    );

    -- =====================================================
    -- EVIDENCE
    -- =====================================================

    INSERT INTO evidence (
        investigation_id, evidence_type, title, description,
        source_type, source_description, collected_date, collected_by, chain_of_custody,
        classification_level, tags, created_by
    ) VALUES
    (
        inv_shadow_network,
        'digital',
        'Ransomware Binary Sample - ShadowCrypt v3.2',
        'Captured ransomware binary from honeypot deployment. Contains unique markers linking to Shadow Network infrastructure.',
        'Honeypot',
        'Honeypot Server HP-047, Washington D.C.',
        '2026-01-08',
        admin_id,
        '[{"date": "2026-01-08", "handler": "Agent Smith", "action": "Initial capture and preservation"}]',
        'SECRET',
        ARRAY['malware', 'ransomware', 'binary'],
        admin_id
    ),
    (
        inv_crypto_cartel,
        'financial',
        'Blockchain Transaction Records - January 2026',
        'Complete transaction history for 47 identified wallets associated with cartel financial network.',
        'Analytics Platform',
        'Chainalysis Reactor Platform',
        '2026-01-15',
        admin_id,
        '[{"date": "2026-01-15", "handler": "Analyst Chen", "action": "Export and verification"}]',
        'SECRET',
        ARRAY['blockchain', 'cryptocurrency', 'financial-records'],
        admin_id
    ),
    (
        inv_ghost_protocol,
        'document',
        'System Access Logs - Mueller, H.',
        'Six months of classified system access logs showing after-hours activity patterns.',
        'Security Operations',
        'Raytheon Security Operations Center',
        '2026-01-12',
        admin_id,
        '[{"date": "2026-01-12", "handler": "SSA Williams", "action": "Legal preservation request fulfilled"}]',
        'TOP SECRET',
        ARRAY['access-logs', 'insider-threat'],
        admin_id
    );

    -- =====================================================
    -- NOTIFICATIONS
    -- =====================================================

    INSERT INTO notifications (
        user_id, title, message, type, priority, is_read, action_url,
        metadata, created_at
    ) VALUES
    (
        admin_id,
        'Critical Alert: Imminent Healthcare Attack',
        'SIGINT indicates Shadow Network planning attack on US healthcare infrastructure within 30 days. Immediate action required.',
        'alert',
        'critical',
        false,
        '/investigations/shadow-network',
        jsonb_build_object('investigation_id', inv_shadow_network, 'threat_type', 'ransomware'),
        NOW() - INTERVAL '2 hours'
    ),
    (
        admin_id,
        'Operation Watchdog Approved',
        'Operation Watchdog has received final approval. Surveillance deployment scheduled for January 25, 2026.',
        'system',
        'high',
        false,
        '/operations/watchdog',
        jsonb_build_object('operation_id', op_watchdog),
        NOW() - INTERVAL '1 day'
    ),
    (
        admin_id,
        'New Intelligence Report Available',
        'FININT analysis on Crypto Cartel financial flows has been completed and uploaded.',
        'info',
        'medium',
        true,
        '/intelligence/reports',
        jsonb_build_object('investigation_id', inv_crypto_cartel),
        NOW() - INTERVAL '3 days'
    ),
    (
        admin_id,
        'Case Assignment: Ghost Protocol',
        'You have been assigned as lead investigator on Case INV-2026-0003: Ghost Protocol.',
        'assignment',
        'high',
        true,
        '/investigations/ghost-protocol',
        jsonb_build_object('investigation_id', inv_ghost_protocol),
        NOW() - INTERVAL '5 days'
    );

    -- =====================================================
    -- ALERTS
    -- =====================================================

    INSERT INTO alerts (
        investigation_id, target_id, alert_type, severity,
        title, message, source_system, is_acknowledged, tags
    ) VALUES
    (
        inv_shadow_network,
        target_volkov,
        'threat',
        'critical',
        'Target Volkov: New Activity Detected',
        'Blockchain analysis detected movement of $2.3M in Bitcoin from wallets associated with target Volkov. Funds moving to new addresses possibly indicating operational preparation. Recommended action: Immediately flag new wallet addresses for tracking. Alert financial institutions on OFAC list.',
        'Automated Blockchain Monitoring',
        false,
        ARRAY['blockchain', 'cryptocurrency', 'financial']
    ),
    (
        inv_ghost_protocol,
        target_mueller,
        'suspicious_activity',
        'high',
        'Anomalous System Access Detected',
        'Subject Mueller accessed classified project files outside his current assignment scope at 0312 local time. Recommended action: Review access logs. Consider interview or enhanced surveillance.',
        'SIEM Alert System',
        true,
        ARRAY['insider-threat', 'access-control']
    ),
    (
        inv_crypto_cartel,
        target_chen,
        'location',
        'medium',
        'Target Chen: Travel Alert',
        'Passport control records indicate target Chen departed Hong Kong for Dubai on flight EK321. Recommended action: Coordinate with Dubai station. Prepare surveillance assets.',
        'International Travel Monitoring',
        false,
        ARRAY['travel', 'surveillance']
    );

    RAISE NOTICE 'Seed data inserted successfully!';
    RAISE NOTICE 'Created 4 investigations, 5 targets, 3 operations, 4 intelligence reports, 3 evidence items, 4 notifications, and 3 alerts.';

END $$;
