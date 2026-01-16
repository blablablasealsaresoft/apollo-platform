// Apollo Platform - Neo4j Graph Database Initialization
// Criminal Network Mapping and Relationship Analysis
// Optimized for: OneCoin investigation, money laundering networks, criminal associations

// ============================================================================
// CONSTRAINTS - Ensure data integrity
// ============================================================================

// Person nodes
CREATE CONSTRAINT person_id IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT person_email IF NOT EXISTS FOR (p:Person) REQUIRE p.email IS UNIQUE;

// Organization nodes
CREATE CONSTRAINT organization_id IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;
CREATE CONSTRAINT organization_name IF NOT EXISTS FOR (o:Organization) REQUIRE o.name IS UNIQUE;

// Financial entities
CREATE CONSTRAINT bank_account_id IF NOT EXISTS FOR (b:BankAccount) REQUIRE b.account_number IS UNIQUE;
CREATE CONSTRAINT cryptocurrency_address_id IF NOT EXISTS FOR (c:CryptocurrencyAddress) REQUIRE c.address IS UNIQUE;
CREATE CONSTRAINT company_id IF NOT EXISTS FOR (c:Company) REQUIRE c.id IS UNIQUE;

// Locations
CREATE CONSTRAINT location_id IF NOT EXISTS FOR (l:Location) REQUIRE l.id IS UNIQUE;

// Communication
CREATE CONSTRAINT phone_number_id IF NOT EXISTS FOR (ph:PhoneNumber) REQUIRE ph.number IS UNIQUE;
CREATE CONSTRAINT email_address_id IF NOT EXISTS FOR (e:EmailAddress) REQUIRE e.address IS UNIQUE;

// Digital identity
CREATE CONSTRAINT social_media_id IF NOT EXISTS FOR (s:SocialMediaAccount) REQUIRE s.url IS UNIQUE;
CREATE CONSTRAINT ip_address_id IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE;

// ============================================================================
// INDEXES - Optimize query performance
// ============================================================================

// Person indexes
CREATE INDEX person_name IF NOT EXISTS FOR (p:Person) ON (p.full_name);
CREATE INDEX person_dob IF NOT EXISTS FOR (p:Person) ON (p.date_of_birth);
CREATE INDEX person_nationality IF NOT EXISTS FOR (p:Person) ON (p.nationality);
CREATE INDEX person_status IF NOT EXISTS FOR (p:Person) ON (p.status);

// Organization indexes
CREATE INDEX org_type IF NOT EXISTS FOR (o:Organization) ON (o.type);
CREATE INDEX org_country IF NOT EXISTS FOR (o:Organization) ON (o.country);

// Company indexes
CREATE INDEX company_jurisdiction IF NOT EXISTS FOR (c:Company) ON (c.jurisdiction);
CREATE INDEX company_status IF NOT EXISTS FOR (c:Company) ON (c.status);

// Transaction indexes
CREATE INDEX transaction_date IF NOT EXISTS FOR ()-[t:TRANSACTION]-() ON (t.date);
CREATE INDEX transaction_amount IF NOT EXISTS FOR ()-[t:TRANSACTION]-() ON (t.amount);
CREATE INDEX transaction_currency IF NOT EXISTS FOR ()-[t:TRANSACTION]-() ON (t.currency);

// Communication indexes
CREATE INDEX communication_date IF NOT EXISTS FOR ()-[c:COMMUNICATED_WITH]-() ON (c.date);

// Location indexes
CREATE INDEX location_type IF NOT EXISTS FOR (l:Location) ON (l.type);
CREATE INDEX location_country IF NOT EXISTS FOR (l:Location) ON (l.country);

// ============================================================================
// ONECOIN CRIMINAL NETWORK - Initial Setup
// ============================================================================

// Main target: Ruja Ignatova
MERGE (ruja:Person {id: 'ignatova-ruja'})
SET ruja.full_name = 'Ruja Plamenova Ignatova',
    ruja.first_name = 'Ruja',
    ruja.last_name = 'Ignatova',
    ruja.aliases = ['CryptoQueen', 'Dr. Ruja', 'The Missing Cryptoqueen'],
    ruja.date_of_birth = date('1980-05-30'),
    ruja.nationality = 'Bulgaria',
    ruja.status = 'FUGITIVE',
    ruja.threat_level = 'FBI_MOST_WANTED',
    ruja.gender = 'Female',
    ruja.education = 'PhD in European Private Law, University of Constance, Germany',
    ruja.last_known_location = 'Unknown',
    ruja.last_seen = date('2017-10-25'),
    ruja.reward = 250000.00,
    ruja.fbi_top_ten = true,
    ruja.created_at = datetime(),
    ruja.updated_at = datetime();

// Brother and co-conspirator: Konstantin Ignatov
MERGE (konstantin:Person {id: 'ignatov-konstantin'})
SET konstantin.full_name = 'Konstantin Ignatov',
    konstantin.first_name = 'Konstantin',
    konstantin.last_name = 'Ignatov',
    konstantin.date_of_birth = date('1989-01-01'),
    konstantin.nationality = 'Bulgaria',
    konstantin.status = 'ARRESTED',
    konstantin.gender = 'Male',
    konstantin.arrested_date = date('2019-03-06'),
    konstantin.cooperating_witness = true,
    konstantin.created_at = datetime(),
    konstantin.updated_at = datetime();

// OneCoin organization
MERGE (onecoin:Organization {id: 'onecoin'})
SET onecoin.name = 'OneCoin',
    onecoin.type = 'Cryptocurrency Ponzi Scheme',
    onecoin.founded = date('2014-01-01'),
    onecoin.headquarters = 'Sofia, Bulgaria',
    onecoin.estimated_fraud = 4000000000.00,
    onecoin.currency = 'USD',
    onecoin.status = 'SHUT_DOWN',
    onecoin.shut_down_date = date('2017-01-01'),
    onecoin.victims_count = 3500000,
    onecoin.countries_affected = ['Bulgaria', 'Germany', 'China', 'India', 'USA', 'UK', 'Uganda', 'Pakistan'],
    onecoin.created_at = datetime(),
    onecoin.updated_at = datetime();

// OneLife marketing arm
MERGE (onelife:Organization {id: 'onelife'})
SET onelife.name = 'OneLife Network',
    onelife.type = 'MLM Marketing Organization',
    onelife.parent_organization = 'OneCoin',
    onelife.founded = date('2014-01-01'),
    onelife.status = 'SHUT_DOWN',
    onelife.created_at = datetime(),
    onelife.updated_at = datetime();

// Key associate: Sebastian Greenwood
MERGE (sebastian:Person {id: 'greenwood-sebastian'})
SET sebastian.full_name = 'Sebastian Greenwood',
    sebastian.first_name = 'Sebastian',
    sebastian.last_name = 'Greenwood',
    sebastian.nationality = 'Sweden',
    sebastian.status = 'ARRESTED',
    sebastian.arrested_date = date('2018-11-06'),
    sebastian.role = 'Co-founder, Global Master Distributor',
    sebastian.created_at = datetime(),
    sebastian.updated_at = datetime();

// Key associate: Mark Scott (lawyer)
MERGE (mark:Person {id: 'scott-mark'})
SET mark.full_name = 'Mark S. Scott',
    mark.first_name = 'Mark',
    mark.last_name = 'Scott',
    mark.nationality = 'USA',
    mark.status = 'CONVICTED',
    mark.profession = 'Attorney',
    mark.role = 'Money Laundering',
    mark.convicted_date = date('2019-11-22'),
    mark.laundered_amount = 400000000.00,
    mark.created_at = datetime(),
    mark.updated_at = datetime();

// ============================================================================
// RELATIONSHIPS - OneCoin Network
// ============================================================================

// Ruja founded OneCoin
MERGE (ruja)-[:FOUNDED {
    date: date('2014-01-01'),
    role: 'Founder and Leader',
    confidence: 1.0,
    verified: true
}]->(onecoin);

// Ruja controlled OneLife
MERGE (ruja)-[:CONTROLLED {
    date: date('2014-01-01'),
    role: 'Owner',
    confidence: 1.0,
    verified: true
}]->(onelife);

// Konstantin is Ruja's brother
MERGE (ruja)-[:SIBLING_OF {
    relationship: 'Brother',
    confidence: 1.0,
    verified: true
}]->(konstantin);

// Konstantin worked for OneCoin
MERGE (konstantin)-[:WORKED_FOR {
    start_date: date('2014-01-01'),
    end_date: date('2019-03-06'),
    role: 'Co-founder, CEO (after Ruja disappeared)',
    confidence: 1.0,
    verified: true
}]->(onecoin);

// Sebastian co-founded OneCoin
MERGE (sebastian)-[:CO_FOUNDED {
    date: date('2014-01-01'),
    role: 'Co-founder, Global Master Distributor',
    confidence: 1.0,
    verified: true
}]->(onecoin);

// Sebastian partnered with Ruja
MERGE (sebastian)-[:PARTNERED_WITH {
    start_date: date('2014-01-01'),
    end_date: date('2018-11-06'),
    context: 'OneCoin co-founders',
    confidence: 1.0,
    verified: true
}]->(ruja);

// Mark Scott laundered money for Ruja
MERGE (mark)-[:LAUNDERED_MONEY_FOR {
    start_date: date('2015-01-01'),
    end_date: date('2017-10-01'),
    amount: 400000000.00,
    currency: 'USD',
    confidence: 1.0,
    verified: true
}]->(ruja);

// Mark Scott worked for OneCoin
MERGE (mark)-[:PROVIDED_SERVICES_TO {
    start_date: date('2015-01-01'),
    end_date: date('2017-10-01'),
    service_type: 'Legal services and money laundering',
    confidence: 1.0,
    verified: true
}]->(onecoin);

// ============================================================================
// KEY LOCATIONS
// ============================================================================

// Sofia, Bulgaria (headquarters)
MERGE (sofia:Location {id: 'location-sofia-bulgaria'})
SET sofia.city = 'Sofia',
    sofia.country = 'Bulgaria',
    sofia.type = 'City',
    sofia.significance = 'OneCoin headquarters',
    sofia.latitude = 42.6977,
    sofia.longitude = 23.3219,
    sofia.created_at = datetime();

MERGE (onecoin)-[:LOCATED_IN {
    start_date: date('2014-01-01'),
    location_type: 'Headquarters',
    confidence: 1.0
}]->(sofia);

MERGE (ruja)-[:LIVED_IN {
    start_date: date('1980-05-30'),
    end_date: date('2014-01-01'),
    location_type: 'Birthplace and early residence',
    confidence: 1.0
}]->(sofia);

// Dubai, UAE (suspected current location)
MERGE (dubai:Location {id: 'location-dubai-uae'})
SET dubai.city = 'Dubai',
    dubai.country = 'United Arab Emirates',
    dubai.type = 'City',
    dubai.significance = 'Suspected hiding location',
    dubai.latitude = 25.2048,
    dubai.longitude = 55.2708,
    dubai.created_at = datetime();

MERGE (ruja)-[:POSSIBLY_LOCATED_IN {
    since: date('2017-10-25'),
    confidence: 0.6,
    source: 'Intelligence reports',
    verified: false
}]->(dubai);

// Athens, Greece (last confirmed sighting)
MERGE (athens:Location {id: 'location-athens-greece'})
SET athens.city = 'Athens',
    athens.country = 'Greece',
    athens.type = 'City',
    athens.significance = 'Last confirmed sighting location',
    athens.latitude = 37.9838,
    athens.longitude = 23.7275,
    athens.created_at = datetime();

MERGE (ruja)-[:LAST_SEEN_IN {
    date: date('2017-10-25'),
    confidence: 1.0,
    verified: true,
    details: 'Flew from Sofia to Athens, then disappeared'
}]->(athens);

// Frankfurt, Germany (operations)
MERGE (frankfurt:Location {id: 'location-frankfurt-germany'})
SET frankfurt.city = 'Frankfurt',
    frankfurt.country = 'Germany',
    frankfurt.type = 'City',
    frankfurt.significance = 'Major OneCoin operations center',
    frankfurt.latitude = 50.1109,
    frankfurt.longitude = 8.6821,
    frankfurt.created_at = datetime();

MERGE (onecoin)-[:OPERATED_IN {
    start_date: date('2014-01-01'),
    end_date: date('2017-01-01'),
    confidence: 1.0
}]->(frankfurt);

// ============================================================================
// ADDITIONAL NODE TYPES AND CONSTRAINTS
// ============================================================================

// Investigation nodes (links to PostgreSQL)
CREATE CONSTRAINT investigation_id IF NOT EXISTS FOR (i:Investigation) REQUIRE i.id IS UNIQUE;

// Evidence nodes
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (e:Evidence) REQUIRE e.id IS UNIQUE;

// Document nodes (for document linking)
CREATE CONSTRAINT document_id IF NOT EXISTS FOR (d:Document) REQUIRE d.id IS UNIQUE;

// Shell company tracking
CREATE CONSTRAINT shell_company_id IF NOT EXISTS FOR (s:ShellCompany) REQUIRE s.id IS UNIQUE;

// Legal entity
CREATE CONSTRAINT legal_entity_id IF NOT EXISTS FOR (le:LegalEntity) REQUIRE le.id IS UNIQUE;

// Domain/Website
CREATE CONSTRAINT domain_id IF NOT EXISTS FOR (dom:Domain) REQUIRE dom.domain IS UNIQUE;

// Device
CREATE CONSTRAINT device_id IF NOT EXISTS FOR (dev:Device) REQUIRE dev.id IS UNIQUE;

// Additional indexes
CREATE INDEX shell_company_name IF NOT EXISTS FOR (s:ShellCompany) ON (s.name);
CREATE INDEX shell_company_jurisdiction IF NOT EXISTS FOR (s:ShellCompany) ON (s.jurisdiction);
CREATE INDEX evidence_type IF NOT EXISTS FOR (e:Evidence) ON (e.type);
CREATE INDEX investigation_status IF NOT EXISTS FOR (i:Investigation) ON (i.status);
CREATE INDEX domain_registered IF NOT EXISTS FOR (dom:Domain) ON (dom.registrar);

// ============================================================================
// ADDITIONAL RELATIONSHIP TYPES FOR FINANCIAL CRIMES
// ============================================================================

// Shell company relationships for Mark Scott's money laundering
MERGE (fenero:ShellCompany {id: 'fenero-funds'})
SET fenero.name = 'Fenero Funds',
    fenero.jurisdiction = 'British Virgin Islands',
    fenero.type = 'Investment Fund',
    fenero.created_date = date('2015-01-01'),
    fenero.status = 'DISSOLVED',
    fenero.laundered_amount = 400000000.00,
    fenero.currency = 'USD',
    fenero.created_at = datetime();

MERGE (rn:ShellCompany {id: 'rivendale-network'})
SET rn.name = 'Rivendale International',
    rn.jurisdiction = 'British Virgin Islands',
    rn.type = 'Shell Corporation',
    rn.status = 'DISSOLVED',
    rn.created_at = datetime();

// Mark Scott created/controlled shell companies
MATCH (mark:Person {id: 'scott-mark'})
MERGE (mark)-[:CREATED {
    date: date('2015-01-01'),
    purpose: 'Money laundering vehicle',
    confidence: 1.0,
    verified: true
}]->(fenero);

MATCH (mark:Person {id: 'scott-mark'})
MERGE (mark)-[:CONTROLLED {
    start_date: date('2015-01-01'),
    end_date: date('2017-10-01'),
    role: 'Beneficial Owner',
    confidence: 1.0,
    verified: true
}]->(rn);

// OneCoin funds flowed through shell companies
MATCH (onecoin:Organization {id: 'onecoin'}), (fenero:ShellCompany {id: 'fenero-funds'})
MERGE (onecoin)-[:TRANSFERRED_FUNDS_TO {
    start_date: date('2015-01-01'),
    end_date: date('2017-10-01'),
    amount: 400000000.00,
    currency: 'USD',
    method: 'Wire transfers through multiple accounts',
    confidence: 1.0,
    verified: true
}]->(fenero);

// ============================================================================
// CRYPTOCURRENCY ADDRESS TRACKING
// ============================================================================

// Known OneCoin-related addresses (examples)
MERGE (addr1:CryptocurrencyAddress {address: '1BTC_EXAMPLE_ADDRESS_1'})
SET addr1.blockchain = 'bitcoin',
    addr1.label = 'OneCoin Exchange Address',
    addr1.first_seen = datetime('2015-03-15'),
    addr1.last_active = datetime('2017-10-20'),
    addr1.total_received = 5000.0,
    addr1.total_sent = 4950.0,
    addr1.is_flagged = true,
    addr1.flag_reason = 'OneCoin fraud proceeds',
    addr1.created_at = datetime();

// Link address to OneCoin
MATCH (onecoin:Organization {id: 'onecoin'}), (addr1:CryptocurrencyAddress {address: '1BTC_EXAMPLE_ADDRESS_1'})
MERGE (onecoin)-[:CONTROLS_ADDRESS {
    confidence: 0.95,
    source: 'Blockchain analysis',
    verified: false
}]->(addr1);

// ============================================================================
// COMMUNICATION AND TRAVEL PATTERNS
// ============================================================================

// Ruja's known phones
MERGE (phone1:PhoneNumber {number: '+359-REDACTED-001'})
SET phone1.country = 'Bulgaria',
    phone1.carrier = 'Unknown',
    phone1.status = 'INACTIVE',
    phone1.last_active = date('2017-10-25'),
    phone1.created_at = datetime();

MATCH (ruja:Person {id: 'ignatova-ruja'}), (phone1:PhoneNumber {number: '+359-REDACTED-001'})
MERGE (ruja)-[:USED_PHONE {
    start_date: date('2014-01-01'),
    end_date: date('2017-10-25'),
    confidence: 1.0,
    verified: true
}]->(phone1);

// ============================================================================
// HELPER QUERIES
// ============================================================================

// Return summary of OneCoin network
// Usage: CALL apoc.cypher.run("MATCH (n:Person)-[r]->(o:Organization {name: 'OneCoin'}) RETURN n, r, o", {}) YIELD value RETURN value;

// Network statistics
// MATCH (p:Person)-[r]-(o:Organization {name: 'OneCoin'})
// RETURN count(DISTINCT p) as people, count(DISTINCT r) as relationships;

// Find all entities connected to a person within 3 hops
// MATCH path = (p:Person {id: 'ignatova-ruja'})-[*1..3]-(connected)
// RETURN path;

// Money trail query
// MATCH path = (org:Organization {name: 'OneCoin'})-[:TRANSFERRED_FUNDS_TO*1..5]->(dest)
// RETURN path;

// Find shortest path between two entities
// MATCH path = shortestPath((start:Person {id: 'ignatova-ruja'})-[*]-(end:Person {id: 'scott-mark'}))
// RETURN path;

RETURN "Apollo Neo4j database initialized with comprehensive criminal network structure" AS status;
