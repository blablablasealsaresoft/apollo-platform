/**
 * Intelligence Ingestion Processor
 * Multi-source data normalization, validation, and enrichment
 */

import { logger } from '@apollo/shared';
import {
  FusionInput,
  IntelligenceSource,
  SourceType
} from '../algorithms/fusion_engine';

// ============================================
// TYPES
// ============================================

export interface RawIntelPayload {
  investigations?: string[];
  telemetry?: Record<string, unknown>;
  target?: string;
  sources?: RawSourceData[];
  options?: {
    deepAnalysis?: boolean;
    maxGraphDepth?: number;
    minCorrelationScore?: number;
    includeTimeline?: boolean;
    includeRiskAssessment?: boolean;
  };
}

export interface RawSourceData {
  sourceId?: string;
  sourceType?: string;
  reliability?: number;
  timestamp?: string | Date;
  data?: Record<string, any>;
  // Direct fields for convenience
  email?: string;
  name?: string;
  phone?: string;
  wallet?: string;
  location?: string;
  aliases?: string[];
  [key: string]: any;
}

export interface OsintData {
  email?: string;
  name?: string;
  aliases?: string[];
  location?: string;
  social_profiles?: string[];
  websites?: string[];
  organizations?: string[];
}

export interface SigintData {
  communication_id?: string;
  participants?: string[];
  channel_type?: string;
  timestamp?: string;
  metadata?: Record<string, any>;
}

export interface GeointData {
  latitude?: number;
  longitude?: number;
  location_name?: string;
  timestamp?: string;
  confidence?: number;
  source_imagery?: string;
}

export interface FinintData {
  account_number?: string;
  bank_name?: string;
  transactions?: Array<{
    amount: number;
    currency: string;
    timestamp: string;
    counterparty?: string;
  }>;
  total_volume?: number;
}

export interface BlockchainData {
  wallet?: string;
  address?: string;
  blockchain?: string;
  transactions?: number;
  total_volume?: string;
  owner_email?: string;
  owner_name?: string;
  balance?: string;
}

export interface BreachData {
  email?: string;
  password?: string;
  password_hash?: string;
  phone?: string;
  name?: string;
  breach?: string;
  source?: string;
  breach_date?: string;
}

export interface SherlockData {
  username?: string;
  platforms?: string[];
  found_count?: number;
  not_found_count?: number;
  results?: Record<string, { found: boolean; url?: string }>;
}

export interface SocmintData {
  platform?: string;
  username?: string;
  user_id?: string;
  joined_date?: string;
  created_at?: string;
  posts?: number;
  followers?: number;
  following?: number;
  bio?: string;
}

// ============================================
// MAIN INGESTION FUNCTION
// ============================================

/**
 * Ingest and normalize raw intelligence payload
 */
export async function ingestIntel(payload: RawIntelPayload): Promise<FusionInput> {
  logger.info('Processing intelligence ingestion', {
    sourcesCount: payload.sources?.length || 0,
    target: payload.target
  });

  // Validate and normalize payload
  const normalizedSources = await normalizeIntelligenceSources(payload.sources || []);

  // Add any inline data as sources
  const inlineSources = extractInlineSources(payload);
  normalizedSources.push(...inlineSources);

  return {
    investigations: payload.investigations ?? [],
    telemetry: payload.telemetry ?? {},
    target: payload.target,
    sources: normalizedSources,
    options: {
      deepAnalysis: payload.options?.deepAnalysis ?? false,
      maxGraphDepth: payload.options?.maxGraphDepth ?? 3,
      minCorrelationScore: payload.options?.minCorrelationScore ?? 0.6,
      includeTimeline: payload.options?.includeTimeline ?? true,
      includeRiskAssessment: payload.options?.includeRiskAssessment ?? true
    }
  };
}

/**
 * Normalize array of raw source data into IntelligenceSource format
 */
async function normalizeIntelligenceSources(
  rawSources: RawSourceData[]
): Promise<IntelligenceSource[]> {
  const normalized: IntelligenceSource[] = [];

  for (const raw of rawSources) {
    try {
      const source = normalizeSource(raw);
      if (source) {
        // Enrich source data
        const enriched = await enrichSourceData(source);
        normalized.push(enriched);
      }
    } catch (error) {
      logger.warn('Failed to normalize source', { error: String(error), source: raw });
    }
  }

  return normalized;
}

/**
 * Normalize a single raw source
 */
function normalizeSource(raw: RawSourceData): IntelligenceSource | null {
  // Determine source type
  const sourceType = detectSourceType(raw);
  if (!sourceType) {
    logger.warn('Could not determine source type', { raw });
    return null;
  }

  // Parse timestamp
  const timestamp = parseTimestamp(raw.timestamp);

  // Extract data payload
  const data = extractSourceData(raw, sourceType);
  if (Object.keys(data).length === 0) {
    logger.warn('Empty source data', { sourceType, raw });
    return null;
  }

  // Generate source ID if not provided
  const sourceId = raw.sourceId || generateSourceId(sourceType, data);

  // Determine reliability
  const reliability = raw.reliability ?? getDefaultReliability(sourceType);

  return {
    sourceId,
    sourceType,
    reliability,
    timestamp,
    data
  };
}

/**
 * Detect source type from raw data
 */
function detectSourceType(raw: RawSourceData): SourceType | null {
  // Explicit source type
  if (raw.sourceType) {
    const normalized = raw.sourceType.toLowerCase() as SourceType;
    if (isValidSourceType(normalized)) {
      return normalized;
    }
  }

  // Infer from data content
  const data = raw.data || raw;

  // Blockchain indicators
  if (data.wallet || data.address || data.blockchain || data.transactions) {
    return 'blockchain';
  }

  // Breach indicators
  if (data.breach || data.password || data.password_hash || data.breach_date) {
    return 'breach';
  }

  // Sherlock indicators
  if (data.platforms || data.found_count || (data.username && Array.isArray(data.platforms))) {
    return 'sherlock';
  }

  // Social media indicators
  if (data.platform && (data.followers || data.posts || data.joined_date)) {
    return 'socmint';
  }

  // SIGINT indicators
  if (data.communication_id || data.channel_type || data.participants) {
    return 'sigint';
  }

  // GEOINT indicators
  if (data.latitude !== undefined || data.longitude !== undefined || data.source_imagery) {
    return 'geoint';
  }

  // FININT indicators
  if (data.account_number || data.bank_name || (data.transactions && Array.isArray(data.transactions))) {
    return 'finint';
  }

  // Default to OSINT for general data
  if (data.email || data.name || data.phone || data.location) {
    return 'osint';
  }

  return 'unknown';
}

function isValidSourceType(type: string): type is SourceType {
  const validTypes: SourceType[] = [
    'osint', 'sigint', 'geoint', 'finint', 'humint',
    'blockchain', 'breach', 'sherlock', 'socmint', 'unknown'
  ];
  return validTypes.includes(type as SourceType);
}

/**
 * Extract and normalize source-specific data
 */
function extractSourceData(raw: RawSourceData, sourceType: SourceType): Record<string, any> {
  const baseData = raw.data || {};

  // Merge any top-level fields into data
  const mergedData = { ...baseData };

  // Common fields
  const commonFields = [
    'email', 'name', 'phone', 'location', 'aliases', 'username',
    'wallet', 'address', 'organization'
  ];

  for (const field of commonFields) {
    if (raw[field] !== undefined && mergedData[field] === undefined) {
      mergedData[field] = raw[field];
    }
  }

  // Source-specific normalization
  switch (sourceType) {
    case 'osint':
      return normalizeOsintData(mergedData);

    case 'sigint':
      return normalizeSigintData(mergedData);

    case 'geoint':
      return normalizeGeointData(mergedData);

    case 'finint':
      return normalizeFinintData(mergedData);

    case 'blockchain':
      return normalizeBlockchainData(mergedData);

    case 'breach':
      return normalizeBreachData(mergedData);

    case 'sherlock':
      return normalizeSherlockData(mergedData);

    case 'socmint':
      return normalizeSocmintData(mergedData);

    default:
      return mergedData;
  }
}

// ============================================
// SOURCE-SPECIFIC NORMALIZERS
// ============================================

function normalizeOsintData(data: Record<string, any>): OsintData {
  const normalized: OsintData = {};

  if (data.email) normalized.email = String(data.email).toLowerCase().trim();
  if (data.name) normalized.name = String(data.name).trim();
  if (data.location) normalized.location = String(data.location).trim();

  if (data.aliases) {
    normalized.aliases = Array.isArray(data.aliases)
      ? data.aliases.map(String)
      : [String(data.aliases)];
  }

  if (data.social_profiles) {
    normalized.social_profiles = Array.isArray(data.social_profiles)
      ? data.social_profiles
      : [data.social_profiles];
  }

  if (data.websites) {
    normalized.websites = Array.isArray(data.websites)
      ? data.websites
      : [data.websites];
  }

  if (data.organizations) {
    normalized.organizations = Array.isArray(data.organizations)
      ? data.organizations
      : [data.organizations];
  }

  return normalized;
}

function normalizeSigintData(data: Record<string, any>): SigintData {
  const normalized: SigintData = {};

  if (data.communication_id) normalized.communication_id = String(data.communication_id);
  if (data.channel_type) normalized.channel_type = String(data.channel_type);
  if (data.timestamp) normalized.timestamp = parseTimestamp(data.timestamp).toISOString();

  if (data.participants) {
    normalized.participants = Array.isArray(data.participants)
      ? data.participants.map(String)
      : [String(data.participants)];
  }

  if (data.metadata && typeof data.metadata === 'object') {
    normalized.metadata = data.metadata;
  }

  return normalized;
}

function normalizeGeointData(data: Record<string, any>): GeointData {
  const normalized: GeointData = {};

  if (data.latitude !== undefined) normalized.latitude = Number(data.latitude);
  if (data.longitude !== undefined) normalized.longitude = Number(data.longitude);
  if (data.location_name) normalized.location_name = String(data.location_name);
  if (data.timestamp) normalized.timestamp = parseTimestamp(data.timestamp).toISOString();
  if (data.confidence !== undefined) normalized.confidence = Number(data.confidence);
  if (data.source_imagery) normalized.source_imagery = String(data.source_imagery);

  return normalized;
}

function normalizeFinintData(data: Record<string, any>): FinintData {
  const normalized: FinintData = {};

  if (data.account_number) normalized.account_number = String(data.account_number);
  if (data.bank_name) normalized.bank_name = String(data.bank_name);
  if (data.total_volume !== undefined) normalized.total_volume = Number(data.total_volume);

  if (data.transactions && Array.isArray(data.transactions)) {
    normalized.transactions = data.transactions.map((tx: any) => ({
      amount: Number(tx.amount || 0),
      currency: String(tx.currency || 'USD'),
      timestamp: parseTimestamp(tx.timestamp).toISOString(),
      counterparty: tx.counterparty ? String(tx.counterparty) : undefined
    }));
  }

  return normalized;
}

function normalizeBlockchainData(data: Record<string, any>): BlockchainData {
  const normalized: BlockchainData = {};

  if (data.wallet) normalized.wallet = String(data.wallet).trim();
  if (data.address) normalized.address = String(data.address).trim();
  if (data.blockchain) normalized.blockchain = String(data.blockchain);
  if (data.transactions !== undefined) normalized.transactions = Number(data.transactions);
  if (data.total_volume) normalized.total_volume = String(data.total_volume);
  if (data.owner_email) normalized.owner_email = String(data.owner_email).toLowerCase().trim();
  if (data.owner_name) normalized.owner_name = String(data.owner_name).trim();
  if (data.balance) normalized.balance = String(data.balance);

  // Auto-detect blockchain from wallet format
  if (!normalized.blockchain && (normalized.wallet || normalized.address)) {
    normalized.blockchain = detectBlockchain(normalized.wallet || normalized.address || '');
  }

  return normalized;
}

function normalizeBreachData(data: Record<string, any>): BreachData {
  const normalized: BreachData = {};

  if (data.email) normalized.email = String(data.email).toLowerCase().trim();
  if (data.password) normalized.password = String(data.password);
  if (data.password_hash) normalized.password_hash = String(data.password_hash);
  if (data.phone) normalized.phone = normalizePhone(String(data.phone));
  if (data.name) normalized.name = String(data.name).trim();
  if (data.breach) normalized.breach = String(data.breach);
  if (data.source) normalized.source = String(data.source);
  if (data.breach_date) normalized.breach_date = parseTimestamp(data.breach_date).toISOString();

  return normalized;
}

function normalizeSherlockData(data: Record<string, any>): SherlockData {
  const normalized: SherlockData = {};

  if (data.username) normalized.username = String(data.username).trim();
  if (data.found_count !== undefined) normalized.found_count = Number(data.found_count);
  if (data.not_found_count !== undefined) normalized.not_found_count = Number(data.not_found_count);

  if (data.platforms && Array.isArray(data.platforms)) {
    normalized.platforms = data.platforms.map(String);
  }

  if (data.results && typeof data.results === 'object') {
    normalized.results = {};
    for (const [platform, result] of Object.entries(data.results)) {
      if (typeof result === 'object' && result !== null) {
        const r = result as any;
        normalized.results[platform] = {
          found: Boolean(r.found),
          url: r.url ? String(r.url) : undefined
        };
      }
    }
  }

  return normalized;
}

function normalizeSocmintData(data: Record<string, any>): SocmintData {
  const normalized: SocmintData = {};

  if (data.platform) normalized.platform = String(data.platform);
  if (data.username) normalized.username = String(data.username).trim();
  if (data.user_id) normalized.user_id = String(data.user_id);
  if (data.joined_date) normalized.joined_date = parseTimestamp(data.joined_date).toISOString();
  if (data.created_at) normalized.created_at = parseTimestamp(data.created_at).toISOString();
  if (data.posts !== undefined) normalized.posts = Number(data.posts);
  if (data.followers !== undefined) normalized.followers = Number(data.followers);
  if (data.following !== undefined) normalized.following = Number(data.following);
  if (data.bio) normalized.bio = String(data.bio);

  return normalized;
}

// ============================================
// DATA ENRICHMENT
// ============================================

/**
 * Enrich source data with additional derived information
 */
async function enrichSourceData(source: IntelligenceSource): Promise<IntelligenceSource> {
  const enriched = { ...source };
  const data = { ...source.data };

  // Email enrichment
  if (data.email) {
    const email = String(data.email);
    data.email_domain = email.split('@')[1] || '';
    data.email_local = email.split('@')[0] || '';
  }

  // Wallet enrichment
  if (data.wallet || data.address) {
    const wallet = data.wallet || data.address;
    if (!data.blockchain) {
      data.blockchain = detectBlockchain(wallet);
    }
  }

  // Phone enrichment
  if (data.phone) {
    const phone = String(data.phone);
    const normalized = normalizePhone(phone);
    if (normalized) {
      data.phone = normalized;
      data.phone_country_code = normalized.slice(0, Math.min(4, normalized.indexOf('-') || 4));
    }
  }

  // Location enrichment
  if (data.location) {
    const location = String(data.location).toLowerCase();

    // Detect high-risk locations
    const highRiskCountries = ['russia', 'iran', 'north korea', 'syria', 'venezuela', 'crimea', 'belarus', 'myanmar'];
    data.high_risk_location = highRiskCountries.some(c => location.includes(c));

    // Detect tax havens
    const taxHavens = ['cayman', 'panama', 'bermuda', 'bahamas', 'switzerland', 'malta'];
    data.tax_haven = taxHavens.some(h => location.includes(h));
  }

  enriched.data = data;
  return enriched;
}

// ============================================
// INLINE SOURCE EXTRACTION
// ============================================

/**
 * Extract sources from inline payload fields
 */
function extractInlineSources(payload: RawIntelPayload): IntelligenceSource[] {
  const sources: IntelligenceSource[] = [];

  // Check telemetry for source data
  if (payload.telemetry && typeof payload.telemetry === 'object') {
    const telemetry = payload.telemetry as Record<string, any>;

    // OSINT data
    if (telemetry.osint) {
      const osintSource = createInlineSource('osint', telemetry.osint);
      if (osintSource) sources.push(osintSource);
    }

    // Blockchain data
    if (telemetry.blockchain) {
      const blockchainSource = createInlineSource('blockchain', telemetry.blockchain);
      if (blockchainSource) sources.push(blockchainSource);
    }

    // Breach data
    if (telemetry.breach) {
      const breachSource = createInlineSource('breach', telemetry.breach);
      if (breachSource) sources.push(breachSource);
    }

    // Social media data
    if (telemetry.social || telemetry.socmint) {
      const socmintSource = createInlineSource('socmint', telemetry.social || telemetry.socmint);
      if (socmintSource) sources.push(socmintSource);
    }
  }

  return sources;
}

function createInlineSource(
  sourceType: SourceType,
  data: unknown
): IntelligenceSource | null {
  if (!data || typeof data !== 'object') return null;

  const dataObj = data as Record<string, any>;
  if (Object.keys(dataObj).length === 0) return null;

  return {
    sourceId: generateSourceId(sourceType, dataObj),
    sourceType,
    reliability: getDefaultReliability(sourceType),
    timestamp: new Date(),
    data: dataObj
  };
}

// ============================================
// UTILITIES
// ============================================

function parseTimestamp(input?: string | Date): Date {
  if (!input) return new Date();

  if (input instanceof Date) {
    return isNaN(input.getTime()) ? new Date() : input;
  }

  try {
    const parsed = new Date(input);
    return isNaN(parsed.getTime()) ? new Date() : parsed;
  } catch {
    return new Date();
  }
}

function generateSourceId(sourceType: SourceType, data: Record<string, any>): string {
  const timestamp = Date.now();

  // Use key identifiers for uniqueness
  let identifier = '';
  if (data.email) identifier = data.email;
  else if (data.wallet || data.address) identifier = data.wallet || data.address;
  else if (data.phone) identifier = data.phone;
  else if (data.username) identifier = data.username;
  else identifier = JSON.stringify(data).slice(0, 50);

  // Simple hash
  let hash = 0;
  const str = `${sourceType}:${identifier}:${timestamp}`;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }

  return `${sourceType}_${Math.abs(hash).toString(16)}`;
}

function getDefaultReliability(sourceType: SourceType): number {
  const reliabilityMap: Record<SourceType, number> = {
    blockchain: 0.95,
    sigint: 0.90,
    finint: 0.90,
    geoint: 0.85,
    breach: 0.85,
    sherlock: 0.80,
    socmint: 0.75,
    osint: 0.70,
    humint: 0.65,
    unknown: 0.50
  };

  return reliabilityMap[sourceType] ?? 0.50;
}

function detectBlockchain(wallet: string): string {
  if (wallet.startsWith('0x') && wallet.length === 42) return 'Ethereum';
  if (wallet.startsWith('bc1') || wallet.startsWith('1') || wallet.startsWith('3')) return 'Bitcoin';
  if (wallet.startsWith('X')) return 'Monero';
  if (wallet.startsWith('r')) return 'Ripple';
  if (wallet.startsWith('L') || wallet.startsWith('M')) return 'Litecoin';
  if (wallet.startsWith('D')) return 'Dogecoin';
  if (wallet.startsWith('tz')) return 'Tezos';
  if (wallet.startsWith('addr')) return 'Cardano';
  return 'Unknown';
}

function normalizePhone(phone: string): string {
  // Remove all non-digit characters except leading +
  let normalized = phone.replace(/[^\d+]/g, '');

  // Ensure starts with +
  if (!normalized.startsWith('+') && normalized.length >= 10) {
    normalized = '+' + normalized;
  }

  return normalized.length >= 8 ? normalized : '';
}

// ============================================
// BATCH PROCESSING
// ============================================

/**
 * Process multiple intelligence payloads in batch
 */
export async function ingestBatch(
  payloads: RawIntelPayload[]
): Promise<FusionInput[]> {
  const results: FusionInput[] = [];

  for (const payload of payloads) {
    try {
      const normalized = await ingestIntel(payload);
      results.push(normalized);
    } catch (error) {
      logger.error('Failed to process payload in batch', { error: String(error) });
    }
  }

  return results;
}

/**
 * Stream process large datasets
 */
export async function* ingestStream(
  payloadStream: AsyncIterable<RawIntelPayload>
): AsyncGenerator<FusionInput> {
  for await (const payload of payloadStream) {
    try {
      const normalized = await ingestIntel(payload);
      yield normalized;
    } catch (error) {
      logger.error('Failed to process payload in stream', { error: String(error) });
    }
  }
}

// ============================================
// VALIDATION
// ============================================

/**
 * Validate raw payload structure
 */
export function validatePayload(payload: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!payload || typeof payload !== 'object') {
    return { valid: false, errors: ['Payload must be an object'] };
  }

  const p = payload as RawIntelPayload;

  // Validate sources if present
  if (p.sources !== undefined) {
    if (!Array.isArray(p.sources)) {
      errors.push('sources must be an array');
    } else {
      for (let i = 0; i < p.sources.length; i++) {
        const source = p.sources[i];
        if (!source || typeof source !== 'object') {
          errors.push(`sources[${i}] must be an object`);
        }
      }
    }
  }

  // Validate target if present
  if (p.target !== undefined && typeof p.target !== 'string') {
    errors.push('target must be a string');
  }

  // Validate options if present
  if (p.options !== undefined) {
    if (typeof p.options !== 'object') {
      errors.push('options must be an object');
    } else {
      if (p.options.maxGraphDepth !== undefined && typeof p.options.maxGraphDepth !== 'number') {
        errors.push('options.maxGraphDepth must be a number');
      }
      if (p.options.minCorrelationScore !== undefined) {
        if (typeof p.options.minCorrelationScore !== 'number') {
          errors.push('options.minCorrelationScore must be a number');
        } else if (p.options.minCorrelationScore < 0 || p.options.minCorrelationScore > 1) {
          errors.push('options.minCorrelationScore must be between 0 and 1');
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

// Note: Functions are exported inline above
