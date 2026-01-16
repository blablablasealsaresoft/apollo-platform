/**
 * API Key Management Service
 * Implements secure API key validation with rotation support,
 * scope-based permissions, and rate limiting per key
 */

import crypto from 'crypto';
import {
  database,
  redis,
  logger,
  generateId,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  BadRequestError,
} from '@apollo/shared';

// API Key scopes/permissions
export enum ApiKeyScope {
  // Read scopes
  READ_INVESTIGATIONS = 'read:investigations',
  READ_TARGETS = 'read:targets',
  READ_EVIDENCE = 'read:evidence',
  READ_INTELLIGENCE = 'read:intelligence',
  READ_OPERATIONS = 'read:operations',
  READ_ANALYTICS = 'read:analytics',
  READ_USERS = 'read:users',

  // Write scopes
  WRITE_INVESTIGATIONS = 'write:investigations',
  WRITE_TARGETS = 'write:targets',
  WRITE_EVIDENCE = 'write:evidence',
  WRITE_INTELLIGENCE = 'write:intelligence',
  WRITE_OPERATIONS = 'write:operations',
  WRITE_USERS = 'write:users',

  // Admin scopes
  ADMIN_FULL = 'admin:full',
  ADMIN_USERS = 'admin:users',
  ADMIN_KEYS = 'admin:keys',
  ADMIN_AUDIT = 'admin:audit',

  // Special scopes
  BLOCKCHAIN_FORENSICS = 'blockchain:forensics',
  OSINT_TOOLS = 'osint:tools',
  BIOMETRIC_AUTH = 'biometric:auth',
  FACIAL_RECOGNITION = 'facial:recognition',
  WEBHOOK_EVENTS = 'webhook:events',
}

// API Key status
export enum ApiKeyStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
  RATE_LIMITED = 'rate_limited',
}

// API Key data structure
export interface ApiKey {
  id: string;
  userId: string;
  name: string;
  keyPrefix: string; // First 8 chars for identification
  keyHash: string;
  scopes: ApiKeyScope[];
  status: ApiKeyStatus;
  rateLimit: number; // requests per minute
  rateLimitWindow: number; // window in seconds
  expiresAt: Date | null;
  lastUsed: Date | null;
  lastRotated: Date | null;
  ipWhitelist: string[] | null;
  metadata: Record<string, any> | null;
  createdAt: Date;
  updatedAt: Date;
}

// API Key creation options
export interface CreateApiKeyOptions {
  userId: string;
  name: string;
  scopes: ApiKeyScope[];
  rateLimit?: number;
  rateLimitWindow?: number;
  expiresIn?: number; // days
  ipWhitelist?: string[];
  metadata?: Record<string, any>;
}

// API Key validation result
export interface ApiKeyValidationResult {
  valid: boolean;
  key?: ApiKey;
  error?: string;
  remainingRequests?: number;
  resetTime?: Date;
}

// Predefined scope sets for common use cases
export const SCOPE_PRESETS = {
  readonly: [
    ApiKeyScope.READ_INVESTIGATIONS,
    ApiKeyScope.READ_TARGETS,
    ApiKeyScope.READ_EVIDENCE,
    ApiKeyScope.READ_INTELLIGENCE,
    ApiKeyScope.READ_OPERATIONS,
    ApiKeyScope.READ_ANALYTICS,
  ],
  analyst: [
    ApiKeyScope.READ_INVESTIGATIONS,
    ApiKeyScope.READ_TARGETS,
    ApiKeyScope.READ_EVIDENCE,
    ApiKeyScope.READ_INTELLIGENCE,
    ApiKeyScope.READ_OPERATIONS,
    ApiKeyScope.READ_ANALYTICS,
    ApiKeyScope.WRITE_INVESTIGATIONS,
    ApiKeyScope.WRITE_EVIDENCE,
    ApiKeyScope.WRITE_INTELLIGENCE,
    ApiKeyScope.OSINT_TOOLS,
    ApiKeyScope.BLOCKCHAIN_FORENSICS,
  ],
  operator: [
    ApiKeyScope.READ_INVESTIGATIONS,
    ApiKeyScope.READ_TARGETS,
    ApiKeyScope.READ_EVIDENCE,
    ApiKeyScope.READ_INTELLIGENCE,
    ApiKeyScope.READ_OPERATIONS,
    ApiKeyScope.READ_ANALYTICS,
    ApiKeyScope.WRITE_INVESTIGATIONS,
    ApiKeyScope.WRITE_TARGETS,
    ApiKeyScope.WRITE_EVIDENCE,
    ApiKeyScope.WRITE_INTELLIGENCE,
    ApiKeyScope.WRITE_OPERATIONS,
    ApiKeyScope.OSINT_TOOLS,
    ApiKeyScope.BLOCKCHAIN_FORENSICS,
    ApiKeyScope.FACIAL_RECOGNITION,
  ],
  admin: [
    ApiKeyScope.ADMIN_FULL,
  ],
  webhook: [
    ApiKeyScope.WEBHOOK_EVENTS,
    ApiKeyScope.READ_INVESTIGATIONS,
    ApiKeyScope.READ_TARGETS,
  ],
};

export class ApiKeyService {
  private readonly KEY_PREFIX = 'apollo_';
  private readonly KEY_LENGTH = 32;
  private readonly DEFAULT_RATE_LIMIT = 100; // requests per minute
  private readonly DEFAULT_RATE_WINDOW = 60; // seconds
  private readonly MAX_KEYS_PER_USER = 10;

  /**
   * Create a new API key
   */
  async createApiKey(options: CreateApiKeyOptions): Promise<{
    id: string;
    apiKey: string; // Full key - only shown once
    keyPrefix: string;
    name: string;
    scopes: ApiKeyScope[];
    expiresAt: Date | null;
  }> {
    // Check user's existing key count
    const existingKeys = await database.query(
      `SELECT COUNT(*) as count FROM api_keys WHERE user_id = $1 AND status != 'revoked'`,
      [options.userId],
    );

    if (parseInt(existingKeys.rows[0]?.count || '0') >= this.MAX_KEYS_PER_USER) {
      throw new BadRequestError(`Maximum API keys limit (${this.MAX_KEYS_PER_USER}) reached`);
    }

    // Generate API key
    const rawKey = crypto.randomBytes(this.KEY_LENGTH).toString('hex');
    const apiKey = `${this.KEY_PREFIX}${rawKey}`;
    const keyPrefix = apiKey.substring(0, 12);
    const keyHash = this.hashKey(apiKey);

    // Calculate expiration
    const expiresAt = options.expiresIn
      ? new Date(Date.now() + options.expiresIn * 24 * 60 * 60 * 1000)
      : null;

    const keyId = generateId();

    // Store in database
    await database.query(
      `INSERT INTO api_keys (
        id, user_id, name, key_prefix, key_hash, scopes, status,
        rate_limit, rate_limit_window, expires_at, ip_whitelist, metadata,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())`,
      [
        keyId,
        options.userId,
        options.name,
        keyPrefix,
        keyHash,
        JSON.stringify(options.scopes),
        ApiKeyStatus.ACTIVE,
        options.rateLimit || this.DEFAULT_RATE_LIMIT,
        options.rateLimitWindow || this.DEFAULT_RATE_WINDOW,
        expiresAt,
        options.ipWhitelist ? JSON.stringify(options.ipWhitelist) : null,
        options.metadata ? JSON.stringify(options.metadata) : null,
      ],
    );

    await this.logActivity(options.userId, 'API_KEY_CREATED', {
      keyId,
      name: options.name,
      scopes: options.scopes,
    });

    logger.info(`API key created for user: ${options.userId}, name: ${options.name}`);

    return {
      id: keyId,
      apiKey, // Return full key only once
      keyPrefix,
      name: options.name,
      scopes: options.scopes,
      expiresAt,
    };
  }

  /**
   * Validate an API key and check permissions
   */
  async validateApiKey(
    apiKey: string,
    requiredScopes?: ApiKeyScope[],
    ipAddress?: string,
  ): Promise<ApiKeyValidationResult> {
    // Validate format
    if (!apiKey.startsWith(this.KEY_PREFIX)) {
      return { valid: false, error: 'Invalid API key format' };
    }

    const keyHash = this.hashKey(apiKey);
    const keyPrefix = apiKey.substring(0, 12);

    // Check cache first
    const cachedKey = await redis.get(`apikey:${keyHash}`);
    let key: ApiKey | null = null;

    if (cachedKey) {
      key = JSON.parse(cachedKey);
    } else {
      // Fetch from database
      const result = await database.query<ApiKey>(
        `SELECT
          id, user_id as "userId", name, key_prefix as "keyPrefix", key_hash as "keyHash",
          scopes, status, rate_limit as "rateLimit", rate_limit_window as "rateLimitWindow",
          expires_at as "expiresAt", last_used as "lastUsed", last_rotated as "lastRotated",
          ip_whitelist as "ipWhitelist", metadata, created_at as "createdAt", updated_at as "updatedAt"
         FROM api_keys
         WHERE key_hash = $1`,
        [keyHash],
      );

      if (result.rows.length === 0) {
        return { valid: false, error: 'API key not found' };
      }

      key = result.rows[0]!;

      // Parse JSON fields
      key.scopes = typeof key.scopes === 'string' ? JSON.parse(key.scopes) : key.scopes;
      key.ipWhitelist = key.ipWhitelist
        ? (typeof key.ipWhitelist === 'string' ? JSON.parse(key.ipWhitelist) : key.ipWhitelist)
        : null;

      // Cache the key (5 minute TTL)
      await redis.set(`apikey:${keyHash}`, JSON.stringify(key), 300);
    }

    // Check status
    if (key.status !== ApiKeyStatus.ACTIVE) {
      return { valid: false, error: `API key is ${key.status}` };
    }

    // Check expiration
    if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
      await this.updateKeyStatus(key.id, ApiKeyStatus.EXPIRED);
      return { valid: false, error: 'API key has expired' };
    }

    // Check IP whitelist
    if (ipAddress && key.ipWhitelist && key.ipWhitelist.length > 0) {
      if (!this.isIpAllowed(ipAddress, key.ipWhitelist)) {
        await this.logActivity(key.userId, 'API_KEY_IP_BLOCKED', {
          keyId: key.id,
          ipAddress,
        });
        return { valid: false, error: 'IP address not allowed' };
      }
    }

    // Check rate limit
    const rateLimitResult = await this.checkRateLimit(key);
    if (!rateLimitResult.allowed) {
      return {
        valid: false,
        error: 'Rate limit exceeded',
        remainingRequests: 0,
        resetTime: rateLimitResult.resetTime,
      };
    }

    // Check required scopes
    if (requiredScopes && requiredScopes.length > 0) {
      const hasAdminFull = key.scopes.includes(ApiKeyScope.ADMIN_FULL);
      const hasAllScopes = requiredScopes.every(
        scope => hasAdminFull || key.scopes.includes(scope),
      );

      if (!hasAllScopes) {
        const missingScopes = requiredScopes.filter(
          scope => !hasAdminFull && !key.scopes.includes(scope),
        );
        return {
          valid: false,
          error: `Missing required scopes: ${missingScopes.join(', ')}`,
        };
      }
    }

    // Update last used (async, don't wait)
    this.updateLastUsed(key.id).catch(err =>
      logger.error(`Failed to update API key last used: ${err}`),
    );

    return {
      valid: true,
      key,
      remainingRequests: rateLimitResult.remaining,
      resetTime: rateLimitResult.resetTime,
    };
  }

  /**
   * Rotate an API key (generate new key, invalidate old)
   */
  async rotateApiKey(keyId: string, userId: string): Promise<{
    id: string;
    newApiKey: string;
    keyPrefix: string;
  }> {
    // Verify ownership
    const existing = await this.getKeyById(keyId);
    if (!existing || existing.userId !== userId) {
      throw new NotFoundError('API key not found');
    }

    if (existing.status !== ApiKeyStatus.ACTIVE) {
      throw new BadRequestError('Cannot rotate inactive API key');
    }

    // Generate new key
    const rawKey = crypto.randomBytes(this.KEY_LENGTH).toString('hex');
    const newApiKey = `${this.KEY_PREFIX}${rawKey}`;
    const newKeyPrefix = newApiKey.substring(0, 12);
    const newKeyHash = this.hashKey(newApiKey);

    // Update in database
    await database.query(
      `UPDATE api_keys
       SET key_prefix = $1, key_hash = $2, last_rotated = NOW(), updated_at = NOW()
       WHERE id = $3`,
      [newKeyPrefix, newKeyHash, keyId],
    );

    // Invalidate cache
    await redis.del(`apikey:${this.hashKey(existing.keyHash)}`);

    await this.logActivity(userId, 'API_KEY_ROTATED', { keyId });

    logger.info(`API key rotated: ${keyId}`);

    return {
      id: keyId,
      newApiKey,
      keyPrefix: newKeyPrefix,
    };
  }

  /**
   * Revoke an API key
   */
  async revokeApiKey(keyId: string, userId: string, reason?: string): Promise<void> {
    // Verify ownership (or admin)
    const existing = await this.getKeyById(keyId);
    if (!existing) {
      throw new NotFoundError('API key not found');
    }

    // Allow owner or admin to revoke
    if (existing.userId !== userId) {
      // Check if user is admin (would need to pass user role)
      throw new ForbiddenError('Not authorized to revoke this API key');
    }

    await database.query(
      `UPDATE api_keys SET status = $1, updated_at = NOW() WHERE id = $2`,
      [ApiKeyStatus.REVOKED, keyId],
    );

    // Invalidate cache
    await redis.del(`apikey:${existing.keyHash}`);

    // Clear rate limit data
    await redis.del(`ratelimit:apikey:${keyId}`);

    await this.logActivity(userId, 'API_KEY_REVOKED', { keyId, reason });

    logger.info(`API key revoked: ${keyId}, reason: ${reason}`);
  }

  /**
   * Update API key scopes
   */
  async updateScopes(keyId: string, userId: string, scopes: ApiKeyScope[]): Promise<void> {
    const existing = await this.getKeyById(keyId);
    if (!existing || existing.userId !== userId) {
      throw new NotFoundError('API key not found');
    }

    await database.query(
      `UPDATE api_keys SET scopes = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(scopes), keyId],
    );

    // Invalidate cache
    await redis.del(`apikey:${existing.keyHash}`);

    await this.logActivity(userId, 'API_KEY_SCOPES_UPDATED', {
      keyId,
      oldScopes: existing.scopes,
      newScopes: scopes,
    });

    logger.info(`API key scopes updated: ${keyId}`);
  }

  /**
   * Update API key rate limits
   */
  async updateRateLimit(
    keyId: string,
    userId: string,
    rateLimit: number,
    rateLimitWindow?: number,
  ): Promise<void> {
    const existing = await this.getKeyById(keyId);
    if (!existing || existing.userId !== userId) {
      throw new NotFoundError('API key not found');
    }

    await database.query(
      `UPDATE api_keys
       SET rate_limit = $1, rate_limit_window = COALESCE($2, rate_limit_window), updated_at = NOW()
       WHERE id = $3`,
      [rateLimit, rateLimitWindow || null, keyId],
    );

    // Invalidate cache
    await redis.del(`apikey:${existing.keyHash}`);

    logger.info(`API key rate limit updated: ${keyId}`);
  }

  /**
   * Get all API keys for a user
   */
  async getUserApiKeys(userId: string): Promise<Array<{
    id: string;
    name: string;
    keyPrefix: string;
    scopes: ApiKeyScope[];
    status: ApiKeyStatus;
    rateLimit: number;
    expiresAt: Date | null;
    lastUsed: Date | null;
    lastRotated: Date | null;
    createdAt: Date;
  }>> {
    const result = await database.query(
      `SELECT
        id, name, key_prefix as "keyPrefix", scopes, status,
        rate_limit as "rateLimit", expires_at as "expiresAt",
        last_used as "lastUsed", last_rotated as "lastRotated",
        created_at as "createdAt"
       FROM api_keys
       WHERE user_id = $1 AND status != 'revoked'
       ORDER BY created_at DESC`,
      [userId],
    );

    return result.rows.map(row => ({
      ...row,
      scopes: typeof row.scopes === 'string' ? JSON.parse(row.scopes) : row.scopes,
    }));
  }

  /**
   * Get API key usage statistics
   */
  async getKeyUsageStats(keyId: string, userId: string): Promise<{
    totalRequests: number;
    requestsToday: number;
    requestsThisWeek: number;
    lastUsed: Date | null;
    topEndpoints: Array<{ endpoint: string; count: number }>;
  }> {
    const existing = await this.getKeyById(keyId);
    if (!existing || existing.userId !== userId) {
      throw new NotFoundError('API key not found');
    }

    // Get usage stats from activity logs
    const statsResult = await database.query(
      `SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 day') as today,
        COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '7 days') as week
       FROM api_key_usage
       WHERE api_key_id = $1`,
      [keyId],
    );

    const endpointsResult = await database.query(
      `SELECT endpoint, COUNT(*) as count
       FROM api_key_usage
       WHERE api_key_id = $1 AND timestamp > NOW() - INTERVAL '7 days'
       GROUP BY endpoint
       ORDER BY count DESC
       LIMIT 10`,
      [keyId],
    );

    const stats = statsResult.rows[0] || { total: 0, today: 0, week: 0 };

    return {
      totalRequests: parseInt(stats.total) || 0,
      requestsToday: parseInt(stats.today) || 0,
      requestsThisWeek: parseInt(stats.week) || 0,
      lastUsed: existing.lastUsed,
      topEndpoints: endpointsResult.rows.map(r => ({
        endpoint: r.endpoint,
        count: parseInt(r.count),
      })),
    };
  }

  // ============= Private Helper Methods =============

  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }

  private async getKeyById(keyId: string): Promise<ApiKey | null> {
    const result = await database.query<ApiKey>(
      `SELECT
        id, user_id as "userId", name, key_prefix as "keyPrefix", key_hash as "keyHash",
        scopes, status, rate_limit as "rateLimit", rate_limit_window as "rateLimitWindow",
        expires_at as "expiresAt", last_used as "lastUsed", last_rotated as "lastRotated",
        ip_whitelist as "ipWhitelist", metadata, created_at as "createdAt", updated_at as "updatedAt"
       FROM api_keys
       WHERE id = $1`,
      [keyId],
    );

    if (result.rows.length === 0) {
      return null;
    }

    const key = result.rows[0]!;
    key.scopes = typeof key.scopes === 'string' ? JSON.parse(key.scopes) : key.scopes;
    return key;
  }

  private async updateKeyStatus(keyId: string, status: ApiKeyStatus): Promise<void> {
    await database.query(
      `UPDATE api_keys SET status = $1, updated_at = NOW() WHERE id = $2`,
      [status, keyId],
    );
  }

  private async updateLastUsed(keyId: string): Promise<void> {
    await database.query(
      `UPDATE api_keys SET last_used = NOW() WHERE id = $1`,
      [keyId],
    );
  }

  private async checkRateLimit(key: ApiKey): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: Date;
  }> {
    const now = Date.now();
    const windowKey = `ratelimit:apikey:${key.id}`;
    const windowMs = key.rateLimitWindow * 1000;
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const resetTime = new Date(windowStart + windowMs);

    // Use Redis sliding window counter
    const currentCount = await redis.incr(windowKey);

    if (currentCount === 1) {
      // Set expiration on first request in window
      await redis.expire(windowKey, key.rateLimitWindow);
    }

    const remaining = Math.max(0, key.rateLimit - currentCount);
    const allowed = currentCount <= key.rateLimit;

    return { allowed, remaining, resetTime };
  }

  private isIpAllowed(ipAddress: string, whitelist: string[]): boolean {
    for (const allowed of whitelist) {
      if (allowed.includes('/')) {
        // CIDR notation
        if (this.isIpInCidr(ipAddress, allowed)) {
          return true;
        }
      } else if (allowed === ipAddress) {
        return true;
      }
    }
    return false;
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);

    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);

    return (ipNum & mask) === (rangeNum & mask);
  }

  private ipToNumber(ip: string): number {
    const parts = ip.split('.').map(Number);
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  }

  private async logActivity(
    userId: string,
    action: string,
    metadata?: Record<string, any>,
  ): Promise<void> {
    try {
      await database.query(
        `INSERT INTO activity_logs (id, user_id, action, resource_type, resource_id, metadata, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [
          generateId(),
          userId,
          action,
          'api_key',
          metadata?.keyId || userId,
          metadata ? JSON.stringify(metadata) : null,
        ],
      );
    } catch (error) {
      logger.error(`Failed to log API key activity: ${error}`);
    }
  }
}

export const apiKeyService = new ApiKeyService();
