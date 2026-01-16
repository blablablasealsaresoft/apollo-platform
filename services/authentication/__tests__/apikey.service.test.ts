/**
 * API Key Service Unit Tests
 * Tests for API key creation, validation, rotation, and rate limiting
 */

import { ApiKeyService, ApiKeyScope, ApiKeyStatus, SCOPE_PRESETS } from '../src/services/apikey.service';

// Mock dependencies
jest.mock('@apollo/shared', () => ({
  database: {
    query: jest.fn(),
  },
  redis: {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn(),
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  generateId: jest.fn(() => 'test-key-id-12345'),
  UnauthorizedError: class UnauthorizedError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UnauthorizedError';
    }
  },
  ForbiddenError: class ForbiddenError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'ForbiddenError';
    }
  },
  NotFoundError: class NotFoundError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'NotFoundError';
    }
  },
  BadRequestError: class BadRequestError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'BadRequestError';
    }
  },
}));

jest.mock('crypto', () => ({
  randomBytes: jest.fn(() => Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex')),
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => 'mock-hash-value'),
  })),
}));

import { database, redis, UnauthorizedError, ForbiddenError, NotFoundError, BadRequestError } from '@apollo/shared';

describe('ApiKeyService', () => {
  let apiKeyService: ApiKeyService;
  const userId = 'user-123';

  beforeEach(() => {
    apiKeyService = new ApiKeyService();
    jest.clearAllMocks();
  });

  describe('createApiKey', () => {
    it('should create API key successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] }) // Key count check
        .mockResolvedValueOnce({ rows: [] }) // Insert
        .mockResolvedValue({ rows: [] }); // Log activity

      const result = await apiKeyService.createApiKey({
        userId,
        name: 'Test API Key',
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
      });

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('apiKey');
      expect(result).toHaveProperty('keyPrefix');
      expect(result.apiKey).toMatch(/^apollo_/);
      expect(result.name).toBe('Test API Key');
    });

    it('should throw BadRequestError when max keys limit reached', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [{ count: '10' }] });

      await expect(
        apiKeyService.createApiKey({
          userId,
          name: 'Test Key',
          scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        })
      ).rejects.toThrow(BadRequestError);
    });

    it('should set expiration date when expiresIn provided', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValue({ rows: [] });

      const result = await apiKeyService.createApiKey({
        userId,
        name: 'Expiring Key',
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        expiresIn: 30, // 30 days
      });

      expect(result.expiresAt).not.toBeNull();
    });

    it('should use custom rate limit when provided', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValue({ rows: [] });

      await apiKeyService.createApiKey({
        userId,
        name: 'Rate Limited Key',
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 50,
        rateLimitWindow: 120,
      });

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO api_keys'),
        expect.arrayContaining([50, 120])
      );
    });
  });

  describe('validateApiKey', () => {
    const validApiKey = 'apollo_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    it('should validate active API key successfully', async () => {
      const mockKey = {
        id: 'key-123',
        userId,
        name: 'Test Key',
        keyPrefix: 'apollo_01234',
        keyHash: 'mock-hash',
        scopes: JSON.stringify([ApiKeyScope.READ_INVESTIGATIONS]),
        status: ApiKeyStatus.ACTIVE,
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(null); // Not cached
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [mockKey] });
      (redis.incr as jest.Mock).mockResolvedValueOnce(1); // Rate limit counter

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(true);
      expect(result.key).toBeDefined();
      expect(result.remainingRequests).toBe(99);
    });

    it('should use cached key for validation', async () => {
      const cachedKey = {
        id: 'key-123',
        userId,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        status: ApiKeyStatus.ACTIVE,
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(cachedKey));
      (redis.incr as jest.Mock).mockResolvedValueOnce(1);

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(true);
      expect(database.query).not.toHaveBeenCalled();
    });

    it('should reject invalid API key format', async () => {
      const result = await apiKeyService.validateApiKey('invalid-key');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid API key format');
    });

    it('should reject non-existent key', async () => {
      (redis.get as jest.Mock).mockResolvedValueOnce(null);
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('API key not found');
    });

    it('should reject inactive key', async () => {
      const inactiveKey = {
        id: 'key-123',
        status: ApiKeyStatus.INACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(inactiveKey));

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('API key is inactive');
    });

    it('should reject expired key', async () => {
      const expiredKey = {
        id: 'key-123',
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: new Date(Date.now() - 86400000).toISOString(), // Expired yesterday
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(expiredKey));
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('API key has expired');
    });

    it('should reject IP not in whitelist', async () => {
      const keyWithWhitelist = {
        id: 'key-123',
        userId,
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: ['10.0.0.0/8', '192.168.1.1'],
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(keyWithWhitelist));
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await apiKeyService.validateApiKey(validApiKey, undefined, '172.16.0.1');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('IP address not allowed');
    });

    it('should allow IP in whitelist', async () => {
      const keyWithWhitelist = {
        id: 'key-123',
        userId,
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: ['10.0.0.0/8', '192.168.1.1'],
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(keyWithWhitelist));
      (redis.incr as jest.Mock).mockResolvedValueOnce(1);

      const result = await apiKeyService.validateApiKey(validApiKey, undefined, '10.1.2.3');

      expect(result.valid).toBe(true);
    });

    it('should reject when rate limit exceeded', async () => {
      const rateLimitedKey = {
        id: 'key-123',
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(rateLimitedKey));
      (redis.incr as jest.Mock).mockResolvedValueOnce(101); // Over limit

      const result = await apiKeyService.validateApiKey(validApiKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Rate limit exceeded');
      expect(result.remainingRequests).toBe(0);
    });

    it('should reject when missing required scopes', async () => {
      const limitedScopeKey = {
        id: 'key-123',
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(limitedScopeKey));
      (redis.incr as jest.Mock).mockResolvedValueOnce(1);

      const result = await apiKeyService.validateApiKey(
        validApiKey,
        [ApiKeyScope.WRITE_INVESTIGATIONS, ApiKeyScope.ADMIN_FULL]
      );

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing required scopes');
    });

    it('should allow ADMIN_FULL to bypass scope checks', async () => {
      const adminKey = {
        id: 'key-123',
        status: ApiKeyStatus.ACTIVE,
        scopes: [ApiKeyScope.ADMIN_FULL],
        rateLimit: 100,
        rateLimitWindow: 60,
        expiresAt: null,
        ipWhitelist: null,
      };

      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(adminKey));
      (redis.incr as jest.Mock).mockResolvedValueOnce(1);

      const result = await apiKeyService.validateApiKey(
        validApiKey,
        [ApiKeyScope.WRITE_INVESTIGATIONS, ApiKeyScope.READ_TARGETS]
      );

      expect(result.valid).toBe(true);
    });
  });

  describe('rotateApiKey', () => {
    it('should rotate API key successfully', async () => {
      const existingKey = {
        id: 'key-123',
        userId,
        status: ApiKeyStatus.ACTIVE,
        keyHash: 'old-hash',
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [existingKey] }) // getKeyById
        .mockResolvedValueOnce({ rows: [] }) // Update
        .mockResolvedValue({ rows: [] }); // Log activity

      const result = await apiKeyService.rotateApiKey('key-123', userId);

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('newApiKey');
      expect(result).toHaveProperty('keyPrefix');
      expect(redis.del).toHaveBeenCalled();
    });

    it('should throw NotFoundError for non-existent key', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        apiKeyService.rotateApiKey('non-existent', userId)
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw NotFoundError when user doesnt own key', async () => {
      const otherUserKey = {
        id: 'key-123',
        userId: 'other-user',
        status: ApiKeyStatus.ACTIVE,
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [otherUserKey] });

      await expect(
        apiKeyService.rotateApiKey('key-123', userId)
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw BadRequestError for inactive key', async () => {
      const inactiveKey = {
        id: 'key-123',
        userId,
        status: ApiKeyStatus.INACTIVE,
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [inactiveKey] });

      await expect(
        apiKeyService.rotateApiKey('key-123', userId)
      ).rejects.toThrow(BadRequestError);
    });
  });

  describe('revokeApiKey', () => {
    it('should revoke API key successfully', async () => {
      const existingKey = {
        id: 'key-123',
        userId,
        keyHash: 'hash',
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [existingKey] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValue({ rows: [] });

      await apiKeyService.revokeApiKey('key-123', userId, 'User requested');

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE api_keys SET status'),
        [ApiKeyStatus.REVOKED, 'key-123']
      );
      expect(redis.del).toHaveBeenCalledTimes(2); // Cache and rate limit
    });

    it('should throw ForbiddenError when trying to revoke others key', async () => {
      const otherUserKey = {
        id: 'key-123',
        userId: 'other-user',
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [otherUserKey] });

      await expect(
        apiKeyService.revokeApiKey('key-123', userId)
      ).rejects.toThrow(ForbiddenError);
    });
  });

  describe('updateScopes', () => {
    it('should update API key scopes', async () => {
      const existingKey = {
        id: 'key-123',
        userId,
        scopes: [ApiKeyScope.READ_INVESTIGATIONS],
        keyHash: 'hash',
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [existingKey] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValue({ rows: [] });

      const newScopes = [ApiKeyScope.READ_INVESTIGATIONS, ApiKeyScope.WRITE_INVESTIGATIONS];
      await apiKeyService.updateScopes('key-123', userId, newScopes);

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE api_keys SET scopes'),
        [JSON.stringify(newScopes), 'key-123']
      );
    });
  });

  describe('updateRateLimit', () => {
    it('should update rate limit', async () => {
      const existingKey = {
        id: 'key-123',
        userId,
        keyHash: 'hash',
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [existingKey] })
        .mockResolvedValue({ rows: [] });

      await apiKeyService.updateRateLimit('key-123', userId, 200, 120);

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE api_keys'),
        [200, 120, 'key-123']
      );
    });
  });

  describe('getUserApiKeys', () => {
    it('should return user API keys', async () => {
      const mockKeys = [
        {
          id: 'key-1',
          name: 'Key 1',
          keyPrefix: 'apollo_',
          scopes: JSON.stringify([ApiKeyScope.READ_INVESTIGATIONS]),
          status: ApiKeyStatus.ACTIVE,
          rateLimit: 100,
          expiresAt: null,
          lastUsed: null,
          lastRotated: null,
          createdAt: new Date(),
        },
      ];

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: mockKeys });

      const result = await apiKeyService.getUserApiKeys(userId);

      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('name');
      expect(Array.isArray(result[0].scopes)).toBe(true);
    });
  });

  describe('getKeyUsageStats', () => {
    it('should return usage statistics', async () => {
      const existingKey = {
        id: 'key-123',
        userId,
        lastUsed: new Date(),
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [existingKey] }) // getKeyById
        .mockResolvedValueOnce({ rows: [{ total: '100', today: '10', week: '50' }] })
        .mockResolvedValueOnce({
          rows: [
            { endpoint: '/api/investigations', count: '30' },
            { endpoint: '/api/targets', count: '20' },
          ],
        });

      const result = await apiKeyService.getKeyUsageStats('key-123', userId);

      expect(result.totalRequests).toBe(100);
      expect(result.requestsToday).toBe(10);
      expect(result.requestsThisWeek).toBe(50);
      expect(result.topEndpoints).toHaveLength(2);
    });

    it('should throw NotFoundError for non-existent key', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        apiKeyService.getKeyUsageStats('non-existent', userId)
      ).rejects.toThrow(NotFoundError);
    });
  });

  describe('SCOPE_PRESETS', () => {
    it('should have readonly preset with read-only scopes', () => {
      expect(SCOPE_PRESETS.readonly).toContain(ApiKeyScope.READ_INVESTIGATIONS);
      expect(SCOPE_PRESETS.readonly).toContain(ApiKeyScope.READ_TARGETS);
      expect(SCOPE_PRESETS.readonly).not.toContain(ApiKeyScope.WRITE_INVESTIGATIONS);
    });

    it('should have analyst preset with appropriate scopes', () => {
      expect(SCOPE_PRESETS.analyst).toContain(ApiKeyScope.READ_INVESTIGATIONS);
      expect(SCOPE_PRESETS.analyst).toContain(ApiKeyScope.WRITE_INVESTIGATIONS);
      expect(SCOPE_PRESETS.analyst).toContain(ApiKeyScope.OSINT_TOOLS);
    });

    it('should have admin preset with full access', () => {
      expect(SCOPE_PRESETS.admin).toContain(ApiKeyScope.ADMIN_FULL);
    });
  });
});
