/**
 * Session Service Unit Tests
 * Tests for session management, token handling, and device tracking
 */

import { SessionService, DeviceInfo, createSession } from '../src/services/session.service';

// Mock dependencies
jest.mock('@apollo/shared', () => ({
  config: {
    jwt: {
      secret: 'test-secret-key-12345',
      accessExpiration: '15m',
      refreshExpiration: '7d',
    },
  },
  database: {
    query: jest.fn(),
  },
  redis: {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    srem: jest.fn(),
    expire: jest.fn(),
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  generateId: jest.fn(() => 'test-session-id-12345'),
  generateToken: jest.fn(() => 'test-token-12345'),
  UnauthorizedError: class UnauthorizedError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UnauthorizedError';
    }
  },
  ForbiddenError: class ForbiddenError extends Error {
    code: string;
    constructor(message: string, options?: { code?: string }) {
      super(message);
      this.name = 'ForbiddenError';
      this.code = options?.code || 'FORBIDDEN';
    }
  },
  UserRole: {
    ADMIN: 'admin',
    INVESTIGATOR: 'investigator',
    ANALYST: 'analyst',
    VIEWER: 'viewer',
  },
  ClearanceLevel: {
    TOP_SECRET: 'top_secret',
    SECRET: 'secret',
    CONFIDENTIAL: 'confidential',
    RESTRICTED: 'restricted',
    UNCLASSIFIED: 'unclassified',
  },
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mock.jwt.token'),
  verify: jest.fn(),
}));

import { config, database, redis, UnauthorizedError, ForbiddenError, UserRole, ClearanceLevel } from '@apollo/shared';
import jwt from 'jsonwebtoken';

describe('SessionService', () => {
  let sessionService: SessionService;
  const mockUser = {
    id: 'user-123',
    email: 'test@apollo.com',
    role: UserRole.ANALYST,
    clearanceLevel: ClearanceLevel.SECRET,
  };

  const mockDevice: DeviceInfo = {
    deviceName: 'Chrome on Windows',
    deviceType: 'desktop',
    ipAddress: '192.168.1.100',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
  };

  beforeEach(() => {
    sessionService = new SessionService();
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should initialize with default configuration', () => {
      const service = new SessionService();
      expect(service).toBeInstanceOf(SessionService);
    });

    it('should accept custom configuration', () => {
      const customConfig = {
        maxConcurrentSessions: 10,
        accessTokenExpiry: '30m',
        sessionTimeout: 60 * 60,
      };
      const service = new SessionService(customConfig);
      expect(service).toBeInstanceOf(SessionService);
    });
  });

  describe('createSession', () => {
    beforeEach(() => {
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });
      (redis.set as jest.Mock).mockResolvedValue('OK');
      (redis.sadd as jest.Mock).mockResolvedValue(1);
    });

    it('should create session successfully', async () => {
      const result = await sessionService.createSession(mockUser as any, mockDevice);

      expect(result).toHaveProperty('sessionId');
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('expiresIn');
      expect(result.tokenType).toBe('Bearer');
    });

    it('should remove oldest session when limit exceeded', async () => {
      // Mock 5 existing sessions (at the limit)
      const existingSessions = Array(5).fill(null).map((_, i) => ({
        id: `session-${i}`,
        createdAt: new Date(Date.now() - (5 - i) * 1000),
      }));

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: existingSessions }) // getActiveSessions
        .mockResolvedValueOnce({ rows: [{ userId: mockUser.id }] }) // invalidateSession lookup
        .mockResolvedValue({ rows: [] }); // other queries

      await sessionService.createSession(mockUser as any, mockDevice);

      // Verify oldest session was invalidated
      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE user_sessions SET is_active = false'),
        expect.any(Array)
      );
    });

    it('should throw ForbiddenError for new device when MFA not verified', async () => {
      const serviceWithMfaRequired = new SessionService({
        requireMfaForNewDevices: true,
      });

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // No existing sessions
        .mockResolvedValueOnce({ rows: [] }); // isNewDevice check

      await expect(
        serviceWithMfaRequired.createSession(mockUser as any, mockDevice, { mfaVerified: false })
      ).rejects.toThrow(ForbiddenError);
    });

    it('should allow new device when MFA is verified', async () => {
      const serviceWithMfaRequired = new SessionService({
        requireMfaForNewDevices: true,
      });

      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await serviceWithMfaRequired.createSession(
        mockUser as any,
        mockDevice,
        { mfaVerified: true }
      );

      expect(result).toHaveProperty('sessionId');
    });

    it('should store session with biometric verification flag', async () => {
      const result = await sessionService.createSession(
        mockUser as any,
        mockDevice,
        { biometricVerified: true }
      );

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO user_sessions'),
        expect.arrayContaining([true]) // biometric_verified = true
      );
    });
  });

  describe('refreshTokens', () => {
    const mockRefreshToken = 'mock.refresh.token';

    it('should refresh tokens successfully', async () => {
      (jwt.verify as jest.Mock).mockReturnValueOnce({ userId: mockUser.id });
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{
            id: 'session-123',
            deviceId: 'device-hash',
            mfaVerified: true,
            biometricVerified: false,
            expiresAt: new Date(Date.now() + 86400000),
          }],
        })
        .mockResolvedValueOnce({ rows: [mockUser] })
        .mockResolvedValue({ rows: [] });

      const result = await sessionService.refreshTokens(mockRefreshToken, mockDevice);

      expect(result).toHaveProperty('sessionId');
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
    });

    it('should throw UnauthorizedError for invalid refresh token', async () => {
      (jwt.verify as jest.Mock).mockImplementationOnce(() => {
        throw new Error('Invalid token');
      });

      await expect(
        sessionService.refreshTokens('invalid-token', mockDevice)
      ).rejects.toThrow(UnauthorizedError);
    });

    it('should throw UnauthorizedError when session not found', async () => {
      (jwt.verify as jest.Mock).mockReturnValueOnce({ userId: mockUser.id });
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        sessionService.refreshTokens(mockRefreshToken, mockDevice)
      ).rejects.toThrow(UnauthorizedError);
    });

    it('should invalidate all sessions on device mismatch', async () => {
      (jwt.verify as jest.Mock).mockReturnValueOnce({ userId: mockUser.id });
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{
            id: 'session-123',
            deviceId: 'different-device-hash',
            expiresAt: new Date(Date.now() + 86400000),
          }],
        })
        .mockResolvedValueOnce({ rows: [{ id: 'session-1' }, { id: 'session-2' }] })
        .mockResolvedValue({ rows: [] });

      await expect(
        sessionService.refreshTokens(mockRefreshToken, mockDevice)
      ).rejects.toThrow(UnauthorizedError);

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE user_sessions SET is_active = false'),
        expect.arrayContaining([mockUser.id])
      );
    });
  });

  describe('validateAccessToken', () => {
    const mockAccessToken = 'mock.access.token';

    it('should validate token from Redis cache', async () => {
      const sessionData = {
        userId: mockUser.id,
        deviceId: 'device-hash',
        mfaVerified: true,
        biometricVerified: false,
      };

      (jwt.verify as jest.Mock).mockReturnValueOnce({
        userId: mockUser.id,
        sessionId: 'session-123',
      });
      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify(sessionData));
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await sessionService.validateAccessToken(mockAccessToken);

      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('sessionId');
      expect(result.mfaVerified).toBe(true);
    });

    it('should fall back to database when not in cache', async () => {
      (jwt.verify as jest.Mock).mockReturnValueOnce({
        userId: mockUser.id,
        sessionId: 'session-123',
      });
      (redis.get as jest.Mock).mockResolvedValueOnce(null);
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{
          id: 'session-123',
          mfaVerified: true,
          biometricVerified: false,
        }],
      });

      const result = await sessionService.validateAccessToken(mockAccessToken);

      expect(result).toHaveProperty('sessionId');
      expect(redis.set).toHaveBeenCalled(); // Re-cache
    });

    it('should throw UnauthorizedError for invalid token', async () => {
      (jwt.verify as jest.Mock).mockImplementationOnce(() => {
        throw new Error('Invalid');
      });

      await expect(
        sessionService.validateAccessToken('invalid-token')
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe('invalidateSession', () => {
    it('should invalidate specific session', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ userId: mockUser.id }] })
        .mockResolvedValue({ rows: [] });

      await sessionService.invalidateSession('session-123', 'user_logout');

      expect(database.query).toHaveBeenCalledWith(
        'UPDATE user_sessions SET is_active = false WHERE id = $1',
        ['session-123']
      );
      expect(redis.del).toHaveBeenCalledWith('session:session-123');
      expect(redis.srem).toHaveBeenCalled();
    });

    it('should do nothing for non-existent session', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await sessionService.invalidateSession('non-existent', 'test');

      expect(redis.del).not.toHaveBeenCalled();
    });
  });

  describe('invalidateAllSessions', () => {
    it('should invalidate all user sessions', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            { id: 'session-1' },
            { id: 'session-2' },
            { id: 'session-3' },
          ],
        })
        .mockResolvedValue({ rows: [] });

      const count = await sessionService.invalidateAllSessions(mockUser.id, 'password_change');

      expect(count).toBe(3);
      expect(redis.del).toHaveBeenCalledTimes(4); // 3 sessions + user_sessions set
    });

    it('should return 0 when no active sessions', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      const count = await sessionService.invalidateAllSessions(mockUser.id, 'test');

      expect(count).toBe(0);
    });
  });

  describe('invalidateOtherSessions', () => {
    it('should invalidate all sessions except current', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            { id: 'session-2' },
            { id: 'session-3' },
          ],
        })
        .mockResolvedValue({ rows: [] });

      const count = await sessionService.invalidateOtherSessions(mockUser.id, 'session-1');

      expect(count).toBe(2);
    });
  });

  describe('getActiveSessions', () => {
    it('should return list of active sessions', async () => {
      const mockSessions = [
        {
          id: 'session-1',
          deviceName: 'Chrome',
          deviceType: 'desktop',
          ipAddress: '192.168.1.1',
          lastActivity: new Date(),
          createdAt: new Date(),
          mfaVerified: true,
          biometricVerified: false,
        },
      ];

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: mockSessions });

      const sessions = await sessionService.getActiveSessions(mockUser.id);

      expect(sessions).toHaveLength(1);
      expect(sessions[0]).toHaveProperty('id');
      expect(sessions[0]).toHaveProperty('isCurrent');
    });
  });

  describe('updateMfaVerification', () => {
    it('should update MFA verification status', async () => {
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });
      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify({
        userId: mockUser.id,
        mfaVerified: false,
      }));

      await sessionService.updateMfaVerification('session-123', true);

      expect(database.query).toHaveBeenCalledWith(
        'UPDATE user_sessions SET mfa_verified = $1 WHERE id = $2',
        [true, 'session-123']
      );
      expect(redis.set).toHaveBeenCalled();
    });
  });

  describe('updateBiometricVerification', () => {
    it('should update biometric verification status', async () => {
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });
      (redis.get as jest.Mock).mockResolvedValueOnce(JSON.stringify({
        userId: mockUser.id,
        biometricVerified: false,
      }));

      await sessionService.updateBiometricVerification('session-123', true);

      expect(database.query).toHaveBeenCalledWith(
        'UPDATE user_sessions SET biometric_verified = $1 WHERE id = $2',
        [true, 'session-123']
      );
    });
  });

  describe('cleanupInactiveSessions', () => {
    it('should clean up inactive sessions', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          { id: 'old-session-1', user_id: mockUser.id },
          { id: 'old-session-2', user_id: mockUser.id },
        ],
      });

      const count = await sessionService.cleanupInactiveSessions();

      expect(count).toBe(2);
      expect(redis.del).toHaveBeenCalledTimes(2);
      expect(redis.srem).toHaveBeenCalledTimes(2);
    });
  });

  describe('createSessionLegacy', () => {
    it('should create legacy session format', async () => {
      const result = await createSession('user-123');

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('userId');
      expect(result).toHaveProperty('issuedAt');
      expect(result).toHaveProperty('expiresAt');
      expect(result.userId).toBe('user-123');
    });
  });
});
