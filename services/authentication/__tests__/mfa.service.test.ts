/**
 * MFA Service Unit Tests
 * Tests for multi-factor authentication functionality
 */

import { MfaService, MfaFactorType, MFA_REQUIREMENTS } from '../src/services/mfa.service';
import { BiometricType, BiometricStatus } from '../src/services/biometric.service';

// Mock dependencies
jest.mock('@apollo/shared', () => ({
  database: {
    query: jest.fn(),
  },
  redis: {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
  },
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  generateId: jest.fn(() => 'test-id-12345'),
  UnauthorizedError: class UnauthorizedError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UnauthorizedError';
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

jest.mock('speakeasy', () => ({
  generateSecret: jest.fn(() => ({
    base32: 'MOCK_SECRET_BASE32',
    otpauth_url: 'otpauth://totp/Apollo%20Platform:test@test.com?secret=MOCK_SECRET_BASE32',
  })),
  totp: {
    verify: jest.fn(),
  },
}));

jest.mock('qrcode', () => ({
  toDataURL: jest.fn(() => Promise.resolve('data:image/png;base64,mockQrCodeData')),
}));

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
}));

jest.mock('../src/services/biometric.service', () => ({
  biometricService: {
    getUserEnrollments: jest.fn(),
    authenticateWithBiometric: jest.fn(),
    authenticateWithBackupCode: jest.fn(),
  },
  BiometricType: {
    FINGERPRINT: 'fingerprint',
    FACE_ID: 'face_id',
    VOICE_PRINT: 'voice_print',
  },
  BiometricStatus: {
    ENROLLED: 'enrolled',
    NOT_ENROLLED: 'not_enrolled',
  },
}));

import { database, redis, UnauthorizedError, NotFoundError, BadRequestError } from '@apollo/shared';
import speakeasy from 'speakeasy';
import bcrypt from 'bcrypt';
import { biometricService } from '../src/services/biometric.service';

describe('MfaService', () => {
  let mfaService: MfaService;

  beforeEach(() => {
    mfaService = new MfaService();
    jest.clearAllMocks();
  });

  describe('setupMfa', () => {
    it('should successfully setup MFA for existing user', async () => {
      const userId = 'user-123';

      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ email: 'test@apollo.com' }],
      });

      const result = await mfaService.setupMfa(userId);

      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('qrCodeUrl');
      expect(result.secret).toBe('MOCK_SECRET_BASE32');
      expect(result.qrCodeUrl).toContain('data:image/png;base64');
      expect(redis.set).toHaveBeenCalledWith(
        `mfa:setup:${userId}`,
        'MOCK_SECRET_BASE32',
        600
      );
    });

    it('should throw NotFoundError for non-existent user', async () => {
      const userId = 'non-existent-user';

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(mfaService.setupMfa(userId)).rejects.toThrow(NotFoundError);
    });
  });

  describe('enableMfa', () => {
    const userId = 'user-123';
    const validToken = '123456';

    it('should enable MFA with valid token', async () => {
      (redis.get as jest.Mock).mockResolvedValueOnce('MOCK_SECRET_BASE32');
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(true);
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await mfaService.enableMfa(userId, validToken);

      expect(result).toHaveProperty('backupCodes');
      expect(result.backupCodes).toHaveLength(10);
      expect(redis.del).toHaveBeenCalledWith(`mfa:setup:${userId}`);
    });

    it('should throw UnauthorizedError when setup session expired', async () => {
      (redis.get as jest.Mock).mockResolvedValueOnce(null);

      await expect(mfaService.enableMfa(userId, validToken))
        .rejects.toThrow(UnauthorizedError);
    });

    it('should throw UnauthorizedError with invalid token', async () => {
      (redis.get as jest.Mock).mockResolvedValueOnce('MOCK_SECRET_BASE32');
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(false);

      await expect(mfaService.enableMfa(userId, 'invalid'))
        .rejects.toThrow(UnauthorizedError);
    });
  });

  describe('verifyMfa', () => {
    const userId = 'user-123';

    it('should verify TOTP token successfully', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{
          mfa_secret: 'MOCK_SECRET',
          mfa_backup_codes: '[]',
        }],
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(true);
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await mfaService.verifyMfa(userId, '123456');

      expect(result).toBe(true);
    });

    it('should verify backup code when TOTP fails', async () => {
      const backupCode = 'BACKUP01';

      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{
          mfa_secret: 'MOCK_SECRET',
          mfa_backup_codes: JSON.stringify([backupCode]),
        }],
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(false);
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await mfaService.verifyMfa(userId, backupCode);

      expect(result).toBe(true);
    });

    it('should throw NotFoundError when MFA not enabled', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(mfaService.verifyMfa(userId, '123456'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw UnauthorizedError with invalid token', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{
          mfa_secret: 'MOCK_SECRET',
          mfa_backup_codes: '[]',
        }],
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(false);

      await expect(mfaService.verifyMfa(userId, 'invalid'))
        .rejects.toThrow(UnauthorizedError);
    });
  });

  describe('disableMfa', () => {
    const userId = 'user-123';
    const password = 'validPassword123!';

    it('should disable MFA with valid password', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{ password_hash: 'hashed_password' }],
        })
        .mockResolvedValue({ rows: [] });
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(true);

      await mfaService.disableMfa(userId, password);

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE users'),
        expect.arrayContaining([userId])
      );
    });

    it('should throw NotFoundError for non-existent user', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(mfaService.disableMfa(userId, password))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw UnauthorizedError with invalid password', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ password_hash: 'hashed_password' }],
      });
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      await expect(mfaService.disableMfa(userId, 'wrongpassword'))
        .rejects.toThrow(UnauthorizedError);
    });
  });

  describe('regenerateBackupCodes', () => {
    const userId = 'user-123';
    const password = 'validPassword123!';

    it('should regenerate backup codes with valid password', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{ password_hash: 'hashed_password' }],
        })
        .mockResolvedValue({ rows: [] });
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(true);

      const result = await mfaService.regenerateBackupCodes(userId, password);

      expect(result).toHaveProperty('backupCodes');
      expect(result.backupCodes).toHaveLength(10);
    });

    it('should throw NotFoundError when MFA not enabled', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(mfaService.regenerateBackupCodes(userId, password))
        .rejects.toThrow(NotFoundError);
    });
  });

  describe('getAvailableMfaFactors', () => {
    const userId = 'user-123';

    it('should return available MFA factors', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ is_mfa_enabled: true }],
      });
      (biometricService.getUserEnrollments as jest.Mock).mockResolvedValueOnce([
        { type: BiometricType.FINGERPRINT, status: BiometricStatus.ENROLLED },
      ]);
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ phone_number: '+1234567890', email_verified: true }],
      });

      const factors = await mfaService.getAvailableMfaFactors(userId);

      expect(Array.isArray(factors)).toBe(true);
      expect(factors.find(f => f.type === MfaFactorType.TOTP)).toBeDefined();
    });
  });

  describe('startMfaChallenge', () => {
    const userId = 'user-123';
    const factorTypes = [MfaFactorType.TOTP, MfaFactorType.FINGERPRINT];

    it('should start MFA challenge successfully', async () => {
      const result = await mfaService.startMfaChallenge(userId, factorTypes);

      expect(result).toHaveProperty('challengeId');
      expect(result).toHaveProperty('requiredFactors');
      expect(result).toHaveProperty('expiresAt');
      expect(result.requiredFactors).toEqual(factorTypes);
      expect(redis.set).toHaveBeenCalled();
    });
  });

  describe('verifyMfaChallengeFactor', () => {
    const challengeId = 'challenge-123';

    it('should verify TOTP factor in challenge', async () => {
      const challengeData = JSON.stringify({
        userId: 'user-123',
        requiredFactors: [MfaFactorType.TOTP],
        verifiedFactors: [],
      });

      (redis.get as jest.Mock).mockResolvedValueOnce(challengeData);
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{
          mfa_secret: 'MOCK_SECRET',
          mfa_backup_codes: '[]',
        }],
      });
      (speakeasy.totp.verify as jest.Mock).mockReturnValueOnce(true);
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      const result = await mfaService.verifyMfaChallengeFactor(
        challengeId,
        MfaFactorType.TOTP,
        { token: '123456' }
      );

      expect(result.factorVerified).toBe(true);
      expect(result.challengeComplete).toBe(true);
      expect(result.remainingFactors).toHaveLength(0);
    });

    it('should throw UnauthorizedError for expired challenge', async () => {
      (redis.get as jest.Mock).mockResolvedValueOnce(null);

      await expect(
        mfaService.verifyMfaChallengeFactor(
          challengeId,
          MfaFactorType.TOTP,
          { token: '123456' }
        )
      ).rejects.toThrow(UnauthorizedError);
    });

    it('should throw BadRequestError for non-required factor', async () => {
      const challengeData = JSON.stringify({
        userId: 'user-123',
        requiredFactors: [MfaFactorType.TOTP],
        verifiedFactors: [],
      });

      (redis.get as jest.Mock).mockResolvedValueOnce(challengeData);

      await expect(
        mfaService.verifyMfaChallengeFactor(
          challengeId,
          MfaFactorType.SMS,
          { token: '123456' }
        )
      ).rejects.toThrow(BadRequestError);
    });
  });

  describe('sendOtpCode', () => {
    const userId = 'user-123';

    it('should send SMS OTP code', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ email: 'test@apollo.com', phone_number: '+1234567890' }],
      });
      (database.query as jest.Mock).mockResolvedValue({ rows: [] });

      await mfaService.sendOtpCode(userId, MfaFactorType.SMS);

      expect(redis.set).toHaveBeenCalled();
    });

    it('should throw NotFoundError for non-existent user', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(mfaService.sendOtpCode(userId, MfaFactorType.SMS))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw BadRequestError when phone not configured', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ email: 'test@apollo.com', phone_number: null }],
      });

      await expect(mfaService.sendOtpCode(userId, MfaFactorType.SMS))
        .rejects.toThrow(BadRequestError);
    });
  });

  describe('checkMfaRequirements', () => {
    const userId = 'user-123';

    it('should check requirements for UNCLASSIFIED clearance', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ is_mfa_enabled: true }],
      });
      (biometricService.getUserEnrollments as jest.Mock).mockResolvedValueOnce([]);
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ phone_number: null, email_verified: false }],
      });

      const result = await mfaService.checkMfaRequirements(userId, 'UNCLASSIFIED');

      expect(result).toHaveProperty('meetsRequirements');
      expect(result).toHaveProperty('requiredFactors');
      expect(result).toHaveProperty('enabledFactors');
    });

    it('should require multiple factors for TOP_SECRET clearance', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ is_mfa_enabled: false }],
      });
      (biometricService.getUserEnrollments as jest.Mock).mockResolvedValueOnce([]);
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ phone_number: null, email_verified: false }],
      });

      const result = await mfaService.checkMfaRequirements(userId, 'TOP_SECRET');

      expect(result.meetsRequirements).toBe(false);
      expect(result.missingRequiredTypes).toContain(MfaFactorType.TOTP);
      expect(result.missingRequiredTypes).toContain(MfaFactorType.FINGERPRINT);
    });
  });

  describe('MFA_REQUIREMENTS configuration', () => {
    it('should have correct requirements for each clearance level', () => {
      expect(MFA_REQUIREMENTS.UNCLASSIFIED.minFactors).toBe(1);
      expect(MFA_REQUIREMENTS.RESTRICTED.minFactors).toBe(1);
      expect(MFA_REQUIREMENTS.CONFIDENTIAL.minFactors).toBe(2);
      expect(MFA_REQUIREMENTS.SECRET.minFactors).toBe(2);
      expect(MFA_REQUIREMENTS.SECRET.requiredTypes).toContain(MfaFactorType.TOTP);
      expect(MFA_REQUIREMENTS.TOP_SECRET.minFactors).toBe(2);
      expect(MFA_REQUIREMENTS.TOP_SECRET.requiredTypes).toContain(MfaFactorType.TOTP);
      expect(MFA_REQUIREMENTS.TOP_SECRET.requiredTypes).toContain(MfaFactorType.FINGERPRINT);
    });
  });
});
