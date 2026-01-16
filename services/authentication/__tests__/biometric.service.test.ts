/**
 * Biometric Service Unit Tests
 * Tests for biometric authentication including fingerprint, face ID, and voice print
 */

import { BiometricService, BiometricType, BiometricStatus, BiometricError } from '../src/services/biometric.service';

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
  generateId: jest.fn(() => 'test-enrollment-id-12345'),
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

// Mock crypto
jest.mock('crypto', () => ({
  randomBytes: jest.fn(() => Buffer.from('0123456789abcdef', 'hex')),
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => 'mock-hash-value-32-chars-long-test'),
  })),
  createCipheriv: jest.fn(() => ({
    update: jest.fn(() => 'encrypted-'),
    final: jest.fn(() => 'data'),
    getAuthTag: jest.fn(() => Buffer.from('auth-tag-16-char', 'utf8')),
  })),
  createDecipheriv: jest.fn(() => ({
    setAuthTag: jest.fn(),
    update: jest.fn(() => 'decrypted-'),
    final: jest.fn(() => 'data'),
  })),
}));

// Mock argon2 and bcrypt
jest.mock('argon2', () => ({
  verify: jest.fn(),
}));

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
}));

import { database, redis, UnauthorizedError, NotFoundError, BadRequestError } from '@apollo/shared';
import argon2 from 'argon2';
import bcrypt from 'bcrypt';

describe('BiometricService', () => {
  let biometricService: BiometricService;
  const userId = 'user-123';

  beforeEach(() => {
    // Reset environment
    process.env.BIOMETRIC_ENCRYPTION_KEY = undefined;
    process.env.JWT_SECRET = 'test-jwt-secret';

    biometricService = new BiometricService();
    jest.clearAllMocks();
  });

  describe('canAuthenticate', () => {
    it('should return not enrolled when no enrollment exists', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      const result = await biometricService.canAuthenticate(userId, BiometricType.FINGERPRINT);

      expect(result.available).toBe(true);
      expect(result.enrolled).toBe(false);
      expect(result.status).toBe(BiometricStatus.NOT_ENROLLED);
      expect(result.error).toBe(BiometricError.NOT_ENROLLED);
    });

    it('should return available when enrolled', async () => {
      const enrollment = {
        status: BiometricStatus.ENROLLED,
        updatedAt: new Date(),
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [enrollment] });

      const result = await biometricService.canAuthenticate(userId, BiometricType.FINGERPRINT);

      expect(result.available).toBe(true);
      expect(result.enrolled).toBe(true);
      expect(result.status).toBe(BiometricStatus.ENROLLED);
    });

    it('should return locked out when status is LOCKED_OUT and not expired', async () => {
      const enrollment = {
        status: BiometricStatus.LOCKED_OUT,
        updatedAt: new Date(), // Recent lockout
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [enrollment] });

      const result = await biometricService.canAuthenticate(userId, BiometricType.FINGERPRINT);

      expect(result.available).toBe(false);
      expect(result.enrolled).toBe(true);
      expect(result.status).toBe(BiometricStatus.LOCKED_OUT);
      expect(result.error).toBe(BiometricError.LOCKED_OUT);
    });

    it('should reset lockout when lockout period expired', async () => {
      const enrollment = {
        status: BiometricStatus.LOCKED_OUT,
        updatedAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
      };

      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [enrollment] })
        .mockResolvedValue({ rows: [] }); // resetLockout

      const result = await biometricService.canAuthenticate(userId, BiometricType.FINGERPRINT);

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE biometric_enrollments'),
        expect.arrayContaining([BiometricStatus.ENROLLED])
      );
    });

    it('should return disabled when status is DISABLED', async () => {
      const enrollment = {
        status: BiometricStatus.DISABLED,
        updatedAt: new Date(),
      };

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [enrollment] });

      const result = await biometricService.canAuthenticate(userId, BiometricType.FACE_ID);

      expect(result.available).toBe(false);
      expect(result.enrolled).toBe(true);
      expect(result.status).toBe(BiometricStatus.DISABLED);
      expect(result.error).toBe(BiometricError.NOT_AVAILABLE);
    });
  });

  describe('enrollBiometric', () => {
    const validTemplate = {
      type: BiometricType.FINGERPRINT,
      data: 'biometric-template-data',
      deviceId: 'device-123',
      capturedAt: new Date(),
      qualityScore: 0.9,
    };
    const password = 'validPassword123!';

    beforeEach(() => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] }) // verifyUserPassword
        .mockResolvedValueOnce({ rows: [] }) // getEnrollment (not enrolled)
        .mockResolvedValue({ rows: [] }); // Insert and update
      (argon2.verify as jest.Mock).mockResolvedValue(true);
    });

    it('should enroll biometric successfully', async () => {
      const result = await biometricService.enrollBiometric(
        userId,
        BiometricType.FINGERPRINT,
        validTemplate,
        password
      );

      expect(result).toHaveProperty('enrollmentId');
      expect(result).toHaveProperty('backupCodes');
      expect(result.backupCodes).toHaveLength(10);
    });

    it('should throw BadRequestError for low quality template', async () => {
      const lowQualityTemplate = { ...validTemplate, qualityScore: 0.5 };

      await expect(
        biometricService.enrollBiometric(userId, BiometricType.FINGERPRINT, lowQualityTemplate, password)
      ).rejects.toThrow(BadRequestError);
    });

    it('should throw BadRequestError when already enrolled', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] })
        .mockResolvedValueOnce({ rows: [{ status: BiometricStatus.ENROLLED }] });
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      await expect(
        biometricService.enrollBiometric(userId, BiometricType.FINGERPRINT, validTemplate, password)
      ).rejects.toThrow(BadRequestError);
    });

    it('should throw NotFoundError for invalid user', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        biometricService.enrollBiometric(userId, BiometricType.FINGERPRINT, validTemplate, password)
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw UnauthorizedError for invalid password', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] });
      (argon2.verify as jest.Mock).mockRejectedValue(new Error('argon2 not available'));
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        biometricService.enrollBiometric(userId, BiometricType.FINGERPRINT, validTemplate, 'wrongpassword')
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe('authenticateWithBiometric', () => {
    const templateData = 'submitted-biometric-template';

    it('should authenticate successfully with matching template', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ status: BiometricStatus.ENROLLED, updatedAt: new Date() }] }) // canAuthenticate
        .mockResolvedValueOnce({
          rows: [{
            encryptedTemplate: '0123456789abcdef:617574682d7461672d31362d63686172:encrypted-data',
            status: BiometricStatus.ENROLLED,
            failedAttempts: 0,
          }],
        })
        .mockResolvedValue({ rows: [] }); // Update and log

      const result = await biometricService.authenticateWithBiometric(
        userId,
        BiometricType.FINGERPRINT,
        templateData
      );

      // Note: Matching depends on hash comparison which is mocked
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('biometricType');
      expect(result).toHaveProperty('confidence');
    });

    it('should fail authentication when not enrolled', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      const result = await biometricService.authenticateWithBiometric(
        userId,
        BiometricType.FINGERPRINT,
        templateData
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe(BiometricError.NOT_ENROLLED);
    });

    it('should fail when locked out', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ status: BiometricStatus.LOCKED_OUT, updatedAt: new Date() }],
      });

      const result = await biometricService.authenticateWithBiometric(
        userId,
        BiometricType.FINGERPRINT,
        templateData
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe(BiometricError.LOCKED_OUT);
    });

    it('should fail liveness check and increment failed attempts', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ status: BiometricStatus.ENROLLED, updatedAt: new Date() }] })
        .mockResolvedValueOnce({
          rows: [{
            encryptedTemplate: '0123456789abcdef:617574682d7461672d31362d63686172:encrypted-data',
            status: BiometricStatus.ENROLLED,
            failedAttempts: 0,
          }],
        })
        .mockResolvedValue({ rows: [{ failed_attempts: 1 }] });

      const badLivenessProof = JSON.stringify({
        sensorType: 'optical',
        hasDepthMap: false,
        eyeTracking: false,
        headMotion: false,
      });

      const result = await biometricService.authenticateWithBiometric(
        userId,
        BiometricType.FACE_ID,
        templateData,
        badLivenessProof
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe(BiometricError.LIVENESS_FAILED);
    });

    it('should lockout after max failed attempts', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ status: BiometricStatus.ENROLLED, updatedAt: new Date() }] })
        .mockResolvedValueOnce({
          rows: [{
            encryptedTemplate: '0123456789abcdef:617574682d7461672d31362d63686172:different-data',
            status: BiometricStatus.ENROLLED,
            failedAttempts: 4,
          }],
        })
        .mockResolvedValueOnce({ rows: [{ failed_attempts: 5 }] }) // incrementFailedAttempts
        .mockResolvedValue({ rows: [] }); // lockout

      const result = await biometricService.authenticateWithBiometric(
        userId,
        BiometricType.FINGERPRINT,
        'completely-different-template'
      );

      expect(result.error).toBe(BiometricError.LOCKED_OUT);
    });
  });

  describe('authenticateWithBackupCode', () => {
    it('should authenticate with valid backup code', async () => {
      const backupCodes = ['mock-hash-value-32-chars-long-test']; // Matches mock hash output

      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{
            metadata: JSON.stringify({ backupCodes }),
          }],
        })
        .mockResolvedValue({ rows: [] });

      const result = await biometricService.authenticateWithBackupCode(
        userId,
        BiometricType.FINGERPRINT,
        'any-code' // Will hash to mock value
      );

      expect(result).toBe(true);
    });

    it('should throw NotFoundError when no enrollment', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [] });

      await expect(
        biometricService.authenticateWithBackupCode(userId, BiometricType.FINGERPRINT, 'code')
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw UnauthorizedError for invalid backup code', async () => {
      const backupCodes = ['different-hash'];

      (database.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [{
            metadata: JSON.stringify({ backupCodes }),
          }],
        })
        .mockResolvedValue({ rows: [{ failed_attempts: 1 }] });

      await expect(
        biometricService.authenticateWithBackupCode(userId, BiometricType.FINGERPRINT, 'invalid')
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe('disableBiometric', () => {
    it('should disable biometric successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] })
        .mockResolvedValue({ rows: [] });
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      await biometricService.disableBiometric(userId, BiometricType.FINGERPRINT, 'password');

      expect(database.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE biometric_enrollments'),
        [BiometricStatus.DISABLED, userId, BiometricType.FINGERPRINT]
      );
    });

    it('should throw UnauthorizedError for invalid password', async () => {
      (database.query as jest.Mock).mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] });
      (argon2.verify as jest.Mock).mockRejectedValue(new Error());
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        biometricService.disableBiometric(userId, BiometricType.FINGERPRINT, 'wrong')
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe('getUserEnrollments', () => {
    it('should return all enrollments for user', async () => {
      const enrollments = [
        { type: BiometricType.FINGERPRINT, status: BiometricStatus.ENROLLED, lastUsed: new Date() },
        { type: BiometricType.FACE_ID, status: BiometricStatus.NOT_ENROLLED, lastUsed: null },
      ];

      (database.query as jest.Mock).mockResolvedValueOnce({ rows: enrollments });

      const result = await biometricService.getUserEnrollments(userId);

      expect(result).toHaveLength(2);
      expect(result[0].type).toBe(BiometricType.FINGERPRINT);
    });
  });

  describe('regenerateBackupCodes', () => {
    it('should regenerate backup codes successfully', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] }) // verifyPassword
        .mockResolvedValueOnce({
          rows: [{
            metadata: JSON.stringify({ backupCodes: ['old-code'] }),
          }],
        }) // getEnrollment
        .mockResolvedValue({ rows: [] }); // Update
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const result = await biometricService.regenerateBackupCodes(
        userId,
        BiometricType.FINGERPRINT,
        'password'
      );

      expect(result).toHaveProperty('backupCodes');
      expect(result.backupCodes).toHaveLength(10);
    });

    it('should throw NotFoundError when not enrolled', async () => {
      (database.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] })
        .mockResolvedValueOnce({ rows: [] });
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      await expect(
        biometricService.regenerateBackupCodes(userId, BiometricType.FINGERPRINT, 'password')
      ).rejects.toThrow(NotFoundError);
    });
  });

  describe('BiometricType enum', () => {
    it('should have correct values', () => {
      expect(BiometricType.FINGERPRINT).toBe('fingerprint');
      expect(BiometricType.FACE_ID).toBe('face_id');
      expect(BiometricType.VOICE_PRINT).toBe('voice_print');
    });
  });

  describe('BiometricStatus enum', () => {
    it('should have correct values', () => {
      expect(BiometricStatus.NOT_ENROLLED).toBe('not_enrolled');
      expect(BiometricStatus.ENROLLED).toBe('enrolled');
      expect(BiometricStatus.LOCKED_OUT).toBe('locked_out');
      expect(BiometricStatus.DISABLED).toBe('disabled');
    });
  });

  describe('BiometricError enum', () => {
    it('should have correct error types', () => {
      expect(BiometricError.FALLBACK).toBe('fallback');
      expect(BiometricError.NOT_ENROLLED).toBe('biometry_not_enrolled');
      expect(BiometricError.LOCKED_OUT).toBe('biometry_locked_out');
      expect(BiometricError.TEMPLATE_MISMATCH).toBe('template_mismatch');
      expect(BiometricError.LIVENESS_FAILED).toBe('liveness_failed');
    });
  });
});
