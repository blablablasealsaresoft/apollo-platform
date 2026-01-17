import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import crypto from 'crypto';
import { database, redis, logger, generateId, UnauthorizedError, NotFoundError, BadRequestError } from '@apollo/shared';
import { biometricService, BiometricType, BiometricStatus } from './biometric.service';

// MFA factor types
export enum MfaFactorType {
  TOTP = 'totp',
  SMS = 'sms',
  EMAIL = 'email',
  FINGERPRINT = 'fingerprint',
  FACE_ID = 'face_id',
  VOICE_PRINT = 'voice_print',
  HARDWARE_KEY = 'hardware_key',
  BACKUP_CODE = 'backup_code',
}

// MFA verification status
export interface MfaVerificationStatus {
  verified: boolean;
  factorType: MfaFactorType;
  timestamp: Date;
  confidence?: number;
}

// MFA requirements based on clearance level
export const MFA_REQUIREMENTS: Record<string, { minFactors: number; requiredTypes?: MfaFactorType[] }> = {
  UNCLASSIFIED: { minFactors: 1 },
  RESTRICTED: { minFactors: 1 },
  CONFIDENTIAL: { minFactors: 2 },
  SECRET: { minFactors: 2, requiredTypes: [MfaFactorType.TOTP] },
  TOP_SECRET: { minFactors: 2, requiredTypes: [MfaFactorType.TOTP, MfaFactorType.FINGERPRINT] },
};

export class MfaService {
  private readonly MFA_CHALLENGE_TTL = 300; // 5 minutes
  async setupMfa(userId: string): Promise<{ secret: string; qrCodeUrl: string }> {
    // Check if user exists
    const userResult = await database.query(
      'SELECT email FROM users WHERE id = $1',
      [userId],
    );

    if (userResult.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    const { email } = userResult.rows[0]!;

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Apollo Platform (${email})`,
      issuer: 'Apollo Platform',
      length: 32,
    });

    // Store temporary secret in Redis (expires in 10 minutes)
    await redis.set(`mfa:setup:${userId}`, secret.base32, 600);

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url!);

    logger.info(`MFA setup initiated for user: ${userId}`);

    return {
      secret: secret.base32,
      qrCodeUrl,
    };
  }

  async enableMfa(userId: string, token: string): Promise<{ backupCodes: string[] }> {
    // Get temporary secret from Redis
    const secret = await redis.get(`mfa:setup:${userId}`);

    if (!secret) {
      throw new UnauthorizedError('MFA setup session expired');
    }

    // Verify token
    const isValid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!isValid) {
      throw new UnauthorizedError('Invalid MFA token');
    }

    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      speakeasy.generateSecret({ length: 20 }).base32.substring(0, 8),
    );

    // Store secret and backup codes in database
    await database.query(
      `UPDATE users
       SET mfa_secret = $1, mfa_backup_codes = $2, is_mfa_enabled = true
       WHERE id = $3`,
      [secret, JSON.stringify(backupCodes), userId],
    );

    // Remove temporary secret
    await redis.del(`mfa:setup:${userId}`);

    // Log activity
    await this.logActivity(userId, 'MFA_ENABLED');

    logger.info(`MFA enabled for user: ${userId}`);

    return { backupCodes };
  }

  async verifyMfa(userId: string, token: string): Promise<boolean> {
    // Get user's MFA secret
    const result = await database.query(
      'SELECT mfa_secret, mfa_backup_codes FROM users WHERE id = $1 AND is_mfa_enabled = true',
      [userId],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found or MFA not enabled');
    }

    const { mfa_secret, mfa_backup_codes } = result.rows[0]!;

    // Verify TOTP token
    const isValid = speakeasy.totp.verify({
      secret: mfa_secret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (isValid) {
      await this.logActivity(userId, 'MFA_VERIFIED');
      return true;
    }

    // Check backup codes if TOTP failed
    const backupCodes: string[] = JSON.parse(mfa_backup_codes || '[]');
    const codeIndex = backupCodes.indexOf(token);

    if (codeIndex !== -1) {
      // Remove used backup code
      backupCodes.splice(codeIndex, 1);
      await database.query(
        'UPDATE users SET mfa_backup_codes = $1 WHERE id = $2',
        [JSON.stringify(backupCodes), userId],
      );

      await this.logActivity(userId, 'MFA_BACKUP_CODE_USED');
      logger.info(`Backup code used for user: ${userId}`);
      return true;
    }

    throw new UnauthorizedError('Invalid MFA token');
  }

  async disableMfa(userId: string, password: string): Promise<void> {
    // Verify password
    const result = await database.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    const bcrypt = await import('bcrypt');
    const isValid = await bcrypt.compare(password, result.rows[0]!.password_hash);

    if (!isValid) {
      throw new UnauthorizedError('Invalid password');
    }

    // Disable MFA
    await database.query(
      `UPDATE users
       SET is_mfa_enabled = false, mfa_secret = NULL, mfa_backup_codes = NULL
       WHERE id = $1`,
      [userId],
    );

    // Log activity
    await this.logActivity(userId, 'MFA_DISABLED');

    logger.info(`MFA disabled for user: ${userId}`);
  }

  async regenerateBackupCodes(userId: string, password: string): Promise<{ backupCodes: string[] }> {
    // Verify password
    const result = await database.query(
      'SELECT password_hash FROM users WHERE id = $1 AND is_mfa_enabled = true',
      [userId],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found or MFA not enabled');
    }

    const bcrypt = await import('bcrypt');
    const isValid = await bcrypt.compare(password, result.rows[0]!.password_hash);

    if (!isValid) {
      throw new UnauthorizedError('Invalid password');
    }

    // Generate new backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      speakeasy.generateSecret({ length: 20 }).base32.substring(0, 8),
    );

    // Update backup codes
    await database.query(
      'UPDATE users SET mfa_backup_codes = $1 WHERE id = $2',
      [JSON.stringify(backupCodes), userId],
    );

    // Log activity
    await this.logActivity(userId, 'MFA_BACKUP_CODES_REGENERATED');

    logger.info(`Backup codes regenerated for user: ${userId}`);

    return { backupCodes };
  }

  private async logActivity(userId: string, action: string, metadata?: Record<string, any>): Promise<void> {
    try {
      await database.query(
        `INSERT INTO activity_logs (id, user_id, action, resource_type, resource_id, metadata, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
        [generateId(), userId, action, 'mfa', userId, metadata ? JSON.stringify(metadata) : null],
      );
    } catch (error) {
      logger.error(`Failed to log MFA activity: ${error}`);
    }
  }

  /**
   * Get available MFA factors for a user
   */
  async getAvailableMfaFactors(userId: string): Promise<Array<{
    type: MfaFactorType;
    enabled: boolean;
    lastUsed?: Date;
  }>> {
    const factors: Array<{ type: MfaFactorType; enabled: boolean; lastUsed?: Date }> = [];

    // Check TOTP
    const totpResult = await database.query(
      'SELECT is_mfa_enabled FROM users WHERE id = $1',
      [userId],
    );

    if (totpResult.rows.length > 0) {
      factors.push({
        type: MfaFactorType.TOTP,
        enabled: totpResult.rows[0]!.is_mfa_enabled || false,
      });
    }

    // Check biometric factors
    const biometricEnrollments = await biometricService.getUserEnrollments(userId);

    for (const enrollment of biometricEnrollments) {
      let factorType: MfaFactorType;
      switch (enrollment.type) {
        case BiometricType.FINGERPRINT:
          factorType = MfaFactorType.FINGERPRINT;
          break;
        case BiometricType.FACE_ID:
          factorType = MfaFactorType.FACE_ID;
          break;
        case BiometricType.VOICE_PRINT:
          factorType = MfaFactorType.VOICE_PRINT;
          break;
        default:
          continue;
      }

      factors.push({
        type: factorType,
        enabled: enrollment.status === BiometricStatus.ENROLLED,
        lastUsed: enrollment.lastUsed || undefined,
      });
    }

    // Add SMS and Email as potential factors (check if configured)
    const userResult = await database.query(
      'SELECT phone_number, email_verified FROM users WHERE id = $1',
      [userId],
    );

    if (userResult.rows.length > 0) {
      const user = userResult.rows[0]!;

      factors.push({
        type: MfaFactorType.SMS,
        enabled: !!user.phone_number,
      });

      factors.push({
        type: MfaFactorType.EMAIL,
        enabled: user.email_verified || false,
      });
    }

    return factors;
  }

  /**
   * Start MFA challenge for multi-factor verification
   */
  async startMfaChallenge(userId: string, factorTypes: MfaFactorType[]): Promise<{
    challengeId: string;
    requiredFactors: MfaFactorType[];
    expiresAt: Date;
  }> {
    const challengeId = generateId();
    const expiresAt = new Date(Date.now() + this.MFA_CHALLENGE_TTL * 1000);

    await redis.set(
      `mfa:challenge:${challengeId}`,
      JSON.stringify({
        userId,
        requiredFactors: factorTypes,
        verifiedFactors: [],
        createdAt: new Date().toISOString(),
      }),
      this.MFA_CHALLENGE_TTL,
    );

    logger.info(`MFA challenge started for user: ${userId}, factors: ${factorTypes.join(', ')}`);

    return {
      challengeId,
      requiredFactors: factorTypes,
      expiresAt,
    };
  }

  /**
   * Verify a factor in an MFA challenge
   */
  async verifyMfaChallengeFactor(
    challengeId: string,
    factorType: MfaFactorType,
    verificationData: {
      token?: string;
      biometricTemplate?: string;
      livenessProof?: string;
    },
  ): Promise<{
    factorVerified: boolean;
    challengeComplete: boolean;
    remainingFactors: MfaFactorType[];
  }> {
    // Get challenge data
    const challengeData = await redis.get(`mfa:challenge:${challengeId}`);
    if (!challengeData) {
      throw new UnauthorizedError('MFA challenge expired or not found');
    }

    const challenge = JSON.parse(challengeData);
    const { userId, requiredFactors, verifiedFactors } = challenge;

    // Check if factor is required
    if (!requiredFactors.includes(factorType)) {
      throw new BadRequestError(`Factor type ${factorType} is not required for this challenge`);
    }

    // Check if already verified
    if (verifiedFactors.includes(factorType)) {
      throw new BadRequestError(`Factor type ${factorType} is already verified`);
    }

    // Verify the factor
    let verified = false;

    switch (factorType) {
      case MfaFactorType.TOTP:
        if (!verificationData.token) {
          throw new BadRequestError('TOTP token is required');
        }
        verified = await this.verifyMfa(userId, verificationData.token);
        break;

      case MfaFactorType.FINGERPRINT:
      case MfaFactorType.FACE_ID:
      case MfaFactorType.VOICE_PRINT:
        if (!verificationData.biometricTemplate) {
          throw new BadRequestError('Biometric template is required');
        }
        const biometricType = this.factorTypeToBiometric(factorType);
        const biometricResult = await biometricService.authenticateWithBiometric(
          userId,
          biometricType,
          verificationData.biometricTemplate,
          verificationData.livenessProof,
        );
        verified = biometricResult.success;
        break;

      case MfaFactorType.SMS:
      case MfaFactorType.EMAIL:
        if (!verificationData.token) {
          throw new BadRequestError('Verification code is required');
        }
        verified = await this.verifyOtpCode(userId, factorType, verificationData.token);
        break;

      case MfaFactorType.BACKUP_CODE:
        if (!verificationData.token) {
          throw new BadRequestError('Backup code is required');
        }
        verified = await this.verifyBackupCode(userId, verificationData.token);
        break;

      default:
        throw new BadRequestError(`Unsupported factor type: ${factorType}`);
    }

    if (!verified) {
      throw new UnauthorizedError('Factor verification failed');
    }

    // Update challenge
    verifiedFactors.push(factorType);
    const remainingFactors = requiredFactors.filter(
      (f: MfaFactorType) => !verifiedFactors.includes(f),
    );
    const challengeComplete = remainingFactors.length === 0;

    if (challengeComplete) {
      // Remove challenge on completion
      await redis.del(`mfa:challenge:${challengeId}`);

      // Log successful multi-factor authentication
      await this.logActivity(userId, 'MFA_CHALLENGE_COMPLETED', {
        challengeId,
        factors: verifiedFactors,
      });
    } else {
      // Update challenge with verified factor
      await redis.set(
        `mfa:challenge:${challengeId}`,
        JSON.stringify({ ...challenge, verifiedFactors }),
        this.MFA_CHALLENGE_TTL,
      );
    }

    return {
      factorVerified: true,
      challengeComplete,
      remainingFactors,
    };
  }

  /**
   * Send OTP code via SMS or Email
   */
  async sendOtpCode(userId: string, method: MfaFactorType.SMS | MfaFactorType.EMAIL): Promise<void> {
    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');

    // Store code with expiration
    await redis.set(
      `mfa:otp:${userId}:${method}`,
      codeHash,
      300, // 5 minutes
    );

    // Get user contact info
    const userResult = await database.query(
      'SELECT email, phone_number FROM users WHERE id = $1',
      [userId],
    );

    if (userResult.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    const user = userResult.rows[0]!;

    if (method === MfaFactorType.SMS) {
      if (!user.phone_number) {
        throw new BadRequestError('Phone number not configured');
      }
      // In production: Send SMS via Twilio, AWS SNS, etc.
      logger.info(`[DEV] SMS code for ${user.phone_number}: ${code}`);
    } else if (method === MfaFactorType.EMAIL) {
      // In production: Send email via SendGrid, AWS SES, etc.
      logger.info(`[DEV] Email code for ${user.email}: ${code}`);
    }

    await this.logActivity(userId, 'OTP_CODE_SENT', { method });
  }

  /**
   * Verify OTP code sent via SMS or Email
   */
  private async verifyOtpCode(
    userId: string,
    method: MfaFactorType.SMS | MfaFactorType.EMAIL,
    code: string,
  ): Promise<boolean> {
    const storedHash = await redis.get(`mfa:otp:${userId}:${method}`);
    if (!storedHash) {
      return false;
    }

    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    if (codeHash !== storedHash) {
      return false;
    }

    // Remove used code
    await redis.del(`mfa:otp:${userId}:${method}`);
    return true;
  }

  /**
   * Verify backup code
   */
  private async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    // Try TOTP backup codes first
    try {
      await this.verifyMfa(userId, code);
      return true;
    } catch {
      // Try biometric backup codes
      const enrollments = await biometricService.getUserEnrollments(userId);
      for (const enrollment of enrollments) {
        try {
          const verified = await biometricService.authenticateWithBackupCode(
            userId,
            enrollment.type as BiometricType,
            code,
          );
          if (verified) return true;
        } catch {
          continue;
        }
      }
    }
    return false;
  }

  /**
   * Convert MFA factor type to biometric type
   */
  private factorTypeToBiometric(factorType: MfaFactorType): BiometricType {
    switch (factorType) {
      case MfaFactorType.FINGERPRINT:
        return BiometricType.FINGERPRINT;
      case MfaFactorType.FACE_ID:
        return BiometricType.FACE_ID;
      case MfaFactorType.VOICE_PRINT:
        return BiometricType.VOICE_PRINT;
      default:
        throw new BadRequestError('Invalid biometric factor type');
    }
  }

  /**
   * Check if user meets MFA requirements for clearance level
   */
  async checkMfaRequirements(userId: string, clearanceLevel: string): Promise<{
    meetsRequirements: boolean;
    requiredFactors: number;
    enabledFactors: MfaFactorType[];
    missingRequiredTypes?: MfaFactorType[];
  }> {
    const requirements = MFA_REQUIREMENTS[clearanceLevel] || { minFactors: 1 };
    const availableFactors = await this.getAvailableMfaFactors(userId);
    const enabledFactors = availableFactors
      .filter(f => f.enabled)
      .map(f => f.type);

    let meetsRequirements = enabledFactors.length >= requirements.minFactors;
    let missingRequiredTypes: MfaFactorType[] | undefined;

    if (requirements.requiredTypes) {
      const missing = requirements.requiredTypes.filter(
        required => !enabledFactors.includes(required),
      );
      if (missing.length > 0) {
        meetsRequirements = false;
        missingRequiredTypes = missing;
      }
    }

    return {
      meetsRequirements,
      requiredFactors: requirements.minFactors,
      enabledFactors,
      missingRequiredTypes,
    };
  }
}

export const mfaService = new MfaService();
