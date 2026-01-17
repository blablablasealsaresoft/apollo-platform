/**
 * Biometric Authentication Service
 * Implements fingerprint, facial recognition, and voice print authentication
 * Based on BiometricAuthentication library patterns adapted for server-side validation
 */

import crypto from 'crypto';
import {
  database,
  redis,
  logger,
  generateId,
  UnauthorizedError,
  NotFoundError,
  BadRequestError,
} from '@apollo/shared';

// Biometric types supported
export enum BiometricType {
  FINGERPRINT = 'fingerprint',
  FACE_ID = 'face_id',
  VOICE_PRINT = 'voice_print',
}

// Biometric authentication status
export enum BiometricStatus {
  NOT_ENROLLED = 'not_enrolled',
  ENROLLED = 'enrolled',
  LOCKED_OUT = 'locked_out',
  DISABLED = 'disabled',
}

// Biometric error types (matching BiometricAuthentication library patterns)
export enum BiometricError {
  FALLBACK = 'fallback',
  NOT_ENROLLED = 'biometry_not_enrolled',
  CANCELED_BY_USER = 'canceled_by_user',
  CANCELED_BY_SYSTEM = 'canceled_by_system',
  PASSCODE_NOT_SET = 'passcode_not_set',
  FAILED = 'failed',
  LOCKED_OUT = 'biometry_locked_out',
  NOT_AVAILABLE = 'biometry_not_available',
  TEMPLATE_MISMATCH = 'template_mismatch',
  LIVENESS_FAILED = 'liveness_failed',
}

// Biometric enrollment data
interface BiometricEnrollment {
  id: string;
  userId: string;
  type: BiometricType;
  templateHash: string;
  encryptedTemplate: string;
  status: BiometricStatus;
  failedAttempts: number;
  lastUsed: Date | null;
  createdAt: Date;
  updatedAt: Date;
  deviceId?: string;
  metadata?: Record<string, any>;
}

// Biometric verification result
interface BiometricVerificationResult {
  success: boolean;
  biometricType: BiometricType;
  confidence: number;
  error?: BiometricError;
  livenessScore?: number;
}

// Biometric template data (encrypted)
interface BiometricTemplate {
  type: BiometricType;
  data: string;
  deviceId?: string;
  capturedAt: Date;
  qualityScore: number;
}

export class BiometricService {
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes
  private readonly TEMPLATE_ENCRYPTION_KEY: string;
  private readonly MIN_CONFIDENCE_THRESHOLD = 0.85;
  private readonly MIN_LIVENESS_THRESHOLD = 0.90;

  constructor() {
    // Use environment variable or generate a secure key
    this.TEMPLATE_ENCRYPTION_KEY = process.env.BIOMETRIC_ENCRYPTION_KEY ||
      crypto.createHash('sha256').update(process.env.JWT_SECRET || 'apollo-biometric-key').digest('hex');
  }

  /**
   * Check if user can authenticate with biometrics
   */
  async canAuthenticate(userId: string, type: BiometricType): Promise<{
    available: boolean;
    enrolled: boolean;
    status: BiometricStatus;
    error?: BiometricError;
  }> {
    const enrollment = await this.getEnrollment(userId, type);

    if (!enrollment) {
      return {
        available: true,
        enrolled: false,
        status: BiometricStatus.NOT_ENROLLED,
        error: BiometricError.NOT_ENROLLED,
      };
    }

    if (enrollment.status === BiometricStatus.LOCKED_OUT) {
      // Check if lockout has expired
      const lockoutExpiry = new Date(enrollment.updatedAt.getTime() + this.LOCKOUT_DURATION);
      if (new Date() < lockoutExpiry) {
        return {
          available: false,
          enrolled: true,
          status: BiometricStatus.LOCKED_OUT,
          error: BiometricError.LOCKED_OUT,
        };
      }
      // Reset lockout
      await this.resetLockout(userId, type);
    }

    if (enrollment.status === BiometricStatus.DISABLED) {
      return {
        available: false,
        enrolled: true,
        status: BiometricStatus.DISABLED,
        error: BiometricError.NOT_AVAILABLE,
      };
    }

    return {
      available: true,
      enrolled: true,
      status: enrollment.status,
    };
  }

  /**
   * Enroll a biometric template for a user
   */
  async enrollBiometric(
    userId: string,
    type: BiometricType,
    template: BiometricTemplate,
    password: string, // Required for enrollment verification
  ): Promise<{ enrollmentId: string; backupCodes: string[] }> {
    // Verify user password before enrollment
    await this.verifyUserPassword(userId, password);

    // Check for existing enrollment
    const existingEnrollment = await this.getEnrollment(userId, type);
    if (existingEnrollment && existingEnrollment.status === BiometricStatus.ENROLLED) {
      throw new BadRequestError(`${type} is already enrolled. Disable first to re-enroll.`);
    }

    // Validate template quality
    if (template.qualityScore < 0.7) {
      throw new BadRequestError('Biometric template quality is too low. Please try again.');
    }

    // Encrypt and hash the template
    const encryptedTemplate = this.encryptTemplate(template.data);
    const templateHash = this.hashTemplate(template.data);

    const enrollmentId = generateId();
    const backupCodes = this.generateBackupCodes();

    // Store enrollment in database
    await database.query(
      `INSERT INTO biometric_enrollments (
        id, user_id, biometric_type, template_hash, encrypted_template,
        status, failed_attempts, device_id, metadata, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
      ON CONFLICT (user_id, biometric_type) DO UPDATE SET
        template_hash = EXCLUDED.template_hash,
        encrypted_template = EXCLUDED.encrypted_template,
        status = EXCLUDED.status,
        failed_attempts = 0,
        device_id = EXCLUDED.device_id,
        metadata = EXCLUDED.metadata,
        updated_at = NOW()`,
      [
        enrollmentId,
        userId,
        type,
        templateHash,
        encryptedTemplate,
        BiometricStatus.ENROLLED,
        0,
        template.deviceId || null,
        JSON.stringify({
          qualityScore: template.qualityScore,
          capturedAt: template.capturedAt,
          backupCodes: backupCodes.map(code => this.hashTemplate(code)),
        }),
      ],
    );

    // Update user's biometric status
    await database.query(
      `UPDATE users SET
        biometric_enabled = true,
        biometric_types = array_append(
          COALESCE(biometric_types, ARRAY[]::text[]),
          $1
        )
      WHERE id = $2`,
      [type, userId],
    );

    await this.logActivity(userId, 'BIOMETRIC_ENROLLED', { type, deviceId: template.deviceId });

    logger.info(`Biometric enrolled for user: ${userId}, type: ${type}`);

    return { enrollmentId, backupCodes };
  }

  /**
   * Authenticate with biometric data
   */
  async authenticateWithBiometric(
    userId: string,
    type: BiometricType,
    templateData: string,
    livenessProof?: string,
  ): Promise<BiometricVerificationResult> {
    // Check if authentication is available
    const availability = await this.canAuthenticate(userId, type);
    if (!availability.available) {
      return {
        success: false,
        biometricType: type,
        confidence: 0,
        error: availability.error,
      };
    }

    const enrollment = await this.getEnrollment(userId, type);
    if (!enrollment) {
      return {
        success: false,
        biometricType: type,
        confidence: 0,
        error: BiometricError.NOT_ENROLLED,
      };
    }

    // Verify liveness (anti-spoofing)
    let livenessScore = 1.0;
    if (livenessProof) {
      livenessScore = await this.verifyLiveness(type, livenessProof);
      if (livenessScore < this.MIN_LIVENESS_THRESHOLD) {
        await this.incrementFailedAttempts(userId, type);
        return {
          success: false,
          biometricType: type,
          confidence: 0,
          livenessScore,
          error: BiometricError.LIVENESS_FAILED,
        };
      }
    }

    // Compare templates
    const storedTemplate = this.decryptTemplate(enrollment.encryptedTemplate);
    const confidence = await this.compareTemplates(type, templateData, storedTemplate);

    if (confidence < this.MIN_CONFIDENCE_THRESHOLD) {
      const newAttempts = await this.incrementFailedAttempts(userId, type);

      if (newAttempts >= this.MAX_FAILED_ATTEMPTS) {
        await this.lockout(userId, type);
        return {
          success: false,
          biometricType: type,
          confidence,
          livenessScore,
          error: BiometricError.LOCKED_OUT,
        };
      }

      return {
        success: false,
        biometricType: type,
        confidence,
        livenessScore,
        error: BiometricError.TEMPLATE_MISMATCH,
      };
    }

    // Success - reset failed attempts and update last used
    await database.query(
      `UPDATE biometric_enrollments
       SET failed_attempts = 0, last_used = NOW(), updated_at = NOW()
       WHERE user_id = $1 AND biometric_type = $2`,
      [userId, type],
    );

    await this.logActivity(userId, 'BIOMETRIC_AUTH_SUCCESS', { type, confidence });

    return {
      success: true,
      biometricType: type,
      confidence,
      livenessScore,
    };
  }

  /**
   * Authenticate with biometric backup code (fallback)
   */
  async authenticateWithBackupCode(
    userId: string,
    type: BiometricType,
    backupCode: string,
  ): Promise<boolean> {
    const enrollment = await this.getEnrollment(userId, type);
    if (!enrollment || !enrollment.metadata) {
      throw new NotFoundError('Biometric enrollment not found');
    }

    const metadata = typeof enrollment.metadata === 'string'
      ? JSON.parse(enrollment.metadata)
      : enrollment.metadata;

    const backupCodes: string[] = metadata.backupCodes || [];
    const codeHash = this.hashTemplate(backupCode);
    const codeIndex = backupCodes.indexOf(codeHash);

    if (codeIndex === -1) {
      await this.incrementFailedAttempts(userId, type);
      throw new UnauthorizedError('Invalid backup code');
    }

    // Remove used backup code
    backupCodes.splice(codeIndex, 1);
    metadata.backupCodes = backupCodes;

    await database.query(
      `UPDATE biometric_enrollments
       SET metadata = $1, updated_at = NOW()
       WHERE user_id = $2 AND biometric_type = $3`,
      [JSON.stringify(metadata), userId, type],
    );

    await this.logActivity(userId, 'BIOMETRIC_BACKUP_CODE_USED', { type });
    logger.info(`Biometric backup code used for user: ${userId}, type: ${type}`);

    return true;
  }

  /**
   * Disable biometric authentication
   */
  async disableBiometric(userId: string, type: BiometricType, password: string): Promise<void> {
    await this.verifyUserPassword(userId, password);

    await database.query(
      `UPDATE biometric_enrollments
       SET status = $1, updated_at = NOW()
       WHERE user_id = $2 AND biometric_type = $3`,
      [BiometricStatus.DISABLED, userId, type],
    );

    await database.query(
      `UPDATE users SET
        biometric_types = array_remove(biometric_types, $1),
        biometric_enabled = (
          SELECT COUNT(*) > 0 FROM biometric_enrollments
          WHERE user_id = $2 AND status = 'enrolled'
        )
      WHERE id = $2`,
      [type, userId],
    );

    await this.logActivity(userId, 'BIOMETRIC_DISABLED', { type });
    logger.info(`Biometric disabled for user: ${userId}, type: ${type}`);
  }

  /**
   * Get all biometric enrollments for a user
   */
  async getUserEnrollments(userId: string): Promise<Array<{
    type: BiometricType;
    status: BiometricStatus;
    lastUsed: Date | null;
    deviceId?: string;
  }>> {
    const result = await database.query(
      `SELECT biometric_type as type, status, last_used as "lastUsed", device_id as "deviceId"
       FROM biometric_enrollments
       WHERE user_id = $1`,
      [userId],
    );

    return result.rows as any;
  }

  /**
   * Generate new backup codes for biometric enrollment
   */
  async regenerateBackupCodes(
    userId: string,
    type: BiometricType,
    password: string,
  ): Promise<{ backupCodes: string[] }> {
    await this.verifyUserPassword(userId, password);

    const enrollment = await this.getEnrollment(userId, type);
    if (!enrollment) {
      throw new NotFoundError('Biometric enrollment not found');
    }

    const backupCodes = this.generateBackupCodes();
    const metadata = typeof enrollment.metadata === 'string'
      ? JSON.parse(enrollment.metadata)
      : enrollment.metadata || {};

    metadata.backupCodes = backupCodes.map(code => this.hashTemplate(code));

    await database.query(
      `UPDATE biometric_enrollments
       SET metadata = $1, updated_at = NOW()
       WHERE user_id = $2 AND biometric_type = $3`,
      [JSON.stringify(metadata), userId, type],
    );

    await this.logActivity(userId, 'BIOMETRIC_BACKUP_CODES_REGENERATED', { type });

    return { backupCodes };
  }

  // ============= Private Helper Methods =============

  private async getEnrollment(userId: string, type: BiometricType): Promise<BiometricEnrollment | null> {
    const result = await database.query<BiometricEnrollment>(
      `SELECT
        id, user_id as "userId", biometric_type as type,
        template_hash as "templateHash", encrypted_template as "encryptedTemplate",
        status, failed_attempts as "failedAttempts",
        last_used as "lastUsed", created_at as "createdAt", updated_at as "updatedAt",
        device_id as "deviceId", metadata
       FROM biometric_enrollments
       WHERE user_id = $1 AND biometric_type = $2`,
      [userId, type],
    );

    return result.rows[0] || null;
  }

  private async verifyUserPassword(userId: string, password: string): Promise<void> {
    const result = await database.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    // Use argon2 if available, fallback to bcrypt
    let isValid = false;
    const { password_hash } = result.rows[0]!;

    try {
      const argon2 = await import('argon2');
      isValid = await argon2.verify(password_hash, password);
    } catch {
      const bcrypt = await import('bcrypt');
      isValid = await bcrypt.compare(password, password_hash);
    }

    if (!isValid) {
      throw new UnauthorizedError('Invalid password');
    }
  }

  private encryptTemplate(template: string): string {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(this.TEMPLATE_ENCRYPTION_KEY, 'hex').slice(0, 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(template, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  private decryptTemplate(encryptedData: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = Buffer.from(this.TEMPLATE_ENCRYPTION_KEY, 'hex').slice(0, 32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  private hashTemplate(template: string): string {
    return crypto.createHash('sha256').update(template).digest('hex');
  }

  private generateBackupCodes(): string[] {
    return Array.from({ length: 10 }, () => {
      return crypto.randomBytes(4).toString('hex').toUpperCase();
    });
  }

  private async compareTemplates(
    type: BiometricType,
    submittedTemplate: string,
    storedTemplate: string,
  ): Promise<number> {
    // In production, this would use actual biometric comparison algorithms
    // For fingerprint: minutiae-based matching
    // For face: deep learning embeddings comparison
    // For voice: speaker verification model

    switch (type) {
      case BiometricType.FINGERPRINT:
        return this.compareFingerprintTemplates(submittedTemplate, storedTemplate);
      case BiometricType.FACE_ID:
        return this.compareFaceTemplates(submittedTemplate, storedTemplate);
      case BiometricType.VOICE_PRINT:
        return this.compareVoicePrintTemplates(submittedTemplate, storedTemplate);
      default:
        return 0;
    }
  }

  private async compareFingerprintTemplates(submitted: string, stored: string): Promise<number> {
    // Fingerprint matching using minutiae comparison
    // In production: Use NIST Biometric Image Software (NBIS) or similar
    const submittedHash = this.hashTemplate(submitted);
    const storedHash = this.hashTemplate(stored);

    if (submittedHash === storedHash) {
      return 1.0;
    }

    // Simulate fuzzy matching for demonstration
    // Real implementation would extract minutiae points and compare
    const similarity = this.calculateSimilarity(submitted, stored);
    return similarity;
  }

  private async compareFaceTemplates(submitted: string, stored: string): Promise<number> {
    // Face recognition using embedding comparison
    // In production: Use FaceNet, ArcFace, or similar deep learning models
    const submittedHash = this.hashTemplate(submitted);
    const storedHash = this.hashTemplate(stored);

    if (submittedHash === storedHash) {
      return 1.0;
    }

    // Simulate cosine similarity for face embeddings
    const similarity = this.calculateSimilarity(submitted, stored);
    return similarity;
  }

  private async compareVoicePrintTemplates(submitted: string, stored: string): Promise<number> {
    // Voice print comparison using speaker verification
    // In production: Use i-vector or x-vector based speaker verification
    const submittedHash = this.hashTemplate(submitted);
    const storedHash = this.hashTemplate(stored);

    if (submittedHash === storedHash) {
      return 1.0;
    }

    // Simulate speaker verification score
    const similarity = this.calculateSimilarity(submitted, stored);
    return similarity;
  }

  private calculateSimilarity(str1: string, str2: string): number {
    // Simple similarity calculation for demonstration
    // In production, use actual biometric matching algorithms
    if (str1 === str2) return 1.0;

    const len1 = str1.length;
    const len2 = str2.length;
    const maxLen = Math.max(len1, len2);

    if (maxLen === 0) return 1.0;

    let matches = 0;
    const minLen = Math.min(len1, len2);

    for (let i = 0; i < minLen; i++) {
      if (str1[i] === str2[i]) matches++;
    }

    return matches / maxLen;
  }

  private async verifyLiveness(type: BiometricType, livenessProof: string): Promise<number> {
    // Liveness detection to prevent spoofing attacks
    // In production: Use 3D depth detection, challenge-response, or motion analysis

    try {
      const proofData = JSON.parse(livenessProof);

      switch (type) {
        case BiometricType.FINGERPRINT:
          // Capacitive vs optical sensor validation
          return proofData.sensorType === 'capacitive' ? 0.95 : 0.85;

        case BiometricType.FACE_ID:
          // 3D depth map, eye tracking, head movement
          const depthScore = proofData.hasDepthMap ? 0.4 : 0;
          const eyeScore = proofData.eyeTracking ? 0.3 : 0;
          const motionScore = proofData.headMotion ? 0.3 : 0;
          return depthScore + eyeScore + motionScore;

        case BiometricType.VOICE_PRINT:
          // Audio analysis for replay attack detection
          return proofData.isLiveAudio ? 0.95 : 0.5;

        default:
          return 0.5;
      }
    } catch {
      return 0.5;
    }
  }

  private async incrementFailedAttempts(userId: string, type: BiometricType): Promise<number> {
    const result = await database.query(
      `UPDATE biometric_enrollments
       SET failed_attempts = failed_attempts + 1, updated_at = NOW()
       WHERE user_id = $1 AND biometric_type = $2
       RETURNING failed_attempts`,
      [userId, type],
    );

    return result.rows[0]?.failed_attempts || 0;
  }

  private async lockout(userId: string, type: BiometricType): Promise<void> {
    await database.query(
      `UPDATE biometric_enrollments
       SET status = $1, updated_at = NOW()
       WHERE user_id = $2 AND biometric_type = $3`,
      [BiometricStatus.LOCKED_OUT, userId, type],
    );

    await this.logActivity(userId, 'BIOMETRIC_LOCKED_OUT', { type });
    logger.warn(`Biometric locked out for user: ${userId}, type: ${type}`);
  }

  private async resetLockout(userId: string, type: BiometricType): Promise<void> {
    await database.query(
      `UPDATE biometric_enrollments
       SET status = $1, failed_attempts = 0, updated_at = NOW()
       WHERE user_id = $2 AND biometric_type = $3`,
      [BiometricStatus.ENROLLED, userId, type],
    );
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
        [generateId(), userId, action, 'biometric', userId, metadata ? JSON.stringify(metadata) : null],
      );
    } catch (error) {
      logger.error(`Failed to log biometric activity: ${error}`);
    }
  }
}

export const biometricService = new BiometricService();
