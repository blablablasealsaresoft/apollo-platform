import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { database, redis, logger, generateId, UnauthorizedError, NotFoundError } from '@apollo/shared';

export class MfaService {
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

  private async logActivity(userId: string, action: string): Promise<void> {
    try {
      await database.query(
        `INSERT INTO activity_logs (id, user_id, action, resource_type, resource_id, timestamp)
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [generateId(), userId, action, 'mfa', userId],
      );
    } catch (error) {
      logger.error(`Failed to log MFA activity: ${error}`);
    }
  }
}

export const mfaService = new MfaService();
