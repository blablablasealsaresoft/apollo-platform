import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import {
  config,
  database,
  redis,
  logger,
  generateId,
  generateToken,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
  InternalServerError,
  ServiceUnavailableError,
  BadRequestError,
  User,
  UserRole,
  ClearanceLevel,
  JWTPayload,
} from '@apollo/shared';
import { sessionService, DeviceInfo } from './session.service';
import { biometricService, BiometricType } from './biometric.service';
import { mfaService } from './mfa.service';

// Try to import argon2, fallback to bcrypt if not available
let argon2: typeof import('argon2') | null = null;
(async () => {
  try {
    argon2 = await import('argon2');
    logger.info('Argon2 password hashing available');
  } catch {
    logger.warn('Argon2 not available, using bcrypt for password hashing');
  }
})();

// Password hashing configuration
const ARGON2_OPTIONS = {
  type: 2 as const, // argon2id
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
};

const BCRYPT_ROUNDS = 12;

// Password validation regex patterns
const PASSWORD_PATTERNS = {
  minLength: 12,
  hasUppercase: /[A-Z]/,
  hasLowercase: /[a-z]/,
  hasNumber: /[0-9]/,
  hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/,
};

// Error codes for authentication service
export const AUTH_ERROR_CODES = {
  USER_EXISTS: 'AUTH_USER_EXISTS',
  INVALID_CREDENTIALS: 'AUTH_INVALID_CREDENTIALS',
  ACCOUNT_DISABLED: 'AUTH_ACCOUNT_DISABLED',
  TOKEN_INVALID: 'AUTH_TOKEN_INVALID',
  TOKEN_EXPIRED: 'AUTH_TOKEN_EXPIRED',
  MFA_REQUIRED: 'AUTH_MFA_REQUIRED',
  REGISTRATION_FAILED: 'AUTH_REGISTRATION_FAILED',
  LOGIN_FAILED: 'AUTH_LOGIN_FAILED',
  DATABASE_ERROR: 'AUTH_DATABASE_ERROR',
  REDIS_ERROR: 'AUTH_REDIS_ERROR',
  PASSWORD_WEAK: 'AUTH_PASSWORD_WEAK',
} as const;

export class AuthService {
  /**
   * Hash password using argon2 (preferred) or bcrypt (fallback)
   */
  private async hashPassword(password: string): Promise<string> {
    if (argon2) {
      return argon2.hash(password, ARGON2_OPTIONS);
    }
    return bcrypt.hash(password, BCRYPT_ROUNDS);
  }

  /**
   * Verify password against stored hash (supports both argon2 and bcrypt)
   */
  private async verifyPassword(password: string, hash: string): Promise<boolean> {
    // Check if it's an argon2 hash (starts with $argon2)
    if (hash.startsWith('$argon2') && argon2) {
      return argon2.verify(hash, password);
    }
    // Fallback to bcrypt
    return bcrypt.compare(password, hash);
  }

  /**
   * Validate password strength requirements
   */
  private validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < PASSWORD_PATTERNS.minLength) {
      errors.push(`Password must be at least ${PASSWORD_PATTERNS.minLength} characters long`);
    }
    if (!PASSWORD_PATTERNS.hasUppercase.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!PASSWORD_PATTERNS.hasLowercase.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!PASSWORD_PATTERNS.hasNumber.test(password)) {
      errors.push('Password must contain at least one number');
    }
    if (!PASSWORD_PATTERNS.hasSpecial.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Upgrade password hash from bcrypt to argon2 if needed
   */
  private async upgradePasswordHashIfNeeded(userId: string, password: string, currentHash: string): Promise<void> {
    // If argon2 is available and current hash is bcrypt, upgrade it
    if (argon2 && currentHash.startsWith('$2')) {
      const newHash = await this.hashPassword(password);
      await database.query(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [newHash, userId],
      );
      logger.info(`Password hash upgraded to argon2 for user: ${userId}`);
    }
  }

  async register(userData: {
    email: string;
    username: string;
    password: string;
    firstName: string;
    lastName: string;
    role?: UserRole;
    clearanceLevel?: ClearanceLevel;
  }): Promise<{ user: User; accessToken: string; refreshToken: string }> {
    try {
      // Validate password strength
      const passwordValidation = this.validatePasswordStrength(userData.password);
      if (!passwordValidation.valid) {
        throw new BadRequestError(passwordValidation.errors.join('. '), AUTH_ERROR_CODES.PASSWORD_WEAK);
      }

      // Check if user exists
      let existingUser;
      try {
        existingUser = await database.query(
          'SELECT id FROM users WHERE email = $1 OR username = $2',
          [userData.email, userData.username],
        );
      } catch (dbError) {
        logger.error(`Database error during user lookup: ${dbError}`);
        throw new ServiceUnavailableError('Database service unavailable', AUTH_ERROR_CODES.DATABASE_ERROR);
      }

      if (existingUser.rows.length > 0) {
        throw new ConflictError('User with this email or username already exists', AUTH_ERROR_CODES.USER_EXISTS);
      }

      // Hash password with argon2 (preferred) or bcrypt
      const passwordHash = await this.hashPassword(userData.password);

      // Create user
      const userId = generateId();
      let result;
      try {
        result = await database.query<User>(
          `INSERT INTO users (
            id, email, username, password_hash, first_name, last_name,
            role, clearance_level, is_active, is_mfa_enabled
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          RETURNING id, email, username, first_name as "firstName", last_name as "lastName",
                    role, clearance_level as "clearanceLevel", is_active as "isActive",
                    is_mfa_enabled as "isMfaEnabled", created_at as "createdAt", updated_at as "updatedAt"`,
          [
            userId,
            userData.email,
            userData.username,
            passwordHash,
            userData.firstName,
            userData.lastName,
            userData.role || UserRole.VIEWER,
            userData.clearanceLevel || ClearanceLevel.UNCLASSIFIED,
            true,
            false,
          ],
        );
      } catch (dbError) {
        logger.error(`Database error during user creation: ${dbError}`);
        throw new InternalServerError('Failed to create user account', AUTH_ERROR_CODES.REGISTRATION_FAILED);
      }

      const user = result.rows[0]!;

      // Generate tokens
      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Log activity (non-blocking)
      this.logActivity(user.id, 'USER_REGISTERED', 'user', user.id).catch(err => {
        logger.warn(`Failed to log registration activity: ${err}`);
      });

      logger.info(`User registered: ${user.email}`);

      return { user, accessToken, refreshToken };
    } catch (error) {
      // Re-throw known errors
      if (error instanceof ConflictError || error instanceof BadRequestError ||
          error instanceof ServiceUnavailableError || error instanceof InternalServerError) {
        throw error;
      }
      // Wrap unknown errors
      logger.error(`Unexpected registration error: ${error}`);
      throw new InternalServerError('Registration failed due to an unexpected error', AUTH_ERROR_CODES.REGISTRATION_FAILED);
    }
  }

  async login(
    email: string,
    password: string,
    ipAddress: string,
  ): Promise<{ user: User; accessToken: string; refreshToken: string; requiresMfa: boolean }> {
    try {
      // Find user
      let result;
      try {
        result = await database.query<User & { passwordHash: string }>(
          `SELECT
            id, email, username, password_hash as "passwordHash",
            first_name as "firstName", last_name as "lastName",
            role, clearance_level as "clearanceLevel",
            is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
            last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
          FROM users WHERE email = $1`,
          [email],
        );
      } catch (dbError) {
        logger.error(`Database error during login lookup: ${dbError}`);
        throw new ServiceUnavailableError('Authentication service temporarily unavailable', AUTH_ERROR_CODES.DATABASE_ERROR);
      }

      if (result.rows.length === 0) {
        // Log failed attempt (non-blocking)
        logger.warn(`Failed login attempt for non-existent email: ${email.substring(0, 3)}***`);
        throw new UnauthorizedError('Invalid credentials', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
      }

      const user = result.rows[0]!;

      // Check if user is active
      if (!user.isActive) {
        logger.warn(`Login attempt for disabled account: ${user.id}`);
        throw new UnauthorizedError('Account is disabled', AUTH_ERROR_CODES.ACCOUNT_DISABLED);
      }

      // Verify password (supports both argon2 and bcrypt)
      const isPasswordValid = await this.verifyPassword(password, user.passwordHash);
      if (!isPasswordValid) {
        // Log failed attempt (non-blocking)
        this.logActivity(user.id, 'LOGIN_FAILED', 'user', user.id, { ipAddress, reason: 'invalid_password' }).catch(() => {});
        throw new UnauthorizedError('Invalid credentials', AUTH_ERROR_CODES.INVALID_CREDENTIALS);
      }

      // Upgrade password hash to argon2 if needed (non-blocking)
      this.upgradePasswordHashIfNeeded(user.id, password, user.passwordHash).catch(err => {
        logger.warn(`Failed to upgrade password hash: ${err}`);
      });

      // Check if MFA is enabled
      if (user.isMfaEnabled) {
        try {
          // Store pending login in Redis
          const sessionId = generateToken();
          await redis.set(`mfa:pending:${sessionId}`, user.id, 300); // 5 minutes

          return {
            user: { ...user, passwordHash: undefined } as any,
            accessToken: sessionId, // Return session ID for MFA verification
            refreshToken: '',
            requiresMfa: true,
          };
        } catch (redisError) {
          logger.error(`Redis error during MFA setup: ${redisError}`);
          throw new ServiceUnavailableError('MFA service temporarily unavailable', AUTH_ERROR_CODES.REDIS_ERROR);
        }
      }

      // Generate tokens
      const { accessToken, refreshToken } = await this.generateTokens(user);

      // Update last login (non-blocking)
      database.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]).catch(err => {
        logger.warn(`Failed to update last login: ${err}`);
      });

      // Log activity (non-blocking)
      this.logActivity(user.id, 'USER_LOGIN', 'user', user.id, { ipAddress }).catch(err => {
        logger.warn(`Failed to log login activity: ${err}`);
      });

      logger.info(`User logged in: ${user.email}`);

      return {
        user: { ...user, passwordHash: undefined } as any,
        accessToken,
        refreshToken,
        requiresMfa: false,
      };
    } catch (error) {
      // Re-throw known errors
      if (error instanceof UnauthorizedError || error instanceof ServiceUnavailableError) {
        throw error;
      }
      // Wrap unknown errors
      logger.error(`Unexpected login error: ${error}`);
      throw new InternalServerError('Login failed due to an unexpected error', AUTH_ERROR_CODES.LOGIN_FAILED);
    }
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    // Invalidate refresh token
    const tokenKey = `refresh_token:${userId}`;
    const storedToken = await redis.get(tokenKey);

    if (storedToken === refreshToken) {
      await redis.del(tokenKey);
    }

    // Log activity
    await this.logActivity(userId, 'USER_LOGOUT', 'user', userId);

    logger.info(`User logged out: ${userId}`);
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.jwt.secret) as JWTPayload;

      // Check if refresh token is valid in Redis
      const tokenKey = `refresh_token:${decoded.userId}`;
      const storedToken = await redis.get(tokenKey);

      if (!storedToken || storedToken !== refreshToken) {
        throw new UnauthorizedError('Invalid refresh token');
      }

      // Get user
      const result = await database.query<User>(
        `SELECT
          id, email, username, first_name as "firstName", last_name as "lastName",
          role, clearance_level as "clearanceLevel",
          is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
          last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
        FROM users WHERE id = $1 AND is_active = true`,
        [decoded.userId],
      );

      if (result.rows.length === 0) {
        throw new UnauthorizedError('User not found or inactive');
      }

      const user = result.rows[0]!;

      // Generate new tokens
      const tokens = await this.generateTokens(user);

      logger.info(`Access token refreshed: ${user.email}`);

      return tokens;
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired refresh token');
    }
  }

  async resetPasswordRequest(email: string): Promise<void> {
    const result = await database.query<User>('SELECT id, email FROM users WHERE email = $1', [
      email,
    ]);

    if (result.rows.length === 0) {
      // Don't reveal if user exists
      return;
    }

    const user = result.rows[0]!;

    // Generate reset token
    const resetToken = generateToken();
    const resetTokenHash = await bcrypt.hash(resetToken, 10);

    // Store reset token in database
    await database.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expires = NOW() + INTERVAL \'1 hour\' WHERE id = $2',
      [resetTokenHash, user.id],
    );

    // In production, send email with reset link
    logger.info(`Password reset requested for: ${user.email}`);
    // TODO: Send email with reset token
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const result = await database.query(
      `SELECT id, password_reset_token, password_reset_expires
       FROM users
       WHERE password_reset_expires > NOW()`,
    );

    let userId: string | null = null;

    // Find user with matching token
    for (const row of result.rows) {
      const isValid = await bcrypt.compare(token, row.password_reset_token);
      if (isValid) {
        userId = row.id;
        break;
      }
    }

    if (!userId) {
      throw new UnauthorizedError('Invalid or expired reset token');
    }

    // Validate new password strength
    const passwordValidation = this.validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      throw new BadRequestError(passwordValidation.errors.join('. '), AUTH_ERROR_CODES.PASSWORD_WEAK);
    }

    // Hash new password with argon2 (preferred) or bcrypt
    const passwordHash = await this.hashPassword(newPassword);

    // Update password and clear reset token
    await database.query(
      'UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2',
      [passwordHash, userId],
    );

    // Log activity
    await this.logActivity(userId, 'PASSWORD_RESET', 'user', userId);

    logger.info(`Password reset completed for user: ${userId}`);
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
    const result = await database.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId],
    );

    if (result.rows.length === 0) {
      throw new NotFoundError('User not found');
    }

    const { password_hash } = result.rows[0]!;

    // Verify old password
    const isValid = await this.verifyPassword(oldPassword, password_hash);
    if (!isValid) {
      throw new UnauthorizedError('Invalid current password');
    }

    // Validate new password strength
    const passwordValidation = this.validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      throw new BadRequestError(passwordValidation.errors.join('. '), AUTH_ERROR_CODES.PASSWORD_WEAK);
    }

    // Hash new password with argon2 (preferred) or bcrypt
    const passwordHash = await this.hashPassword(newPassword);

    // Update password
    await database.query('UPDATE users SET password_hash = $1 WHERE id = $2', [
      passwordHash,
      userId,
    ]);

    // Log activity
    await this.logActivity(userId, 'PASSWORD_CHANGED', 'user', userId);

    logger.info(`Password changed for user: ${userId}`);
  }

  async validateToken(token: string): Promise<JWTPayload> {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;

      // Check if user is still active
      const result = await database.query(
        'SELECT id FROM users WHERE id = $1 AND is_active = true',
        [decoded.userId],
      );

      if (result.rows.length === 0) {
        throw new UnauthorizedError('User not found or inactive');
      }

      return decoded;
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired token');
    }
  }

  private async generateTokens(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JWTPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      clearanceLevel: user.clearanceLevel,
    };

    // Generate access token (short-lived)
    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.accessExpiration,
    });

    // Generate refresh token (long-lived)
    const refreshToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.refreshExpiration,
    });

    // Store refresh token in Redis
    const tokenKey = `refresh_token:${user.id}`;
    await redis.set(tokenKey, refreshToken, 7 * 24 * 60 * 60); // 7 days

    return { accessToken, refreshToken };
  }

  private async logActivity(
    userId: string,
    action: string,
    resourceType: string,
    resourceId: string,
    metadata?: any,
  ): Promise<void> {
    try {
      await database.query(
        `INSERT INTO activity_logs (id, user_id, action, resource_type, resource_id, metadata, ip_address, user_agent, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
        [
          generateId(),
          userId,
          action,
          resourceType,
          resourceId,
          metadata ? JSON.stringify(metadata) : null,
          metadata?.ipAddress || 'unknown',
          metadata?.userAgent || 'unknown',
        ],
      );
    } catch (error) {
      logger.error(`Failed to log activity: ${error}`);
    }
  }
}

export const authService = new AuthService();
