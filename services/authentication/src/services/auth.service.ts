import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
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
  User,
  UserRole,
  ClearanceLevel,
  JWTPayload,
} from '@apollo/shared';

export class AuthService {
  async register(userData: {
    email: string;
    username: string;
    password: string;
    firstName: string;
    lastName: string;
    role?: UserRole;
    clearanceLevel?: ClearanceLevel;
  }): Promise<{ user: User; accessToken: string; refreshToken: string }> {
    // Check if user exists
    const existingUser = await database.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [userData.email, userData.username],
    );

    if (existingUser.rows.length > 0) {
      throw new ConflictError('User with this email or username already exists');
    }

    // Hash password
    const passwordHash = await bcrypt.hash(userData.password, 12);

    // Create user
    const userId = generateId();
    const result = await database.query<User>(
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

    const user = result.rows[0]!;

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user);

    // Log activity
    await this.logActivity(user.id, 'USER_REGISTERED', 'user', user.id);

    logger.info(`User registered: ${user.email}`);

    return { user, accessToken, refreshToken };
  }

  async login(
    email: string,
    password: string,
    ipAddress: string,
  ): Promise<{ user: User; accessToken: string; refreshToken: string; requiresMfa: boolean }> {
    // Find user
    const result = await database.query<User & { passwordHash: string }>(
      `SELECT
        id, email, username, password_hash as "passwordHash",
        first_name as "firstName", last_name as "lastName",
        role, clearance_level as "clearanceLevel",
        is_active as "isActive", is_mfa_enabled as "isMfaEnabled",
        last_login as "lastLogin", created_at as "createdAt", updated_at as "updatedAt"
      FROM users WHERE email = $1`,
      [email],
    );

    if (result.rows.length === 0) {
      throw new UnauthorizedError('Invalid credentials');
    }

    const user = result.rows[0]!;

    // Check if user is active
    if (!user.isActive) {
      throw new UnauthorizedError('Account is disabled');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedError('Invalid credentials');
    }

    // Check if MFA is enabled
    if (user.isMfaEnabled) {
      // Store pending login in Redis
      const sessionId = generateToken();
      await redis.set(`mfa:pending:${sessionId}`, user.id, 300); // 5 minutes

      return {
        user: { ...user, passwordHash: undefined } as any,
        accessToken: '',
        refreshToken: '',
        requiresMfa: true,
      };
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user);

    // Update last login
    await database.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Log activity
    await this.logActivity(user.id, 'USER_LOGIN', 'user', user.id, { ipAddress });

    logger.info(`User logged in: ${user.email}`);

    return {
      user: { ...user, passwordHash: undefined } as any,
      accessToken,
      refreshToken,
      requiresMfa: false,
    };
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

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 12);

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
    const isValid = await bcrypt.compare(oldPassword, password_hash);
    if (!isValid) {
      throw new UnauthorizedError('Invalid current password');
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 12);

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
