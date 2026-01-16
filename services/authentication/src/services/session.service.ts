/**
 * Session Management Service
 * Implements secure session handling with JWT tokens, refresh tokens,
 * concurrent session limits, and session invalidation
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import {
  config,
  database,
  redis,
  logger,
  generateId,
  generateToken,
  UnauthorizedError,
  ForbiddenError,
  User,
  JWTPayload,
} from '@apollo/shared';

// Session configuration
export interface SessionConfig {
  maxConcurrentSessions: number;
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
  sessionTimeout: number; // in seconds
  enforceDeviceBinding: boolean;
  requireMfaForNewDevices: boolean;
}

// Session data structure
export interface Session {
  id: string;
  userId: string;
  deviceId: string;
  deviceName: string;
  deviceType: string;
  ipAddress: string;
  userAgent: string;
  location?: string;
  accessToken: string;
  refreshTokenHash: string;
  isActive: boolean;
  lastActivity: Date;
  createdAt: Date;
  expiresAt: Date;
  mfaVerified: boolean;
  biometricVerified: boolean;
  issuedAt?: string; // Legacy compatibility
}

// Token pair
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

// Device info
export interface DeviceInfo {
  deviceId?: string;
  deviceName: string;
  deviceType: string;
  ipAddress: string;
  userAgent: string;
  location?: string;
}

const DEFAULT_CONFIG: SessionConfig = {
  maxConcurrentSessions: 5,
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  sessionTimeout: 30 * 60, // 30 minutes of inactivity
  enforceDeviceBinding: true,
  requireMfaForNewDevices: true,
};

export class SessionService {
  private config: SessionConfig;

  constructor(sessionConfig?: Partial<SessionConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...sessionConfig };
  }

  /**
   * Create a new session for a user
   */
  async createSession(
    user: User,
    device: DeviceInfo,
    options: {
      mfaVerified?: boolean;
      biometricVerified?: boolean;
    } = {},
  ): Promise<TokenPair & { sessionId: string }> {
    // Check concurrent session limit
    const activeSessions = await this.getActiveSessions(user.id);

    if (activeSessions.length >= this.config.maxConcurrentSessions) {
      // Remove oldest session
      const oldestSession = activeSessions.sort(
        (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
      )[0];

      if (oldestSession) {
        await this.invalidateSession(oldestSession.id, 'session_limit_exceeded');
      }
    }

    // Check if this is a new device
    const isNewDevice = await this.isNewDevice(user.id, device);
    if (isNewDevice && this.config.requireMfaForNewDevices && !options.mfaVerified) {
      // Store pending session requiring MFA
      const pendingSessionId = generateId();
      await redis.set(
        `pending_session:${pendingSessionId}`,
        JSON.stringify({ userId: user.id, device }),
        600, // 10 minutes
      );

      throw new ForbiddenError('MFA required for new device', {
        code: 'MFA_REQUIRED_NEW_DEVICE',
        pendingSessionId,
      } as any);
    }

    // Generate device ID if not provided
    const deviceId = device.deviceId || this.generateDeviceId(device);

    // Generate tokens
    const { accessToken, refreshToken, expiresIn } = await this.generateTokenPair(user, deviceId);

    // Create session record
    const sessionId = generateId();
    const refreshTokenHash = this.hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + this.parseExpiry(this.config.refreshTokenExpiry));

    await database.query(
      `INSERT INTO user_sessions (
        id, user_id, device_id, device_name, device_type,
        ip_address, user_agent, location, access_token, refresh_token_hash,
        is_active, last_activity, created_at, expires_at,
        mfa_verified, biometric_verified
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13, $14)`,
      [
        sessionId,
        user.id,
        deviceId,
        device.deviceName,
        device.deviceType,
        device.ipAddress,
        device.userAgent,
        device.location || null,
        accessToken,
        refreshTokenHash,
        true,
        expiresAt,
        options.mfaVerified || false,
        options.biometricVerified || false,
      ],
    );

    // Store session in Redis for fast access
    await redis.set(
      `session:${sessionId}`,
      JSON.stringify({
        userId: user.id,
        deviceId,
        mfaVerified: options.mfaVerified || false,
        biometricVerified: options.biometricVerified || false,
      }),
      this.parseExpiry(this.config.refreshTokenExpiry),
    );

    // Add to user's session list
    await redis.sadd(`user_sessions:${user.id}`, sessionId);

    // Log session creation
    await this.logSessionActivity(sessionId, user.id, 'SESSION_CREATED', {
      device: device.deviceName,
      ipAddress: device.ipAddress,
      isNewDevice,
    });

    logger.info(`Session created for user: ${user.id}, device: ${deviceId}`);

    return {
      sessionId,
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: 'Bearer',
    };
  }

  /**
   * Legacy createSession function for backward compatibility
   */
  static async createSessionLegacy(userId: string): Promise<{
    id: string;
    userId: string;
    issuedAt: string;
    expiresAt: string;
  }> {
    const now = new Date();
    const expires = new Date(now.getTime() + 1000 * 60 * 60);
    return {
      id: generateId(),
      userId,
      issuedAt: now.toISOString(),
      expiresAt: expires.toISOString(),
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshTokens(
    refreshToken: string,
    device: DeviceInfo,
  ): Promise<TokenPair & { sessionId: string }> {
    // Verify refresh token
    let decoded: JWTPayload;
    try {
      decoded = jwt.verify(refreshToken, config.jwt.secret) as JWTPayload;
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired refresh token');
    }

    // Find session by refresh token hash
    const refreshTokenHash = this.hashToken(refreshToken);
    const sessionResult = await database.query<Session>(
      `SELECT * FROM user_sessions
       WHERE user_id = $1 AND refresh_token_hash = $2 AND is_active = true`,
      [decoded.userId, refreshTokenHash],
    );

    if (sessionResult.rows.length === 0) {
      throw new UnauthorizedError('Session not found or expired');
    }

    const session = sessionResult.rows[0]!;

    // Verify device binding if enabled
    if (this.config.enforceDeviceBinding) {
      const currentDeviceId = device.deviceId || this.generateDeviceId(device);
      if (session.deviceId !== currentDeviceId) {
        // Possible token theft - invalidate all sessions for security
        await this.invalidateAllSessions(decoded.userId, 'device_mismatch_security');
        throw new UnauthorizedError('Device mismatch. All sessions invalidated for security.');
      }
    }

    // Check session expiration
    if (new Date(session.expiresAt) < new Date()) {
      await this.invalidateSession(session.id, 'expired');
      throw new UnauthorizedError('Session expired');
    }

    // Get user
    const userResult = await database.query<User>(
      `SELECT id, email, role, clearance_level as "clearanceLevel"
       FROM users WHERE id = $1 AND is_active = true`,
      [decoded.userId],
    );

    if (userResult.rows.length === 0) {
      throw new UnauthorizedError('User not found or inactive');
    }

    const user = userResult.rows[0]!;

    // Generate new token pair
    const { accessToken, refreshToken: newRefreshToken, expiresIn } =
      await this.generateTokenPair(user, session.deviceId);

    const newRefreshTokenHash = this.hashToken(newRefreshToken);

    // Update session
    await database.query(
      `UPDATE user_sessions
       SET access_token = $1, refresh_token_hash = $2, last_activity = NOW(),
           ip_address = $3, user_agent = $4
       WHERE id = $5`,
      [accessToken, newRefreshTokenHash, device.ipAddress, device.userAgent, session.id],
    );

    // Update Redis
    await redis.set(
      `session:${session.id}`,
      JSON.stringify({
        userId: user.id,
        deviceId: session.deviceId,
        mfaVerified: session.mfaVerified,
        biometricVerified: session.biometricVerified,
      }),
      this.parseExpiry(this.config.refreshTokenExpiry),
    );

    logger.info(`Tokens refreshed for user: ${user.id}, session: ${session.id}`);

    return {
      sessionId: session.id,
      accessToken,
      refreshToken: newRefreshToken,
      expiresIn,
      tokenType: 'Bearer',
    };
  }

  /**
   * Validate access token and return session
   */
  async validateAccessToken(accessToken: string): Promise<{
    user: JWTPayload;
    sessionId: string;
    mfaVerified: boolean;
    biometricVerified: boolean;
  }> {
    // Verify JWT
    let decoded: JWTPayload & { sessionId?: string; deviceId?: string };
    try {
      decoded = jwt.verify(accessToken, config.jwt.secret) as any;
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired access token');
    }

    // Check session in Redis first (fast path)
    const sessionId = decoded.sessionId;
    if (sessionId) {
      const cachedSession = await redis.get(`session:${sessionId}`);
      if (cachedSession) {
        const sessionData = JSON.parse(cachedSession);

        // Update last activity in background
        this.updateLastActivity(sessionId).catch(err =>
          logger.error(`Failed to update last activity: ${err}`),
        );

        return {
          user: decoded,
          sessionId,
          mfaVerified: sessionData.mfaVerified,
          biometricVerified: sessionData.biometricVerified,
        };
      }
    }

    // Fallback to database
    const sessionResult = await database.query<Session>(
      `SELECT id, mfa_verified as "mfaVerified", biometric_verified as "biometricVerified"
       FROM user_sessions
       WHERE user_id = $1 AND access_token = $2 AND is_active = true`,
      [decoded.userId, accessToken],
    );

    if (sessionResult.rows.length === 0) {
      throw new UnauthorizedError('Session not found or invalidated');
    }

    const session = sessionResult.rows[0]!;

    // Re-cache in Redis
    await redis.set(
      `session:${session.id}`,
      JSON.stringify({
        userId: decoded.userId,
        mfaVerified: session.mfaVerified,
        biometricVerified: session.biometricVerified,
      }),
      this.parseExpiry(this.config.accessTokenExpiry),
    );

    return {
      user: decoded,
      sessionId: session.id,
      mfaVerified: session.mfaVerified,
      biometricVerified: session.biometricVerified,
    };
  }

  /**
   * Invalidate a specific session
   */
  async invalidateSession(sessionId: string, reason: string): Promise<void> {
    // Get session info before invalidating
    const sessionResult = await database.query<Session>(
      'SELECT user_id as "userId" FROM user_sessions WHERE id = $1',
      [sessionId],
    );

    if (sessionResult.rows.length === 0) {
      return; // Session doesn't exist
    }

    const { userId } = sessionResult.rows[0]!;

    // Invalidate in database
    await database.query(
      'UPDATE user_sessions SET is_active = false WHERE id = $1',
      [sessionId],
    );

    // Remove from Redis
    await redis.del(`session:${sessionId}`);
    await redis.srem(`user_sessions:${userId}`, sessionId);

    // Log invalidation
    await this.logSessionActivity(sessionId, userId, 'SESSION_INVALIDATED', { reason });

    logger.info(`Session invalidated: ${sessionId}, reason: ${reason}`);
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateAllSessions(userId: string, reason: string): Promise<number> {
    // Get all active sessions
    const sessionsResult = await database.query(
      'SELECT id FROM user_sessions WHERE user_id = $1 AND is_active = true',
      [userId],
    );

    const sessionIds = sessionsResult.rows.map(r => r.id);

    if (sessionIds.length === 0) {
      return 0;
    }

    // Invalidate all in database
    await database.query(
      'UPDATE user_sessions SET is_active = false WHERE user_id = $1 AND is_active = true',
      [userId],
    );

    // Remove from Redis
    for (const sessionId of sessionIds) {
      await redis.del(`session:${sessionId}`);
    }
    await redis.del(`user_sessions:${userId}`);

    // Log activity
    await this.logSessionActivity(null, userId, 'ALL_SESSIONS_INVALIDATED', {
      reason,
      count: sessionIds.length,
    });

    logger.info(`All sessions invalidated for user: ${userId}, count: ${sessionIds.length}`);

    return sessionIds.length;
  }

  /**
   * Invalidate all sessions except the current one
   */
  async invalidateOtherSessions(userId: string, currentSessionId: string): Promise<number> {
    // Get all active sessions except current
    const sessionsResult = await database.query(
      'SELECT id FROM user_sessions WHERE user_id = $1 AND is_active = true AND id != $2',
      [userId, currentSessionId],
    );

    const sessionIds = sessionsResult.rows.map(r => r.id);

    if (sessionIds.length === 0) {
      return 0;
    }

    // Invalidate in database
    await database.query(
      'UPDATE user_sessions SET is_active = false WHERE user_id = $1 AND id != $2 AND is_active = true',
      [userId, currentSessionId],
    );

    // Remove from Redis
    for (const sessionId of sessionIds) {
      await redis.del(`session:${sessionId}`);
      await redis.srem(`user_sessions:${userId}`, sessionId);
    }

    logger.info(`Other sessions invalidated for user: ${userId}, count: ${sessionIds.length}`);

    return sessionIds.length;
  }

  /**
   * Get all active sessions for a user
   */
  async getActiveSessions(userId: string): Promise<Array<{
    id: string;
    deviceName: string;
    deviceType: string;
    ipAddress: string;
    location?: string;
    lastActivity: Date;
    createdAt: Date;
    isCurrent: boolean;
    mfaVerified: boolean;
    biometricVerified: boolean;
  }>> {
    const result = await database.query(
      `SELECT
        id, device_name as "deviceName", device_type as "deviceType",
        ip_address as "ipAddress", location,
        last_activity as "lastActivity", created_at as "createdAt",
        mfa_verified as "mfaVerified", biometric_verified as "biometricVerified"
       FROM user_sessions
       WHERE user_id = $1 AND is_active = true
       ORDER BY last_activity DESC`,
      [userId],
    );

    return result.rows.map(row => ({
      ...row,
      isCurrent: false, // Will be set by caller who knows current session
    }));
  }

  /**
   * Update MFA verification status for session
   */
  async updateMfaVerification(sessionId: string, verified: boolean): Promise<void> {
    await database.query(
      'UPDATE user_sessions SET mfa_verified = $1 WHERE id = $2',
      [verified, sessionId],
    );

    // Update Redis cache
    const cachedSession = await redis.get(`session:${sessionId}`);
    if (cachedSession) {
      const sessionData = JSON.parse(cachedSession);
      sessionData.mfaVerified = verified;
      await redis.set(`session:${sessionId}`, JSON.stringify(sessionData));
    }
  }

  /**
   * Update biometric verification status for session
   */
  async updateBiometricVerification(sessionId: string, verified: boolean): Promise<void> {
    await database.query(
      'UPDATE user_sessions SET biometric_verified = $1 WHERE id = $2',
      [verified, sessionId],
    );

    // Update Redis cache
    const cachedSession = await redis.get(`session:${sessionId}`);
    if (cachedSession) {
      const sessionData = JSON.parse(cachedSession);
      sessionData.biometricVerified = verified;
      await redis.set(`session:${sessionId}`, JSON.stringify(sessionData));
    }
  }

  /**
   * Check for inactive sessions and clean them up
   */
  async cleanupInactiveSessions(): Promise<number> {
    const timeoutThreshold = new Date(Date.now() - this.config.sessionTimeout * 1000);

    const result = await database.query(
      `UPDATE user_sessions
       SET is_active = false
       WHERE is_active = true AND last_activity < $1
       RETURNING id, user_id`,
      [timeoutThreshold],
    );

    // Clean up Redis
    for (const row of result.rows) {
      await redis.del(`session:${row.id}`);
      await redis.srem(`user_sessions:${row.user_id}`, row.id);
    }

    if (result.rows.length > 0) {
      logger.info(`Cleaned up ${result.rows.length} inactive sessions`);
    }

    return result.rows.length;
  }

  // ============= Private Helper Methods =============

  private async generateTokenPair(user: User, deviceId: string): Promise<TokenPair> {
    const sessionId = generateId();

    const payload: JWTPayload & { sessionId: string; deviceId: string } = {
      userId: user.id,
      email: user.email,
      role: user.role,
      clearanceLevel: user.clearanceLevel,
      sessionId,
      deviceId,
    };

    // Generate access token (short-lived)
    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: this.config.accessTokenExpiry,
    });

    // Generate refresh token (long-lived)
    const refreshToken = jwt.sign(
      { userId: user.id, type: 'refresh', sessionId },
      config.jwt.secret,
      { expiresIn: this.config.refreshTokenExpiry },
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpiry(this.config.accessTokenExpiry),
      tokenType: 'Bearer',
    };
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private generateDeviceId(device: DeviceInfo): string {
    const fingerprint = `${device.deviceType}:${device.userAgent}:${device.deviceName}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex').substring(0, 32);
  }

  private async isNewDevice(userId: string, device: DeviceInfo): Promise<boolean> {
    const deviceId = device.deviceId || this.generateDeviceId(device);

    const result = await database.query(
      'SELECT id FROM user_sessions WHERE user_id = $1 AND device_id = $2 LIMIT 1',
      [userId, deviceId],
    );

    return result.rows.length === 0;
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 15 * 60; // Default 15 minutes
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      default:
        return 15 * 60;
    }
  }

  private async updateLastActivity(sessionId: string): Promise<void> {
    await database.query(
      'UPDATE user_sessions SET last_activity = NOW() WHERE id = $1',
      [sessionId],
    );
  }

  private async logSessionActivity(
    sessionId: string | null,
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
          'session',
          sessionId || userId,
          metadata ? JSON.stringify(metadata) : null,
        ],
      );
    } catch (error) {
      logger.error(`Failed to log session activity: ${error}`);
    }
  }
}

// Export singleton instance
export const sessionService = new SessionService();

// Legacy export for backward compatibility
export async function createSession(userId: string): Promise<{
  id: string;
  userId: string;
  issuedAt: string;
  expiresAt: string;
}> {
  return SessionService.createSessionLegacy(userId);
}
