/**
 * Session Management Routes
 * Handles user sessions, device management, and security controls
 */

import { Router, Request, Response, NextFunction } from 'express';
import { body, param, validationResult } from 'express-validator';
import { sessionService } from '../services/session.service';
import { authenticate } from '../middleware/auth.middleware';
import { logger } from '@apollo/shared';

const router = Router();

// Validation middleware
const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array(),
    });
  }
  next();
};

/**
 * GET /sessions
 * Get all active sessions for the authenticated user
 */
router.get(
  '/',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const currentSessionId = req.session?.id;

      const sessions = await sessionService.getActiveSessions(userId);

      // Mark the current session
      const sessionsWithCurrent = sessions.map(session => ({
        ...session,
        isCurrent: session.id === currentSessionId,
      }));

      res.json({
        success: true,
        data: {
          sessions: sessionsWithCurrent,
          totalCount: sessions.length,
          currentSessionId,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /sessions/refresh
 * Refresh access token using refresh token
 */
router.post(
  '/refresh',
  [
    body('refreshToken').notEmpty().withMessage('Refresh token is required'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { refreshToken } = req.body;
      const deviceInfo = {
        deviceName: req.headers['x-device-name'] as string || 'Unknown Device',
        deviceType: req.headers['x-device-type'] as string || 'unknown',
        ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        deviceId: req.headers['x-device-id'] as string,
      };

      const result = await sessionService.refreshTokens(refreshToken, deviceInfo);

      res.json({
        success: true,
        data: {
          sessionId: result.sessionId,
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
          expiresIn: result.expiresIn,
          tokenType: result.tokenType,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /sessions/:sessionId
 * Invalidate a specific session
 */
router.delete(
  '/:sessionId',
  authenticate,
  [
    param('sessionId').isUUID().withMessage('Invalid session ID'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const sessionId = req.params.sessionId;
      const currentSessionId = req.session?.id;

      // Get the session to verify ownership
      const sessions = await sessionService.getActiveSessions(userId);
      const targetSession = sessions.find(s => s.id === sessionId);

      if (!targetSession) {
        return res.status(404).json({
          success: false,
          message: 'Session not found or does not belong to you',
        });
      }

      await sessionService.invalidateSession(sessionId, 'user_requested');

      logger.info(`Session invalidated by user: ${sessionId}`);

      res.json({
        success: true,
        message: 'Session invalidated successfully',
        data: {
          wasCurrentSession: sessionId === currentSessionId,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /sessions
 * Invalidate all sessions except the current one
 */
router.delete(
  '/',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const currentSessionId = req.session?.id;

      if (!currentSessionId) {
        return res.status(400).json({
          success: false,
          message: 'Current session not found',
        });
      }

      const invalidatedCount = await sessionService.invalidateOtherSessions(
        userId,
        currentSessionId,
      );

      logger.info(`${invalidatedCount} other sessions invalidated for user: ${userId}`);

      res.json({
        success: true,
        message: 'All other sessions invalidated successfully',
        data: {
          invalidatedCount,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /sessions/all
 * Invalidate ALL sessions including the current one (logout everywhere)
 */
router.delete(
  '/all',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;

      const invalidatedCount = await sessionService.invalidateAllSessions(
        userId,
        'user_logout_all',
      );

      logger.info(`All ${invalidatedCount} sessions invalidated for user: ${userId}`);

      res.json({
        success: true,
        message: 'All sessions invalidated successfully. Please log in again.',
        data: {
          invalidatedCount,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /sessions/current
 * Get current session details
 */
router.get(
  '/current',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const currentSessionId = req.session?.id;

      if (!currentSessionId) {
        return res.status(404).json({
          success: false,
          message: 'Current session not found',
        });
      }

      const sessions = await sessionService.getActiveSessions(userId);
      const currentSession = sessions.find(s => s.id === currentSessionId);

      if (!currentSession) {
        return res.status(404).json({
          success: false,
          message: 'Current session not found',
        });
      }

      res.json({
        success: true,
        data: {
          ...currentSession,
          isCurrent: true,
          mfaVerified: req.session?.mfaVerified,
          biometricVerified: req.session?.biometricVerified,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /sessions/cleanup
 * Cleanup inactive sessions (admin operation)
 */
router.post(
  '/cleanup',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // This should ideally be restricted to admins
      const cleanedCount = await sessionService.cleanupInactiveSessions();

      logger.info(`Cleaned up ${cleanedCount} inactive sessions`);

      res.json({
        success: true,
        message: 'Inactive sessions cleaned up',
        data: {
          cleanedCount,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

export default router;
