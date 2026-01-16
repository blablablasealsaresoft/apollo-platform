/**
 * Biometric Authentication Routes
 * Handles fingerprint, face ID, and voice print authentication
 */

import { Router, Request, Response, NextFunction } from 'express';
import { body, param, validationResult } from 'express-validator';
import { biometricService, BiometricType, BiometricStatus } from '../services/biometric.service';
import { sessionService } from '../services/session.service';
import { authenticate, requireMfa } from '../middleware/auth.middleware';
import { BadRequestError, UnauthorizedError, logger } from '@apollo/shared';

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
 * GET /biometric/availability
 * Check available biometric authentication methods for the user
 */
router.get(
  '/availability',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;

      const results = await Promise.all([
        biometricService.canAuthenticate(userId, BiometricType.FINGERPRINT),
        biometricService.canAuthenticate(userId, BiometricType.FACE_ID),
        biometricService.canAuthenticate(userId, BiometricType.VOICE_PRINT),
      ]);

      res.json({
        success: true,
        data: {
          fingerprint: results[0],
          faceId: results[1],
          voicePrint: results[2],
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /biometric/enrollments
 * Get all biometric enrollments for the authenticated user
 */
router.get(
  '/enrollments',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const enrollments = await biometricService.getUserEnrollments(userId);

      res.json({
        success: true,
        data: enrollments,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /biometric/enroll/:type
 * Enroll a new biometric authentication method
 */
router.post(
  '/enroll/:type',
  authenticate,
  [
    param('type').isIn(['fingerprint', 'face_id', 'voice_print']).withMessage('Invalid biometric type'),
    body('template').notEmpty().withMessage('Biometric template is required'),
    body('password').notEmpty().withMessage('Password is required for enrollment'),
    body('qualityScore').isFloat({ min: 0, max: 1 }).withMessage('Quality score must be between 0 and 1'),
    body('deviceId').optional().isString(),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const type = req.params.type as BiometricType;
      const { template, password, qualityScore, deviceId } = req.body;

      const result = await biometricService.enrollBiometric(
        userId,
        type,
        {
          type,
          data: template,
          deviceId,
          capturedAt: new Date(),
          qualityScore: parseFloat(qualityScore),
        },
        password,
      );

      logger.info(`Biometric enrolled: ${type} for user ${userId}`);

      res.status(201).json({
        success: true,
        message: `${type} enrolled successfully`,
        data: {
          enrollmentId: result.enrollmentId,
          backupCodes: result.backupCodes,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /biometric/authenticate/:type
 * Authenticate using biometric data
 */
router.post(
  '/authenticate/:type',
  [
    param('type').isIn(['fingerprint', 'face_id', 'voice_print']).withMessage('Invalid biometric type'),
    body('template').notEmpty().withMessage('Biometric template is required'),
    body('userId').notEmpty().withMessage('User ID is required'),
    body('livenessProof').optional().isString(),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const type = req.params.type as BiometricType;
      const { template, userId, livenessProof } = req.body;

      const result = await biometricService.authenticateWithBiometric(
        userId,
        type,
        template,
        livenessProof,
      );

      if (!result.success) {
        return res.status(401).json({
          success: false,
          error: result.error,
          message: 'Biometric authentication failed',
          confidence: result.confidence,
          livenessScore: result.livenessScore,
        });
      }

      // Update session biometric verification if session exists
      if (req.session?.id) {
        await sessionService.updateBiometricVerification(req.session.id, true);
      }

      logger.info(`Biometric auth success: ${type} for user ${userId}`);

      res.json({
        success: true,
        message: 'Biometric authentication successful',
        data: {
          biometricType: result.biometricType,
          confidence: result.confidence,
          livenessScore: result.livenessScore,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /biometric/authenticate/:type/backup-code
 * Authenticate using a biometric backup code
 */
router.post(
  '/authenticate/:type/backup-code',
  [
    param('type').isIn(['fingerprint', 'face_id', 'voice_print']).withMessage('Invalid biometric type'),
    body('backupCode').notEmpty().withMessage('Backup code is required'),
    body('userId').notEmpty().withMessage('User ID is required'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const type = req.params.type as BiometricType;
      const { backupCode, userId } = req.body;

      const success = await biometricService.authenticateWithBackupCode(
        userId,
        type,
        backupCode,
      );

      if (!success) {
        return res.status(401).json({
          success: false,
          message: 'Invalid backup code',
        });
      }

      logger.info(`Biometric backup code used: ${type} for user ${userId}`);

      res.json({
        success: true,
        message: 'Backup code authentication successful',
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /biometric/enroll/:type
 * Disable a biometric authentication method
 */
router.delete(
  '/enroll/:type',
  authenticate,
  [
    param('type').isIn(['fingerprint', 'face_id', 'voice_print']).withMessage('Invalid biometric type'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const type = req.params.type as BiometricType;
      const { password } = req.body;

      await biometricService.disableBiometric(userId, type, password);

      logger.info(`Biometric disabled: ${type} for user ${userId}`);

      res.json({
        success: true,
        message: `${type} disabled successfully`,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /biometric/regenerate-backup-codes/:type
 * Regenerate backup codes for a biometric enrollment
 */
router.post(
  '/regenerate-backup-codes/:type',
  authenticate,
  [
    param('type').isIn(['fingerprint', 'face_id', 'voice_print']).withMessage('Invalid biometric type'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const type = req.params.type as BiometricType;
      const { password } = req.body;

      const result = await biometricService.regenerateBackupCodes(userId, type, password);

      logger.info(`Biometric backup codes regenerated: ${type} for user ${userId}`);

      res.json({
        success: true,
        message: 'Backup codes regenerated successfully',
        data: {
          backupCodes: result.backupCodes,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

export default router;
